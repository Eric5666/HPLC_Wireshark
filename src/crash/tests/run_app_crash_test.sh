#!/bin/bash
# run_app_crash_test.sh - 真实应用崩溃可用性验证(Linux)
#
# 验证打包产物(而非测试小程序)的崩溃检测链路是否"可定位":
#   1. 解压 dist/ 下的 Linux tarball(解压即用包)与符号包
#   2. 确认 crashpad_handler 与主程序同目录且可执行(打包遗漏会静默失效)
#   3. 带 --self-crash-test 启动真实 BPLC_STA_Monitor:
#      main() 在 CrashHandler::install() 之后于 crash_selftest_trigger()
#      内触发确定性空指针崩溃(函数 noinline,不会被优化/内联掉)
#   4. 断言进程以 SIGSEGV 退出(139),且 crashpad_db 下生成 MDMP dump
#   5. 用发布符号包对 dump 做 minidump_stackwalk,断言崩溃线程的栈中
#      能定位到 crash_selftest_trigger 及其 main.cpp 行号
#      —— 只验"结构有效"不够,必须证明 dump 可符号化定位到崩溃处
#
# 与 run_crash_tests.sh 的区别:那个测的是独立 crash_test 小程序,
# 这里测的是用户实际拿到的发布包。
set -e
cd "$(dirname "$0")/../../.."
ROOT="$PWD"

echo "=== 1/6 查找打包产物与符号包 ==="
ARCH="${ARCH:-$(uname -m)}"   # 与 scripts/package_linux.sh 的包名一致
TARBALL=$(ls -t dist/BPLC_STA_Monitor_v*_linux_${ARCH}.tar.gz 2>/dev/null | grep -v symbols | head -1)
SYMTARBALL=$(ls -t dist/BPLC_STA_Monitor_v*_linux_${ARCH}_symbols.tar.gz 2>/dev/null | head -1)
[ -n "$TARBALL" ] || { echo "[FAIL] dist/ 下没有 Linux tarball,先跑 scripts/package_linux.sh"; exit 1; }
[ -n "$SYMTARBALL" ] || { echo "[FAIL] dist/ 下没有符号包,先跑 scripts/package_linux.sh"; exit 1; }
echo "tarball: $TARBALL"
echo "symbols: $SYMTARBALL"

echo "=== 2/6 解压并检查崩溃组件 ==="
WORK=/tmp/app_crash_test
SYMDIR=/tmp/app_crash_test_syms
rm -rf "$WORK" "$SYMDIR"; mkdir -p "$WORK" "$SYMDIR"
tar xzf "$TARBALL" -C "$WORK"
tar xzf "$SYMTARBALL" -C "$SYMDIR"
APP="$WORK/usr/bin/BPLC_STA_Monitor"
HANDLER="$WORK/usr/bin/crashpad_handler"
[ -x "$APP" ] || { echo "[FAIL] 主程序缺失或不可执行: $APP"; exit 1; }
[ -x "$HANDLER" ] || { echo "[FAIL] crashpad_handler 缺失或不可执行(打包遗漏,崩溃检测将静默失效)"; exit 1; }
[ -n "$(find "$SYMDIR" -name '*.sym' | head -1)" ] || { echo "[FAIL] 符号包内无 .sym 文件"; exit 1; }
echo "[OK] 主程序、crashpad_handler、符号文件就位"

echo "=== 3/6 启动真实应用并触发确定性崩溃 ==="
export QT_QPA_PLATFORM=offscreen
set +e
timeout 60 "$WORK/usr/bin/run.sh" -platform offscreen --self-crash-test > /tmp/app_crash_test.log 2>&1
CODE=$?
set -e
if [ "$CODE" -ne 139 ]; then
    echo "[FAIL] 应用未按预期以 SIGSEGV 崩溃, exit=$CODE (124=卡住被 timeout 杀掉)"
    tail -25 /tmp/app_crash_test.log
    exit 1
fi
echo "[OK] 应用以 SIGSEGV 崩溃, exit=139"

echo "=== 4/6 确认 dump 落盘且结构有效 ==="
DB="$WORK/usr/bin/crashpad_db"
DMP=""
for i in $(seq 1 60); do
    DMP=$(find "$DB" -name "*.dmp" 2>/dev/null | head -1)
    [ -n "$DMP" ] && break
    sleep 1
done
[ -n "$DMP" ] || { echo "[FAIL] 60s 内 $DB 下无 .dmp 生成(崩溃未被捕获)"; exit 1; }
MAGIC=$(head -c 4 "$DMP")
SIZE=$(stat -c%s "$DMP")
[ "$MAGIC" = "MDMP" ] || { echo "[FAIL] $DMP 魔数不是 MDMP"; exit 1; }
[ "$SIZE" -ge 1024 ] || { echo "[FAIL] $DMP 仅 $SIZE 字节,疑似空 dump"; exit 1; }
echo "[OK] dump: $DMP ($SIZE 字节, MDMP 魔数 OK)"

echo "=== 5/6 符号化 dump ==="
bash scripts/symbolize.sh "$DMP" --symdir "$SYMDIR" > /tmp/app_crash_stack.txt 2>/tmp/app_crash_stack.err || {
    echo "[FAIL] minidump_stackwalk 符号化失败:"
    tail -10 /tmp/app_crash_stack.err
    exit 1
}
grep -q "SIGSEGV" /tmp/app_crash_stack.txt || { echo "[FAIL] 栈回溯中未见 SIGSEGV 崩溃原因"; exit 1; }
echo "[OK] 符号化完成,崩溃原因为 SIGSEGV"

echo "=== 6/6 断言定位到崩溃处 ==="
# 取崩溃线程段,要求其中出现 crash_selftest_trigger 且带 main.cpp 行号
CRASH_SEC=$(awk '/Thread [0-9]+ \(crashed\)/{f=1} f{print} f&&/^ *$/{exit}' /tmp/app_crash_stack.txt)
if ! echo "$CRASH_SEC" | grep -q "crash_selftest_trigger"; then
    echo "[FAIL] 崩溃线程栈中找不到 crash_selftest_trigger,符号化未能定位崩溃处:"
    echo "$CRASH_SEC" | head -12
    exit 1
fi
FRAME=$(echo "$CRASH_SEC" | grep "crash_selftest_trigger" | head -1)
echo "崩溃帧: $FRAME"
# 要求解析出"源文件:行号"(如 [main.cpp : 27 + 0x..]),而不只是函数名+偏移
if ! echo "$FRAME" | grep -Eq "\[[^]]+\.(cpp|c|cc|cxx) : [0-9]+"; then
    echo "[FAIL] 崩溃帧无源码行号(只有偏移,行号信息缺失)"
    exit 1
fi
echo "[PASS] 真实应用崩溃可定位: dump 已符号化到崩溃函数及源码行"
echo "ALL DONE"
