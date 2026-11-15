#!/usr/bin/env bash
# Linux 打包脚本:构建 → 收集 Qt 运行时 → tar.gz 安装包
# 用法: bash scripts/package_linux.sh [版本号,默认 1.0.1]
#
# 产物: dist/BPLC_STA_Monitor_v<VER>_linux_<arch>.tar.gz(arch = uname -m,如 x86_64 / aarch64)
# 解压即用,含 crashpad_handler(崩溃转储必需,放程序同目录)。
#
# 依赖: qmake(Qt6) / make(需联网构建 crashpad 依赖)
set -e
cd "$(dirname "$0")/.."
VER="${1:-1.0.1}"
# 架构取自构建机(uname -m:x86_64 / aarch64 原样用于包名),可用 ARCH= 覆盖
ARCH="${ARCH:-$(uname -m)}"

echo "== 0/4 检查 crashpad 依赖"
if [ ! -f 3rdparty/install/crashpad/bin/crashpad_handler ]; then
    echo "未找到 3rdparty/install/crashpad,先构建:"
    echo "  bash 3rdparty/build_crash_deps.sh crashpad"
    bash 3rdparty/build_crash_deps.sh crashpad
fi

echo "== 1/4 qmake + 构建(默认 crashpad 后端)"
rm -rf build_linux build_linux_host
mkdir -p build_linux
cd build_linux
qmake ../BPLC_STA_Monitor.pro
make -j"$(nproc)"
cd ..
# 插件宿主进程 bplc-plugin-host:独立工程,主程序在同目录查找它
# (plugin_manager.cpp),不在主 .pro 里,须单独构建(缺失会导致插件不可用)。
mkdir -p build_linux_host
cd build_linux_host
qmake ../src/plugin/host/bplc-plugin-host.pro
make -j"$(nproc)"
cd ..

echo "== 2/4 ldd 收集运行时库"
rm -rf AppDir
mkdir -p AppDir/usr/bin AppDir/usr/lib
cp build_linux/BPLC_STA_Monitor AppDir/usr/bin/
# bplc-plugin-host 必须与主程序同目录(主程序按 exe 目录查找,见上)
cp build_linux_host/bplc-plugin-host AppDir/usr/bin/
chmod +x AppDir/usr/bin/bplc-plugin-host
# crashpad_handler 必须与主程序同目录(后端按 exe 目录查找)
cp 3rdparty/install/crashpad/bin/crashpad_handler AppDir/usr/bin/
chmod +x AppDir/usr/bin/crashpad_handler
# 配置文件【不入包】: 用户的 config.ini 绝不拷进发行包, 示范模板也不带。
# 程序首次启动时会在 exe 同目录自动生成带注释的完整配置模板(src/app/appconfig.h)。
# 附 Wireshark 解析插件:全量复制,仅剔除强平台相关的文件
# (Windows 批处理 .bat、dissector C 源码 .c 不进 Linux 包,其余 .lua/.py/
# 测试 pcap/文档等平台中立文件全部保留)
mkdir -p AppDir/usr/share/bplc_sta_monitor/wireshark_support_plugins
cp -r wireshark_support_plugins/. AppDir/usr/share/bplc_sta_monitor/wireshark_support_plugins/
rm -f AppDir/usr/share/bplc_sta_monitor/wireshark_support_plugins/*.c \
      AppDir/usr/share/bplc_sta_monitor/wireshark_support_plugins/*.bat
# ldd 收集所有 .so 依赖(含 Qt6)
ldd AppDir/usr/bin/BPLC_STA_Monitor | grep -o '/[^ ]*\.so[^ ]*' | sort -u | while read -r lib; do
    cp -L "$lib" AppDir/usr/lib/ 2>/dev/null || true
done
# Qt 插件(xcb 平台插件等)
QT_PLUGINS="$(qmake -query QT_INSTALL_PLUGINS 2>/dev/null)"
if [ -n "$QT_PLUGINS" ] && [ -d "$QT_PLUGINS/platforms" ]; then
    mkdir -p AppDir/usr/lib/qt6/plugins
    cp -r "$QT_PLUGINS/platforms" AppDir/usr/lib/qt6/plugins/
    cp -r "$QT_PLUGINS/xcbglintegrations" AppDir/usr/lib/qt6/plugins/ 2>/dev/null || true
    # TLS 后端(更新检查/Sentry 上报走 HTTPS,缺它则 "No functional TLS backend")
    cp -r "$QT_PLUGINS/tls" AppDir/usr/lib/qt6/plugins/ 2>/dev/null || \
        echo "::warning::未找到 Qt TLS 插件($QT_PLUGINS/tls),HTTPS 功能将不可用"
fi
# SQL 驱动(TOPO 历史存 SQLite:QSqlDatabase("QSQLITE") 打开数据库,缺它则
# 驱动加载失败、拓扑历史写不进库)。只拷用到的 libqsqlite.so,不拷整目录
# (mysql/odbc/psql 等驱动用不到)。缺失直接失败,不让坏包流出去。
# 本检查独立于 platforms 目录:即使 platforms 缺失也要检查,不能因为
# 平台插件拷不了就悄悄跳过驱动检查。
if [ -z "$QT_PLUGINS" ]; then
    echo "::error::无法确定 Qt 插件目录(qmake -query QT_INSTALL_PLUGINS 为空),无法检查 SQLite 驱动" >&2
    exit 1
fi
if [ -f "$QT_PLUGINS/sqldrivers/libqsqlite.so" ]; then
    mkdir -p AppDir/usr/lib/qt6/plugins/sqldrivers
    cp "$QT_PLUGINS/sqldrivers/libqsqlite.so" AppDir/usr/lib/qt6/plugins/sqldrivers/
else
    echo "::error::未找到 Qt SQLite 驱动($QT_PLUGINS/sqldrivers/libqsqlite.so),TOPO 历史数据库将无法打开" >&2
    exit 1
fi
echo "收集到 $(ls AppDir/usr/lib/*.so* 2>/dev/null | wc -l) 个库"

echo "== 3/4 启动脚本"
cat > AppDir/usr/bin/run.sh <<'EOF'
#!/usr/bin/env bash
# 解压即用启动器:设置库路径后启动主程序
HERE="$(cd "$(dirname "$0")" && pwd)"
export LD_LIBRARY_PATH="$HERE/../lib:$LD_LIBRARY_PATH"
export QT_PLUGIN_PATH="$HERE/../lib/qt6/plugins"
exec "$HERE/BPLC_STA_Monitor" "$@"
EOF
chmod +x AppDir/usr/bin/run.sh

echo "== 3.5/4 包级说明文档与用户手册"
# 包根 README:用户解压后第一眼看到的使用说明
cat > AppDir/README.md <<EOF
# BPLC STA Monitor v${VER} (Linux ${ARCH})

BPLC/HPLC 协议 STA 报文监控上位机。

## 快速开始

\`\`\`bash
tar -xzf BPLC_STA_Monitor_v${VER}_linux_${ARCH}.tar.gz
cd usr/bin
./run.sh
\`\`\`

## 目录说明

- \`usr/bin/BPLC_STA_Monitor\` — 主程序(请经 \`run.sh\` 启动,勿直接运行)
- \`usr/bin/run.sh\` — 启动器(设置库路径与 Qt 插件路径)
- \`usr/bin/bplc-plugin-host\` — 插件宿主进程(须与主程序同目录,勿删除)
- \`usr/bin/crashpad_handler\` — 崩溃转储辅助进程(须与主程序同目录,勿删除)
- 配置文件由程序首次启动时在程序同目录自动生成(带注释的完整模板); 包内不含任何配置文件
- \`usr/lib/\` — Qt6 及第三方运行时库
- \`usr/share/bplc_sta_monitor/wireshark_support_plugins/\` — Wireshark 解析插件
  (\`packet-*.lua\` 放 Wireshark 插件目录,\`bplc_serial_extcap.py\` 为 extcap 抓包接口)
- \`docs/\` — 用户手册(中英文)

## 详细文档

- \`docs/USER_MANUAL_zh-CN.md\` — 中文使用说明书
- \`docs/USER_MANUAL_en.md\` — English User Manual
EOF
# 用户手册(中英文)随包
mkdir -p AppDir/docs
for m in docs/USER_MANUAL_zh-CN.md docs/USER_MANUAL_en.md; do
    [ -f "$m" ] && cp "$m" AppDir/docs/
done

echo "== 4/4 打包 tar.gz"
mkdir -p dist
PKG="dist/BPLC_STA_Monitor_v${VER}_linux_${ARCH}.tar.gz"
tar -czf "$PKG" -C AppDir .
ls -la "$PKG"

echo "== 5/5 生成符号包(供崩溃 dump 符号化,见 scripts/symbolize.sh)"
if [ ! -x 3rdparty/install/symtools/dump_syms ]; then
    bash 3rdparty/build_sym_tools.sh
fi
SYMDIR="symbols_tmp/BPLC_STA_Monitor"
SYMFILE=$(mktemp)
3rdparty/install/symtools/dump_syms build_linux/BPLC_STA_Monitor > "$SYMFILE"
HASH=$(awk 'NR==1{print $4}' "$SYMFILE")
mkdir -p "$SYMDIR/$HASH"
mv "$SYMFILE" "$SYMDIR/$HASH/BPLC_STA_Monitor.sym"
# 宿主进程的符号一并归档(宿主崩溃时同样需要符号化定位)
HOSTSYMDIR="symbols_tmp/bplc-plugin-host"
HOSTSYMFILE=$(mktemp)
3rdparty/install/symtools/dump_syms build_linux_host/bplc-plugin-host > "$HOSTSYMFILE"
HOSTHASH=$(awk 'NR==1{print $4}' "$HOSTSYMFILE")
mkdir -p "$HOSTSYMDIR/$HOSTHASH"
mv "$HOSTSYMFILE" "$HOSTSYMDIR/$HOSTHASH/bplc-plugin-host.sym"
SYMPKG="dist/BPLC_STA_Monitor_v${VER}_linux_${ARCH}_symbols.tar.gz"
tar -czf "$SYMPKG" -C symbols_tmp .
rm -rf symbols_tmp
ls -la "$SYMPKG"
echo "DONE: $PKG"
echo "DONE: $SYMPKG (符号包,随版本存档,分析 dump 时用)"
