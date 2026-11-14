#!/bin/bash
# 运行 Wireshark Lua 插件语言文件路径回归测试(不需要 Wireshark)。
# Lua 解释器查找顺序: $LUA → lua5.4 → lua → 用 3rdparty/lua-5.4.* 源码现场编译到 build/(不入库)
set -e
cd "$(dirname "$0")"
REPO="$(cd ../../.. && pwd)"
LUA_BIN="${LUA:-}"
if [ -z "$LUA_BIN" ]; then
    for c in lua5.4 lua; do
        if command -v "$c" >/dev/null 2>&1 && "$c" -v 2>&1 | grep -q "Lua 5\.[34]"; then LUA_BIN="$c"; break; fi
    done
fi
if [ -z "$LUA_BIN" ]; then
    src=""
    for d in "$REPO"/3rdparty/lua-5.4.*/src; do [ -f "$d/lua.c" ] && src="$d"; done
    if [ -z "$src" ]; then
        echo "未找到 Lua 5.4 解释器,也没有 3rdparty/lua-5.4.*/src(可先跑 3rdparty/build_lua.sh 解包源码)" >&2
        exit 1
    fi
    mkdir -p build
    # 只编译解释器到 build/(不含 luac.c,它也有 main),不改动 3rdparty 源码目录
    ${CC:-cc} -O2 -std=gnu99 -DLUA_USE_POSIX -I"$src" -o build/lua \
        $(ls "$src"/*.c | grep -v '/luac\.c$') -lm
    LUA_BIN="$PWD/build/lua"
fi
command -v "$LUA_BIN" >/dev/null 2>&1 && LUA_BIN="$(command -v "$LUA_BIN")"
case "$LUA_BIN" in /*) ;; *) LUA_BIN="$PWD/$LUA_BIN" ;; esac
echo "lua: $LUA_BIN ($("$LUA_BIN" -v 2>&1))"
# 在空的临时目录里跑: 测试用例之一用真实 io.popen 加载插件, 检查 cwd 不会冒出名为 nul 的文件
# (旧 system_is_chinese() 在非 Windows 也执行 `reg query ... 2>nul`, sh 把 2>nul 当成写 ./nul)
HERE="$PWD"
RUNDIR="$(mktemp -d "${TMPDIR:-/tmp}/lang-path-test.XXXXXX")"
trap 'rm -rf "$RUNDIR"' EXIT
cd "$RUNDIR"
rc=0
"$LUA_BIN" "$HERE/test_lang_path.lua" "$REPO/wireshark_support_plugins" real-popen-cwd-ok || rc=$?
if [ -e "$RUNDIR/nul" ]; then
    echo "FAIL: 运行后临时目录出现 nul 文件(非 Windows 执行了 reg query ... 2>nul)" >&2
    rc=1
fi
exit $rc
