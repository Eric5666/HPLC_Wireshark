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
    LUA_BIN=build/lua
fi
echo "lua: $LUA_BIN ($("$LUA_BIN" -v 2>&1))"
"$LUA_BIN" test_lang_path.lua "$REPO/wireshark_support_plugins"
