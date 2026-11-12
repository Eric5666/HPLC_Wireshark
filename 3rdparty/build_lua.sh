#!/bin/bash
# build_lua.sh - 构建内嵌 Lua 5.4 静态库(供 bplc-plugin-host 链接)
#
# 产物: 3rdparty/lua-5.4.9/src/liblua.a
# 用法: ./build_lua.sh
# 注意: qmake 在 bplc-plugin-host.pro 里缺失时会自动调等价命令,本脚本供
#       CI 与手动构建使用。
set -e
cd "$(dirname "$0")"

LUA_DIR="lua-5.4.9"
LUA_TARBALL="lua-5.4.9.tar.gz"
LUA_URL="https://www.lua.org/ftp/lua-5.4.9.tar.gz"

if [ ! -d "$LUA_DIR" ]; then
    if [ ! -f "$LUA_TARBALL" ]; then
        echo "lua: downloading $LUA_URL ..."
        curl -sSL -o "$LUA_TARBALL" "$LUA_URL"
    fi
    echo "lua: extracting ..."
    tar xzf "$LUA_TARBALL"
fi

if [ ! -f "$LUA_DIR/src/liblua.a" ]; then
    echo "lua: building liblua.a ..."
    make -C "$LUA_DIR/src" -j"$(nproc)" liblua.a MYCFLAGS="-fPIC"
fi

if [ -f "$LUA_DIR/src/liblua.a" ]; then
    echo "lua: built OK: $LUA_DIR/src/liblua.a"
else
    echo "lua: BUILD FAILED" >&2
    exit 1
fi
