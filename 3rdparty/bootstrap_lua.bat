@echo off
rem bootstrap_lua.bat - Windows counterpart of 3rdparty/build_lua.sh
rem Usage: bootstrap_lua.bat [make-tool]
rem   Ensures 3rdparty/lua-5.4.9/src/liblua.a exists:
rem   downloads the tarball (fallback, it is vendored in git),
rem   extracts it and builds liblua.a with the given make tool
rem   (default: mingw32-make).
rem
rem NOTE: keep this file CRLF line endings.
setlocal
cd /d "%~dp0"
if "%~1"=="" (set LUA_MAKE=mingw32-make) else (set LUA_MAKE=%~1)

if not exist lua-5.4.9.tar.gz (
    echo lua: downloading lua-5.4.9.tar.gz ...
    curl -sSL -o lua-5.4.9.tar.gz https://www.lua.org/ftp/lua-5.4.9.tar.gz
)
if not exist lua-5.4.9.tar.gz (
    echo lua: download failed 1>&2
    exit /b 1
)
if not exist lua-5.4.9 (
    echo lua: extracting lua-5.4.9.tar.gz ...
    tar -xzf lua-5.4.9.tar.gz
)
if not exist lua-5.4.9 (
    echo lua: extract failed 1>&2
    exit /b 1
)
if not exist lua-5.4.9\src\liblua.a (
    echo lua: building liblua.a with %LUA_MAKE% ...
    cd lua-5.4.9\src
    call %LUA_MAKE% liblua.a MYCFLAGS="-fPIC"
    cd ..\..
)
if not exist lua-5.4.9\src\liblua.a (
    echo lua: build failed 1>&2
    exit /b 1
)
echo lua: liblua.a ready
