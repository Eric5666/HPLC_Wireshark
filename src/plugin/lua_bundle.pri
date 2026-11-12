# lua_bundle.pri: 内嵌 Lua 5.4.9 的获取 + 构建 + 链接(主程序 app_integration
# 与 bplc-plugin-host 共用)。
#
# 行为(幂等):
#   1. 3rdparty/lua-5.4.9 源码目录缺失时自动获取:有 tarball 则直接解压,
#      无则下载(Windows 10 1803+ 自带 curl/tar,无需 bash;unix 同样 curl + tar)。
#   2. src/liblua.a 缺失时自动编译(win32-g++ 用 mingw32-make)。
#   3. 统一追加 INCLUDEPATH / LIBS。
# 注意:3rdparty/lua-5.4.9/ 解压目录被 gitignore(构建产物),tarball 在版本库
# 里;全新 checkout 第 1 步会自动解压,否则 qmake 的 cd 会报"系统找不到指定的路径"。

_LUA_PWD = $$PWD
_LUA_THIRDPARTY = $$_LUA_PWD/../../3rdparty
LUA_DIR = $$_LUA_THIRDPARTY/lua-5.4.9
LUA_SRC = $$LUA_DIR/src
LUA_LIB = $$LUA_SRC/liblua.a
LUA_TARBALL = $$_LUA_THIRDPARTY/lua-5.4.9.tar.gz
LUA_URL = https://www.lua.org/ftp/lua-5.4.9.tar.gz

# --- 1+2. 源码缺失时获取、静态库缺失时编译 ---
!exists($$LUA_LIB) {
    message("lua: bootstrapping bundled lua-5.4.9 ...")
    win32 {
        # qmake 的 system() 在 Windows 下实际跑的是 cmd /v:off /s /c "<command>",
        # /s 会剥掉首尾引号,命令里不能再嵌套双引号——因此逻辑收进
        # 3rdparty/bootstrap_lua.bat,这里只调 bat(路径无空格,不加引号)。
        # 注意:不能用 $$shell_path() —— 在 MSYS/Git Bash(CI 与本地终端都走它)
        # 下会转成 /C/Users/... 这种 MSYS 路径,cmd.exe 认不得(报"系统找不到
        # 指定的路径")。$$clean_path() 始终给出 C:/... 正斜杠,cmd 可直接执行。
        # Windows 下统一用 mingw32-make(各 MinGW 套件都带,含 llvm-mingw)。
        LUA_BOOT = $$clean_path($$_LUA_THIRDPARTY)/bootstrap_lua.bat mingw32-make
        system($$LUA_BOOT)
    } else {
        # unix:走 /bin/sh -c,引号无此问题
        !exists($$LUA_DIR) {
            !exists($$LUA_TARBALL): LUA_DL = curl -sSL -o lua-5.4.9.tar.gz $$LUA_URL &&
            LUA_UNPACK = cd "$$clean_path($$_LUA_THIRDPARTY)" && $$LUA_DL tar -xzf lua-5.4.9.tar.gz
            system($$LUA_UNPACK)
        }
        !exists($$LUA_LIB) {
            LUA_BUILD = cd "$$clean_path($$LUA_DIR)" && make -C src liblua.a MYCFLAGS="-fPIC"
            system($$LUA_BUILD)
        }
    }
    !exists($$LUA_LIB): error("lua: failed to build $$LUA_LIB")
}

# --- 3. 链接 ---
INCLUDEPATH += $$LUA_SRC
DEPENDPATH += $$LUA_SRC
LIBS += $$LUA_LIB
unix: LIBS += -ldl -lm   # Windows(MinGW) 无 libdl,仅 unix 链
