#!/bin/bash
# build_crash_deps.sh - 构建崩溃转储第三方依赖(sentry-native / crashpad)
#
# 产物统一安装到 3rdparty/install/:
#   install/sentry/{include,lib,bin}    libsentry.a(+crashpad_client...), sentry.h, crashpad_handler
#   install/crashpad/{include,lib,bin}  libcrashpad_client.a 等, crashpad 头文件, crashpad_handler(.exe)
#
# 用法:
#   ./build_crash_deps.sh [sentry|crashpad|all]   (默认 all)
#
# 注意: sentry-native 的 crashpad 后端与独立 crashpad 模块共用同一份源码
# (3rdparty/sentry-native/external/crashpad),但分别独立构建,互不耦合。
#
# 源码自举: 3rdparty/sentry-native 不在仓库里(.gitignore),本脚本在缺失时按
# SENTRY_NATIVE_REF(固定提交,保证可复现)浅克隆,并初始化 crashpad 构建所需
# 的嵌套 submodule。可被环境变量覆盖:
#   SENTRY_NATIVE_REF / SENTRY_NATIVE_URL
#   CMAKE_BIN / MAKE_BIN (cmake 与 mingw32-make 的绝对路径;qmake 自动构建用;
#   反斜杠路径(C:\...)会被脚本自动转成正斜杠,避免 Windows 下 bash PATH 的
#   盘符冒号解析问题与单引号内反斜杠的字面量问题)
#
# Windows(Git Bash + MinGW): crashpad 的 getsentry fork 支持 MinGW 构建
# (见其 README.getsentry.md "MinGW Changes"),本脚本自动切 -G "MinGW Makefiles"。
set -e
cd "$(dirname "$0")"

# qmake 自动构建经 CMAKE_BIN/MAKE_BIN 传入 cmake/make 绝对路径;Windows 下
# qmake 扫 PATH 得到的是反斜杠路径(C:\...),在 bash 单引号里会当成字面文件名
# 而失效,统一转成正斜杠(MSYS bash 可直接执行 C:/... 形式)。
_to_bash_path() { local p="$1"; printf '%s' "${p//\\//}"; }
CMAKE_BIN="$(_to_bash_path "${CMAKE_BIN:-cmake}")"
MAKE_BIN="$(_to_bash_path "${MAKE_BIN:-}")"

# ---- 可复现版本钉 ----
SENTRY_NATIVE_REF="${SENTRY_NATIVE_REF:-7afc37457d7fcc37fb0bace9c8045d3fa687717f}"
SENTRY_NATIVE_URL="${SENTRY_NATIVE_URL:-https://github.com/getsentry/sentry-native.git}"

JOBS=$(nproc 2>/dev/null || echo 4)
SRC_SENTRY="$PWD/sentry-native"
SRC_CRASHPAD="$PWD/sentry-native/external/crashpad"
INSTALL="$PWD/install"

WHAT="${1:-all}"

# ---- 平台检测 ----
ON_WINDOWS=0
case "$(uname -s 2>/dev/null)" in
    MINGW*|MSYS*|CYGWIN*) ON_WINDOWS=1 ;;
esac

# 原生 Windows 路径(C:/...)供 CMake(原生 Win32 构建)使用;
# Git Bash 的 /c/... 写法 CMake 不认。
to_win_path() {
    if [ "$ON_WINDOWS" = "1" ]; then
        cygpath -m "$1"
    else
        printf '%s' "$1"
    fi
}

# ---- 源码自举 ----
# 完整性判定:光目录存在不够,必须是有效仓库且 HEAD 正好是钉死的提交。
# 中断的 clone/fetch/checkout 会留下 HEAD 缺失或不对的残留目录——若只判文件存在,
# 下次 git clone 会因"目标已存在"直接报错,或误判"已存在"跳过导致构建失败。
sentry_source_ok() {
    [ -d "$SRC_SENTRY/.git" ] || return 1
    [ "$(git -C "$SRC_SENTRY" rev-parse HEAD 2>/dev/null)" = "$SENTRY_NATIVE_REF" ] || return 1
    return 0
}

ensure_source() {
    if sentry_source_ok; then
        echo "=== sentry-native source already present, skipping fetch ==="
    else
        if [ -e "$SRC_SENTRY" ]; then
            echo "=== sentry-native source incomplete (interrupted fetch or wrong ref), removing and re-fetching ==="
        fi
        echo "=== fetching sentry-native @ ${SENTRY_NATIVE_REF:0:12} ==="
        # 残留的不完整目录必须先删掉,否则 git clone 报 "already exists"
        rm -rf "${SRC_SENTRY:?}"
        git clone --no-checkout "$SENTRY_NATIVE_URL" "$SRC_SENTRY"
        git -C "$SRC_SENTRY" fetch --depth 1 origin "$SENTRY_NATIVE_REF"
        git -C "$SRC_SENTRY" checkout "$SENTRY_NATIVE_REF"
    fi
    # crashpad 独立构建需要的 submodule(幂等,已有则跳过)。
    # 注意:嵌套 submodule 注册在 external/crashpad/.gitmodules,
    # 必须进到 crashpad 仓库里初始化,顶层仓库不认这些路径。
    echo "=== initializing crashpad submodule ==="
    git -C "$SRC_SENTRY" submodule update --init --depth 1 external/crashpad
    git -C "$SRC_CRASHPAD" submodule update --init --depth 1 \
        third_party/mini_chromium/mini_chromium \
        third_party/zlib/zlib \
        third_party/lss/lss
    # 哨兵检查
    for f in "$SRC_CRASHPAD/CMakeLists.txt" \
             "$SRC_CRASHPAD/third_party/mini_chromium/mini_chromium/base/files/file_path.h" \
             "$SRC_CRASHPAD/third_party/zlib/zlib/zlib.h" \
             "$SRC_CRASHPAD/third_party/lss/lss/linux_syscall_support.h"; do
        [ -f "$f" ] || { echo "error: missing $f, submodule init failed"; exit 1; }
    done
    # 打上本地 patch(幂等):给 crashpad 加 CRASHPAD_ENABLE_WER 开关,
    # Windows/MinGW 构建时用它跳过 WER 模块(与 MinGW werapi.h 冲突,且不需要)。
    if ! grep -q "CRASHPAD_ENABLE_WER" "$SRC_CRASHPAD/handler/CMakeLists.txt"; then
        echo "=== applying local crashpad patch: disable-wer ==="
        # --ignore-whitespace:Windows runner 上 git 默认 autocrlf=true,checkout 出 CRLF
        # 换行,而 patch 是 LF,不加这个上下文匹配失败。
        git -C "$SRC_CRASHPAD" apply --ignore-whitespace "$PWD/patches/crashpad-disable-wer.patch"
    else
        echo "=== crashpad local patch already applied, skipping ==="
    fi
    # MinGW 垫片 compat/mingw/werapi.h 把 PWER_SUBMIT_RESULT 的补定义写在了
    # #include_next 之后,但老版本 MinGW 系统头自己第 122 行就用了该类型,
    # 导致系统头先编译不过。移到 include 之前(幂等)。
    if ! grep -q "必须在 include 系统头之前补上" "$SRC_CRASHPAD/compat/mingw/werapi.h"; then
        echo "=== applying local crashpad patch: mingw-werapi ==="
        git -C "$SRC_CRASHPAD" apply --ignore-whitespace "$PWD/patches/crashpad-mingw-werapi.patch"
    else
        echo "=== crashpad mingw-werapi patch already applied, skipping ==="
    fi
    # MSVC 的 offsetof 接受非常量数组下标,GCC 不接受;改写为等价的算术形式(幂等)。
    if ! grep -q "与原式语义等价" "$SRC_CRASHPAD/snapshot/win/pe_image_reader.cc"; then
        echo "=== applying local crashpad patch: mingw-offsetof ==="
        git -C "$SRC_CRASHPAD" apply --ignore-whitespace "$PWD/patches/crashpad-mingw-offsetof.patch"
    else
        echo "=== crashpad mingw-offsetof patch already applied, skipping ==="
    fi
    # 老版本 MinGW (mingw-w64 < 11.0,如早期 Qt Tools 自带的 MinGW 13.1.0)
    # 的 winnt.h 缺少 SDK 10.0.22621+ 的 CET XSAVE 定义(XSAVE_CET_U_FORMAT /
    # CONTEXT_XSTATE),在 cpu_context_win.h 补 SDK 布局兼容的 fallback(幂等)。
    if ! grep -q "mingw-xsave-compat" "$SRC_CRASHPAD/snapshot/win/cpu_context_win.h"; then
        echo "=== applying local crashpad patch: mingw-xsave-compat ==="
        git -C "$SRC_CRASHPAD" apply --ignore-whitespace "$PWD/patches/crashpad-mingw-xsave-compat.patch"
    else
        echo "=== crashpad mingw-xsave-compat patch already applied, skipping ==="
    fi
    # 同上:XSTATE_COMPACTION_ENABLE(_MASK) 也是 mingw-w64 11.0 才引入,
    # minidump 的两个 writer 用到,在 minidump_context_writer.h 补(幂等)。
    if ! grep -q "mingw-xstate-compat" "$SRC_CRASHPAD/minidump/minidump_context_writer.h"; then
        echo "=== applying local crashpad patch: mingw-xstate-compat ==="
        git -C "$SRC_CRASHPAD" apply --ignore-whitespace "$PWD/patches/crashpad-mingw-xstate-compat.patch"
    else
        echo "=== crashpad mingw-xstate-compat patch already applied, skipping ==="
    fi
}

build_sentry() {
    echo "=== building sentry-native (backend=crashpad, static) ==="
    # SENTRY_TRANSPORT 可被环境变量覆盖(如无 curl 开发头时用 none 先验证捕获链路)
    # Windows MinGW 下无 curl 开发库,默认用系统 WinHTTP 传输(无需额外依赖)
    local transport="${SENTRY_TRANSPORT:-curl}"
    if [ "$ON_WINDOWS" = "1" ] && [ -z "${SENTRY_TRANSPORT:-}" ]; then
        transport="winhttp"
    fi
    local gen_args=()
    local extra_args=()
    if [ "$ON_WINDOWS" = "1" ]; then
        gen_args+=(-G "MinGW Makefiles")
        # Windows 无系统 zlib,sentry 内嵌的 crashpad 同样用自带 third_party/zlib,
        # 否则 find_package(ZLIB) 在 configure 阶段直接失败(CI #30 实测)。
        # 注意:不能加 CRASHPAD_ENABLE_WER=OFF —— sentry-native 的 CMakeLists
        # 无条件 add_dependencies(sentry crashpad::wer),关掉 WER 会导致
        # generate 阶段"crashpad::wer 不存在"而失败(CI #31 实测)。
        extra_args+=(-DCRASHPAD_ZLIB_SYSTEM=OFF)
        # sentry 内嵌的 crashpad 同样要编 capture_context.asm(MASM 语法),
        # 需要 uasm;独立 crashpad 构建调过 ensure_uasm,但 PATH 不跨 CI step,
        # 这里再调一次(幂等,已存在则跳过下载)。
        ensure_uasm
    fi
    # qmake 自动构建可经 MAKE_BIN 传入 mingw32-make 绝对路径(Windows 下
    # bash 的 PATH 是 : 分隔,盘符路径 C:/... 放进去会被拆错,故不用 PATH 传递)。
    if [ -n "${MAKE_BIN:-}" ]; then
        gen_args+=(-DCMAKE_MAKE_PROGRAM="$MAKE_BIN")
    fi
    "${CMAKE_BIN:-cmake}" -S "$(to_win_path "$SRC_SENTRY")" -B "$(to_win_path "$SRC_SENTRY/build")" \
        "${gen_args[@]}" \
        "${extra_args[@]}" \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DBUILD_SHARED_LIBS=OFF \
        -DSENTRY_BACKEND=crashpad \
        -DSENTRY_TRANSPORT="$transport" \
        -DSENTRY_BUILD_TESTS=OFF \
        -DSENTRY_BUILD_EXAMPLES=OFF
    "${CMAKE_BIN:-cmake}" --build "$(to_win_path "$SRC_SENTRY/build")" --parallel "$JOBS"
    "${CMAKE_BIN:-cmake}" --install "$(to_win_path "$SRC_SENTRY/build")" --prefix "$(to_win_path "$INSTALL/sentry")"
    echo "sentry -> $INSTALL/sentry"
}

# Windows:准备 MASM 兼容汇编器 uasm,crashpad 的 util/*.asm 需要它。
# MinGW 自带 as 不认 MASM 语法,crashpad 的 CMake 在 MinGW 下会回退找 uasm。
ensure_uasm() {
    [ "$ON_WINDOWS" = "1" ] || return 0
    local tools_dir="$PWD/tools"
    # 注:不能用 command -v uasm 做存在性校验——Git Bash 下它能命中 uasm.exe,
    # 但 Linux shell 只认无扩展名的 uasm;直接判文件最可靠。
    if command -v uasm >/dev/null 2>&1 || [ -f "$tools_dir/uasm.exe" ]; then
        echo "=== uasm ready, skipping download ==="
    else
        local url="https://github.com/Terraspace/UASM/releases/download/v2.57r/uasm257_x64.zip"
        mkdir -p "$tools_dir"
        echo "=== downloading uasm v2.57 (MASM-compatible assembler for crashpad .asm) ==="
        curl -sSL -o "$tools_dir/uasm.zip" "$url"
        ( cd "$tools_dir" && unzip -o -q uasm.zip uasm64.exe && cp -f uasm64.exe uasm.exe )
        rm -f "$tools_dir/uasm.zip"
        chmod +x "$tools_dir/uasm.exe" 2>/dev/null || true
    fi
    [ -f "$tools_dir/uasm.exe" ] || { echo "error: uasm installation failed"; exit 1; }
    # PATH 必须同时给 bash 格式和 Windows 格式:最终调 uasm 的是原生
    # mingw32-make(经 CreateProcess 搜 PATH),认不了 /d/... 这种 bash 路径。
    export PATH="$tools_dir:$(to_win_path "$tools_dir"):$PATH"
    echo "=== uasm ready: $tools_dir/uasm.exe ==="
}

build_crashpad() {
    echo "=== building crashpad standalone (client + handler) ==="
    local gen_args=()
    local extra_args=()
    if [ "$ON_WINDOWS" = "1" ]; then
        gen_args+=(-G "MinGW Makefiles")
        # Windows 无系统 zlib,用 crashpad 自带的 third_party/zlib(已作 submodule 初始化),
        # 否则 find_package(ZLIB) 在 configure 阶段直接失败。
        # 另:跳过 WER 模块(Windows Error Reporting 集成 DLL),它与 MinGW 的 werapi.h
        # 存在头文件声明冲突,且本地 dump 流程不需要它。
        extra_args+=(-DCRASHPAD_ZLIB_SYSTEM=OFF -DCRASHPAD_ENABLE_WER=OFF)
        ensure_uasm
    fi
    # qmake 自动构建可经 MAKE_BIN 传入 mingw32-make 绝对路径(Windows 下
    # bash 的 PATH 是 : 分隔,盘符路径 C:/... 放进去会被拆错,故不用 PATH 传递)。
    if [ -n "${MAKE_BIN:-}" ]; then
        gen_args+=(-DCMAKE_MAKE_PROGRAM="$MAKE_BIN")
    fi
    "${CMAKE_BIN:-cmake}" -S "$(to_win_path "$SRC_CRASHPAD")" -B "$(to_win_path "$SRC_CRASHPAD/build")" \
        "${gen_args[@]}" \
        "${extra_args[@]}" \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DCRASHPAD_ENABLE_INSTALL=ON \
        -DCRASHPAD_ENABLE_INSTALL_DEV=ON
    "${CMAKE_BIN:-cmake}" --build "$(to_win_path "$SRC_CRASHPAD/build")" --parallel "$JOBS"
    "${CMAKE_BIN:-cmake}" --install "$(to_win_path "$SRC_CRASHPAD/build")" --prefix "$(to_win_path "$INSTALL/crashpad")"
    echo "crashpad -> $INSTALL/crashpad"
}

ensure_source

case "$WHAT" in
    sentry)   build_sentry ;;
    crashpad) build_crashpad ;;
    all)      build_sentry; build_crashpad ;;
    *) echo "usage: $0 [sentry|crashpad|all]"; exit 1 ;;
esac
echo "DONE"
