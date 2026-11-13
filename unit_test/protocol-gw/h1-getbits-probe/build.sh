#!/bin/bash
# H1 get_bits 边界检查探针:ASan(仅 Linux)下喂截断帧,验证拒收/不崩。
# 用法: ./build.sh [norun]  (默认构建并运行;传 norun 只构建)
# 跨平台:QT_ROOT 优先 → 版本倒序探测 C:/Qt/6.*/mingw_64 → Linux 候选;
# make 用 make / mingw32-make(Windows);ASan 仅 Linux 开启(MinGW 不支持 -fsanitize=address)。
set -e
cd "$(dirname "$0")"

# 传给 qmake 的路径必须是原生形式(C:/…);bash 的 /c/… 会被原生程序静默忽略。
native_path() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}

# Windows:Qt 自带 MinGW 工具链(g++/mingw32-make)通常不在 PATH 上
for tb in /c/Qt/Tools/mingw*/bin /c/Qt/Tools/*/bin; do
    if [ -d "$tb" ]; then PATH="$tb:$PATH"; export PATH; break; fi
done

QT="${QT_ROOT:-${QT:-}}"
if [ -z "$QT" ]; then
    # 本机 Qt 是整版本替换的:按版本倒序取最新,别写死单一版本号
    for cand in $(ls -d /c/Qt/6.*/mingw_64 2>/dev/null | sort -Vr); do
        if [ -d "$cand" ]; then QT="$cand"; break; fi
    done
    if [ -z "$QT" ]; then
        for cand in "$HOME/Qt/6.11.3/6.11.3/gcc_64" "$HOME/qt/6.11.2/gcc_64" "/usr/lib/qt6" "/usr"; do
            if [ -d "$cand/include/QtCore" ]; then QT="$cand"; break; fi
        done
    fi
fi
[ -n "$QT" ] || { echo "未找到 Qt,请用 QT_ROOT= 指定" >&2; exit 1; }
# Windows:Qt 运行库 DLL(bin/)加进 PATH,否则 exe 启动报 Qt6*.dll not found
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) PATH="$QT/bin:$PATH"; export PATH ;;
esac
QT="$(native_path "$QT")"
export LD_LIBRARY_PATH="$QT/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

MAKE_BIN="${MAKE:-}"
if [ -z "$MAKE_BIN" ]; then
    if command -v make >/dev/null 2>&1; then MAKE_BIN=make
    elif command -v mingw32-make >/dev/null 2>&1; then MAKE_BIN=mingw32-make
    else echo "未找到 make / mingw32-make" >&2; exit 1; fi
fi

# qmake 名字随发行版不同:Windows 只有 qmake.exe;Ubuntu 的 QT_HOST_BINS 里常只有 qmake6。
QMAKE=""
for cand in "$QT/bin/qmake.exe" "$QT/bin/qmake" "$QT/bin/qmake6" \
            "$QT/bin/qmake6.exe" "$QT/bin/qmake-qt6"; do
    if [ -x "$cand" ]; then QMAKE="$cand"; break; fi
done
[ -n "$QMAKE" ] || { echo "未找到 qmake(试过 qmake/qmake6/qmake-qt6): $QT/bin" >&2; exit 1; }

# ASan 仅 Linux(MinGW 的 -fsanitize=address 不可用);Windows 本地/CI 行为一致。
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) SAN="" ;;
    *) SAN="SANITIZERS=address" ;;
esac

name="h1_getbits_probe"
mkdir -p "build/$name"
(cd "build/$name" && "$QMAKE" $SAN "../../$name.pro" && "$MAKE_BIN" -j4)
echo "built build/$name/"

if [ "$1" != "norun" ]; then
    export QT_QPA_PLATFORM=offscreen
    EXE=""
    for cand in "./build/$name/$name" "./build/$name/release/$name" \
                "./build/$name/$name.exe" "./build/$name/release/$name.exe"; do
        if [ -x "$cand" ] || [ -f "$cand" ]; then EXE="$cand"; break; fi
    done
    [ -n "$EXE" ] || { echo "未找到产物 exe" >&2; exit 1; }
    "$EXE"
fi
