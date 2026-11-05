#!/bin/bash
# Build nw_app_bid_probe with qmake into ./build/nw_app_bid_probe/.
#
# 用法:
#   bash build.sh                                    # 自动找 Qt / make
#   QT_ROOT=C:/Qt/6.11.2/mingw_64 bash build.sh      # Windows 指定 Qt
#   QT_ROOT=/usr/lib/qt6 bash build.sh               # Linux/CI 指定 Qt
#
# Qt 查找顺序: $QT_ROOT → $QT → C:/Qt/6.11.2/mingw_64 → $HOME/qt/6.11.2/gcc_64 → /usr/lib/qt6 → /usr
# qmake 查找顺序(发行版命名不同):bin/qmake.exe → bin/qmake → bin/qmake6 → bin/qmake6.exe → bin/qmake-qt6
set -e
cd "$(dirname "$0")"

# 传给 qmake 的路径必须是**原生**形式(C:/… 或 MSYS 混合式);bash 的 /c/… 会被原生程序忽略
native_path() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}

# Windows:Qt 自带 MinGW 工具链(g++.exe / mingw32-make.exe)通常不在 PATH 上
for tb in /c/Qt/Tools/mingw*/bin /c/Qt/Tools/*/bin; do
    if [ -d "$tb" ]; then PATH="$tb:$PATH"; export PATH; break; fi
done

QT="${QT_ROOT:-${QT:-}}"
if [ -z "$QT" ]; then
    for cand in "C:/Qt/6.11.2/mingw_64" "$HOME/qt/6.11.2/gcc_64" "/usr/lib/qt6" "/usr"; do
        if [ -d "$cand/include/QtCore" ]; then QT="$cand"; break; fi
    done
fi
[ -n "$QT" ] || { echo "未找到 Qt,请用 QT_ROOT= 指定(例如 QT_ROOT=/usr/lib/qt6)" >&2; exit 1; }
QT="$(native_path "$QT")"

MAKE_BIN="${MAKE:-}"
if [ -z "$MAKE_BIN" ]; then
    if command -v make >/dev/null 2>&1; then MAKE_BIN=make
    elif command -v mingw32-make >/dev/null 2>&1; then MAKE_BIN=mingw32-make
    else echo "未找到 make / mingw32-make" >&2; exit 1; fi
fi

QMAKE=""
for cand in "$QT/bin/qmake.exe" "$QT/bin/qmake" "$QT/bin/qmake6" \
            "$QT/bin/qmake6.exe" "$QT/bin/qmake-qt6"; do
    if [ -x "$cand" ]; then QMAKE="$cand"; break; fi
done
[ -n "$QMAKE" ] || { echo "未找到 qmake(试过 qmake/qmake6/qmake-qt6): $QT/bin" >&2; exit 1; }

name="nw_app_bid_probe"
mkdir -p "build/$name"
(cd "build/$name" && "$QMAKE" "../../$name.pro" && "$MAKE_BIN" -j4)
echo "built build/$name/"
