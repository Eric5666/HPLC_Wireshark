#!/bin/bash
# Build this probe with qmake into ./build/<name>/.
#
# 用法:
#   bash build.sh                                   # 自动找 Qt / make
#   QT_ROOT=C:/Qt/6.11.2/mingw_64 bash build.sh
#
# Qt 查找顺序: $QT_ROOT → $QT → C:/Qt/6.11.2/mingw_64 → $HOME/qt/6.11.2/gcc_64
# make 查找顺序: $MAKE → make → mingw32-make(Windows 只有 mingw32-make)
set -e
cd "$(dirname "$0")"

# 传给 qmake/moc/g++ 的路径必须是**原生**形式(C:/… 或 MSYS 的 /d/… 混合式);
# bash 习惯的 /c/… 会被原生程序静默忽略(表现为“找不到头文件”)。
native_path() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}

# Windows:Qt 自带的 MinGW 工具链(g++.exe / mingw32-make.exe)通常不在 PATH 上,
# 否则 `make: command not found` / `g++: command not found`
for tb in /c/Qt/Tools/mingw*/bin /c/Qt/Tools/*/bin; do
    if [ -d "$tb" ]; then
        PATH="$tb:$PATH"; export PATH
        break
    fi
done

QT="${QT_ROOT:-${QT:-}}"
if [ -z "$QT" ]; then
    for cand in "C:/Qt/6.11.2/mingw_64" "$HOME/qt/6.11.2/gcc_64" "/c/Qt/6.11.2/mingw_64"; do
        if [ -d "$cand" ]; then QT="$cand"; break; fi
    done
fi
[ -n "$QT" ] || { echo "未找到 Qt,请用 QT_ROOT= 指定" >&2; exit 1; }
QT="$(native_path "$QT")"

MAKE_BIN="${MAKE:-}"
if [ -z "$MAKE_BIN" ]; then
    if command -v make >/dev/null 2>&1; then
        MAKE_BIN=make
    elif command -v mingw32-make >/dev/null 2>&1; then
        MAKE_BIN=mingw32-make
    else
        echo "未找到 make / mingw32-make" >&2
        exit 1
    fi
fi

# qmake 名字随发行版不同:Windows 只有 qmake.exe;Ubuntu/Debian 的 QT_HOST_BINS
# 里常只有 qmake6 或 qmake(qmake-qt6)。逐个探测,别假设叫 qmake。
QMAKE=""
for cand in "$QT/bin/qmake.exe" "$QT/bin/qmake" "$QT/bin/qmake6" \
            "$QT/bin/qmake6.exe" "$QT/bin/qmake-qt6"; do
    if [ -x "$cand" ]; then QMAKE="$cand"; break; fi
done
[ -n "$QMAKE" ] || { echo "未找到 qmake(试过 qmake/qmake6/qmake-qt6): $QT/bin" >&2; exit 1; }

name="entry_containment_probe"
mkdir -p "build/$name"
(cd "build/$name" && "$QMAKE" "../../$name.pro" && "$MAKE_BIN" -j4)
echo "built build/$name/"
