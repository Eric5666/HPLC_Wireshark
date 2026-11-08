#!/bin/bash
# Build topo-online-count-probe from the repo root.
# TopoState only: main.cpp + src/topo/topo_state.cpp (+ i18n + QsLog, as in
# unit_test/topo/topo-restart-probe/build.sh).
# Usage: ./build.sh   (produces ./build/online_count_probe)
#   QT_ROOT=C:/Qt/6.11.2/mingw_64 ./build.sh      # Windows 指定 Qt
#   QT_ROOT=/usr/lib/qt6 ./build.sh               # Linux/CI 指定 Qt
# Run:   ./build/online_count_probe   (prints ok/FAIL lines, exit 0 on pass)
#
# Qt 查找顺序: $QT_ROOT → $QT → C:/Qt/6.11.2/mingw_64 → $HOME/qt/6.11.2/gcc_64 → /usr/lib/qt6 → /usr
# moc 查找顺序(不假设叫 moc): $QT/bin/moc.exe → $QT/bin/moc → $QT/libexec/moc → $QT/libexec/moc.exe
set -e
cd "$(dirname "$0")"
REPO_ROOT="$(cd "../../.." && pwd)"

# 传给 g++/moc 的路径必须是**原生**形式(C:/… 或 MSYS 混合式);bash 的 /c/… 会被原生程序忽略
native_path() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}

# Windows:Qt 自带 MinGW 工具链(g++.exe)通常不在 PATH 上
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

MOC=""
for cand in "$QT/bin/moc.exe" "$QT/bin/moc" "$QT/libexec/moc" "$QT/libexec/moc.exe"; do
    if [ -x "$cand" ]; then MOC="$cand"; break; fi
done
[ -n "$MOC" ] || { echo "未找到 moc(试过 $QT/bin 与 $QT/libexec):请装 qt6-base-dev-tools 或用 QT_ROOT= 指定" >&2; exit 1; }

REPO_ROOT="$(native_path "$REPO_ROOT")"
mkdir -p build
"$MOC" "$REPO_ROOT/3rdparty/qslog/QsLogDestFunctor.h" -o build/moc_QsLogDestFunctor.cpp
INC="-I$REPO_ROOT/src -I$REPO_ROOT/src/protocol -I$REPO_ROOT/src/protocol/common \
  -I$REPO_ROOT/src/common -I$REPO_ROOT/src/topo \
  -I$REPO_ROOT/3rdparty/qslog \
  -I$QT/include -I$QT/include/QtCore -I$QT/include/QtGui -I$QT/include/QtWidgets"
QSLOG="$REPO_ROOT/3rdparty/qslog/QsLog.cpp $REPO_ROOT/3rdparty/qslog/QsLogDest.cpp \
  $REPO_ROOT/3rdparty/qslog/QsLogDestConsole.cpp $REPO_ROOT/3rdparty/qslog/QsLogDestFile.cpp \
  $REPO_ROOT/3rdparty/qslog/QsLogDestFunctor.cpp"
BASE="$REPO_ROOT/src/common/i18n.cpp $QSLOG build/moc_QsLogDestFunctor.cpp"
TOPO="$REPO_ROOT/src/topo/topo_state.cpp"
LIBS="-L$QT/lib -lQt6Widgets -lQt6Gui -lQt6Core"
# shellcheck disable=SC2086
g++ -std=c++17 -fPIC $INC main.cpp $TOPO $BASE $LIBS -o "build/online_count_probe"
chmod +x "build/online_count_probe"
echo "built build/online_count_probe"
