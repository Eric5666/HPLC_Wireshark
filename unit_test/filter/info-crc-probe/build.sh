#!/bin/bash
# Build info_crc_probe against the model sources in the repo root.
#
# 用法: bash build.sh [out-binary [repo-dir]]
# 运行: ./build/info_crc_probe
#
# Qt 查找顺序: $QT_ROOT → $QT → C:/Qt/6.11.2/mingw_64 → $HOME/qt/6.11.2/gcc_64
# Windows(git-bash/MinGW)自动去掉 -lEGL -lGL 与 Linux 专有的 libfix 库路径。
set -e
cd "$(dirname "$0")"

# 传给 g++/moc 的路径必须是**原生**形式(C:/… 或 MSYS 的 /d/… 混合式);
# bash 习惯的 /c/… 会被原生程序静默忽略(表现为“找不到头文件”)。
native_path() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}

# Windows:Qt 自带的 MinGW 工具链(g++.exe)通常不在 PATH 上 → g++: command not found
for tb in /c/Qt/Tools/mingw*/bin /c/Qt/Tools/*/bin; do
    if [ -d "$tb" ]; then
        PATH="$tb:$PATH"; export PATH
        break
    fi
done

REPO_ROOT="$(cd "../../.." && pwd)"
OUT="${1:-./build/info_crc_probe}"
R="$(native_path "${2:-$REPO_ROOT}")"

QT="${QT_ROOT:-${QT:-}}"
if [ -z "$QT" ]; then
    for cand in "C:/Qt/6.11.2/mingw_64" "$HOME/qt/6.11.2/gcc_64" "/c/Qt/6.11.2/mingw_64"; do
        if [ -d "$cand" ]; then QT="$cand"; break; fi
    done
fi
[ -n "$QT" ] || { echo "未找到 Qt,请用 QT_ROOT= 指定" >&2; exit 1; }
QT="$(native_path "$QT")"

# moc:Windows 版 Qt 装在 bin/(无 libexec/),Linux 版在 libexec/
# moc 位置随发行版不同:Windows 在 bin/;Debian/Ubuntu 在 libexec/(bin/ 里也可能有)。
MOC=""
for cand in "$QT/bin/moc.exe" "$QT/bin/moc" "$QT/libexec/moc" "$QT/libexec/moc.exe"; do
    if [ -x "$cand" ]; then MOC="$cand"; break; fi
done
[ -n "$MOC" ] || { echo "未找到 moc(试过 bin/ 与 libexec/): $QT" >&2; exit 1; }

case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) WINDOWS=1 ;;
    *)                     WINDOWS=0 ;;
esac

CXXFLAGS="-std=c++17"
LIBS="-L$QT/lib -lQt6Widgets -lQt6Gui -lQt6Core -lQt6Concurrent"
if [ "$WINDOWS" = "1" ]; then
    echo "build: Windows/MinGW, Qt=$QT"
else
    CXXFLAGS="$CXXFLAGS -fPIC"
    LIBS="$LIBS -lEGL -lGL"
    [ -d "$HOME/workspace/build_deps/libfix" ] && LIBS="-L$HOME/workspace/build_deps/libfix $LIBS"
    echo "build: Linux/gcc, Qt=$QT"
fi

mkdir -p build
"$MOC" "$R/src/ui/packetlistmodel.h" -o build/moc_packetlistmodel.cpp
"$MOC" "$R/3rdparty/qslog/QsLogDestFunctor.h" -o build/moc_QsLogDestFunctor.cpp

g++ $CXXFLAGS \
  -I$R/src -I$R/src/protocol -I$R/src/protocol/common \
  -I$R/src/common -I$R/src/ui -I$R/src/topo -I$R/3rdparty/qslog \
  -I$QT/include -I$QT/include/QtCore -I$QT/include/QtGui -I$QT/include/QtWidgets \
  -I$QT/include/QtConcurrent \
  info_crc_probe.cpp build/moc_packetlistmodel.cpp build/moc_QsLogDestFunctor.cpp \
  $R/src/ui/packetlistmodel.cpp \
  $R/src/common/i18n.cpp \
  $R/src/protocol/protocol_tree_builder.cpp \
  $R/3rdparty/qslog/QsLog.cpp $R/3rdparty/qslog/QsLogDest.cpp \
  $R/3rdparty/qslog/QsLogDestConsole.cpp $R/3rdparty/qslog/QsLogDestFile.cpp \
  $R/3rdparty/qslog/QsLogDestFunctor.cpp \
  $LIBS -o "$OUT"
echo "built $OUT"
