#!/bin/bash
# Build gw_learn_probe against the parser sources in the repo root.
# Adapted from the original script: repo dir defaults to the checkout root
# (unit_test/protocol-gw/gw-learn-probe/../../..), output defaults to
# ./build/gw_learn_probe, and the QsLogDestFunctor moc file is generated at
# build time (never committed; the old build_before/moc_*.cpp is not used).
# Usage: ./build_probe.sh [out-binary [repo-dir]]
set -e
cd "$(dirname "$0")"
REPO_ROOT="$(cd "../../.." && pwd)"
OUT="${1:-./build/gw_learn_probe}"
native_path() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}
R="$(native_path "${2:-$REPO_ROOT}")"
QT="${QT_ROOT:-${QT:-}}"
if [ -z "$QT" ]; then
    for cand in $(ls -d /c/Qt/6.*/mingw_64 2>/dev/null | sort -Vr); do
        [ -d "$cand/include/QtCore" ] && { QT="$cand"; break; }
    done
fi
if [ -z "$QT" ]; then
    for cand in "$HOME/qt/6.11.2/gcc_64" /usr/lib/qt6 /usr; do
        [ -d "$cand/include/QtCore" ] && { QT="$cand"; break; }
    done
fi
[ -n "$QT" ] || { echo "未找到 Qt,请用 QT_ROOT= 指定" >&2; exit 1; }
if [ -x "$QT/libexec/moc" ]; then MOC="$QT/libexec/moc"
elif [ -x "$QT/bin/moc.exe" ]; then MOC="$QT/bin/moc.exe"
elif [ -x "$QT/bin/moc" ]; then MOC="$QT/bin/moc"
else echo "未找到 moc(检查 $QT)" >&2; exit 1; fi
mkdir -p build
"$MOC" "$R/3rdparty/qslog/QsLogDestFunctor.h" -o build/moc_QsLogDestFunctor.cpp
EGL_LIBS=""
for d in /usr/lib/x86_64-linux-gnu /usr/lib64 /usr/lib /usr/local/lib; do
    [ -e "$d/libEGL.so" ] && { EGL_LIBS="-lEGL -lGL"; break; }
done

g++ -std=c++17 -fPIC \
  -I$R/src -I$R/src/protocol -I$R/src/protocol/common \
  -I$R/src/protocol/gw_protocol/gw_2026 -I$R/src/protocol/gw_protocol/gw_2026/beacon \
  -I$R/src/protocol/gw_protocol/gw_2026/sof -I$R/src/protocol/gw_protocol/gw_2026/ack \
  -I$R/src/protocol/gw_protocol/gw_2026/coord \
  -I$R/src/protocol/gw_protocol/gw_2022 -I$R/src/protocol/gw_protocol/gw_2022/beacon \
  -I$R/src/protocol/gw_protocol/gw_2022/sof -I$R/src/protocol/gw_protocol/gw_2022/ack \
  -I$R/src/protocol/gw_protocol/gw_2022/coord \
  -I$R/src/common -I$R/3rdparty/qslog \
  -I$QT/include -I$QT/include/QtCore -I$QT/include/QtGui -I$QT/include/QtWidgets \
  gw_learn_probe.cpp build/moc_QsLogDestFunctor.cpp \
  $R/src/common/i18n.cpp \
  $R/3rdparty/qslog/QsLog.cpp $R/3rdparty/qslog/QsLogDest.cpp \
  $R/3rdparty/qslog/QsLogDestConsole.cpp $R/3rdparty/qslog/QsLogDestFile.cpp \
  $R/3rdparty/qslog/QsLogDestFunctor.cpp \
  $R/src/protocol/protocol_tree_builder.cpp \
  $R/src/protocol/gw_protocol/gw_2026/gw_2026_parser.cpp \
  $R/src/protocol/gw_protocol/gw_2026/gw_2026_msdu_parser.cpp \
  $R/src/protocol/gw_protocol/gw_2026/beacon/gw_2026_beacon_parser.cpp \
  $R/src/protocol/gw_protocol/gw_2026/sof/gw_2026_sof_parser.cpp \
  $R/src/protocol/gw_protocol/gw_2026/ack/gw_2026_ack_parser.cpp \
  $R/src/protocol/gw_protocol/gw_2026/coord/gw_2026_coord_parser.cpp \
  $R/src/protocol/gw_protocol/gw_2026/gw_2026_tree.cpp \
  $R/src/protocol/gw_protocol/gw_2022/gw_2022_parser.cpp \
  $R/src/protocol/gw_protocol/gw_2022/gw_2022_msdu_parser.cpp \
  $R/src/protocol/gw_protocol/gw_2022/beacon/gw_2022_beacon_parser.cpp \
  $R/src/protocol/gw_protocol/gw_2022/sof/gw_2022_sof_parser.cpp \
  $R/src/protocol/gw_protocol/gw_2022/ack/gw_2022_ack_parser.cpp \
  $R/src/protocol/gw_protocol/gw_2022/coord/gw_2022_coord_parser.cpp \
  $R/src/protocol/gw_protocol/gw_2022/gw_2022_tree.cpp \
  -L$QT/lib -L$HOME/workspace/build_deps/libfix \
  -lQt6Widgets -lQt6Gui -lQt6Core $EGL_LIBS -o "$OUT"
chmod +x "$OUT"
echo "built $OUT"
