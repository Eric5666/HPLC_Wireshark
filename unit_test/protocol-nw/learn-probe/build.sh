#!/bin/bash
# Build learn-probe (NW_2026 TEI<->MAC learning) from the repo root.
# NW probes link the full NW_2026 group plus NW_2021 (delegation fallback)
# plus protocol_tree_builder; the QsLogDestFunctor moc file is generated at
# build time (never committed).
# Usage: ./build.sh   (produces ./build/learn_probe)
# Run:   ./build/learn_probe files crafted/*.bin
#        ./build/learn_probe scan <length-prefixed-mpdus.bin>  (dataset not shipped)
set -e
cd "$(dirname "$0")"
REPO_ROOT="$(cd "../../.." && pwd)"
QT="${QT_ROOT:-$HOME/qt/6.11.2/gcc_64}"   # QT_ROOT(Qt 前缀或 CI 的 symlink farm)优先
LIBFIX="$HOME/workspace/build_deps/libfix"
NW26="$REPO_ROOT/src/protocol/nw_protocol/nw_2026"
NW21="$REPO_ROOT/src/protocol/nw_protocol/nw_2021"
mkdir -p build
"$QT/libexec/moc" "$REPO_ROOT/3rdparty/qslog/QsLogDestFunctor.h" -o build/moc_QsLogDestFunctor.cpp
g++ -std=c++17 -fPIC \
  -I"$REPO_ROOT/src" -I"$REPO_ROOT/src/protocol" -I"$REPO_ROOT/src/protocol/common" \
  -I"$NW26" -I"$NW21" -I"$REPO_ROOT/src/common" -I"$REPO_ROOT/3rdparty/qslog" \
  -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/include/QtGui" -I"$QT/include/QtWidgets" \
  learn_probe.cpp build/moc_QsLogDestFunctor.cpp \
  "$REPO_ROOT/src/common/i18n.cpp" \
  "$REPO_ROOT/3rdparty/qslog/QsLog.cpp" "$REPO_ROOT/3rdparty/qslog/QsLogDest.cpp" \
  "$REPO_ROOT/3rdparty/qslog/QsLogDestConsole.cpp" "$REPO_ROOT/3rdparty/qslog/QsLogDestFile.cpp" \
  "$REPO_ROOT/3rdparty/qslog/QsLogDestFunctor.cpp" \
  "$REPO_ROOT/src/protocol/protocol_tree_builder.cpp" \
  "$NW26/nw_2026_parser.cpp" "$NW26/nw_2026_msdu_parser.cpp" \
  "$NW26/nw_2026_beacon_parser.cpp" "$NW26/nw_2026_tree.cpp" \
  "$NW21/nw_2021_parser.cpp" "$NW21/nw_2021_msdu_parser.cpp" \
  "$NW21/nw_2021_beacon_parser.cpp" "$NW21/nw_2021_tree.cpp" \
  -L"$QT/lib" -L"$LIBFIX" -lQt6Widgets -lQt6Gui -lQt6Core -lEGL -lGL \
  -o build/learn_probe
chmod +x build/learn_probe
echo "built build/learn_probe"
