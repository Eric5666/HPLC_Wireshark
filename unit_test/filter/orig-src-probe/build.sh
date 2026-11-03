#!/bin/bash
# Build orig_src_probe against the parser + model sources in the repo root.
# Usage: ./build.sh [out-binary [repo-dir]]
# Run: ./build/orig_src_probe ../../protocol-gw/gw-topo-merge-probe/gw_topo_merge.bin
set -e
cd "$(dirname "$0")"
REPO_ROOT="$(cd "../../.." && pwd)"
OUT="${1:-./build/orig_src_probe}"
R="${2:-$REPO_ROOT}"
QT="$HOME/qt/6.11.2/gcc_64"
mkdir -p build
"$QT/libexec/moc" "$R/src/ui/packetlistmodel.h" -o build/moc_packetlistmodel.cpp
"$QT/libexec/moc" "$R/3rdparty/qslog/QsLogDestFunctor.h" -o build/moc_QsLogDestFunctor.cpp
g++ -std=c++17 -fPIC \
  -I$R/src -I$R/src/protocol -I$R/src/protocol/common \
  -I$R/src/protocol/nw_protocol/nw_2026 -I$R/src/protocol/nw_protocol/nw_2021 \
  -I$R/src/protocol/gw_protocol/gw_2026 -I$R/src/protocol/gw_protocol/gw_2026/beacon \
  -I$R/src/protocol/gw_protocol/gw_2026/sof -I$R/src/protocol/gw_protocol/gw_2026/ack \
  -I$R/src/protocol/gw_protocol/gw_2026/coord \
  -I$R/src/protocol/gw_protocol/gw_2022 -I$R/src/protocol/gw_protocol/gw_2022/beacon \
  -I$R/src/protocol/gw_protocol/gw_2022/sof -I$R/src/protocol/gw_protocol/gw_2022/ack \
  -I$R/src/protocol/gw_protocol/gw_2022/coord \
  -I$R/src/common -I$R/src/ui -I$R/src/topo -I$R/3rdparty/qslog \
  -I$QT/include -I$QT/include/QtCore -I$QT/include/QtGui -I$QT/include/QtWidgets \
  -I$QT/include/QtConcurrent \
  orig_src_probe.cpp build/moc_packetlistmodel.cpp build/moc_QsLogDestFunctor.cpp \
  $R/src/ui/packetlistmodel.cpp \
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
  $R/src/protocol/nw_protocol/nw_2026/nw_2026_parser.cpp \
  $R/src/protocol/nw_protocol/nw_2026/nw_2026_msdu_parser.cpp \
  $R/src/protocol/nw_protocol/nw_2026/nw_2026_beacon_parser.cpp \
  $R/src/protocol/nw_protocol/nw_2026/nw_2026_tree.cpp \
  $R/src/protocol/nw_protocol/nw_2021/nw_2021_parser.cpp \
  $R/src/protocol/nw_protocol/nw_2021/nw_2021_msdu_parser.cpp \
  $R/src/protocol/nw_protocol/nw_2021/nw_2021_beacon_parser.cpp \
  $R/src/protocol/nw_protocol/nw_2021/nw_2021_tree.cpp \
  -L$QT/lib -L$HOME/workspace/build_deps/libfix \
  -lQt6Widgets -lQt6Gui -lQt6Core -lQt6Concurrent -lEGL -lGL -o "$OUT"
chmod +x "$OUT"
echo "built $OUT"
