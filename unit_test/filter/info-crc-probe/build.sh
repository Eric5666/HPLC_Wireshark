#!/bin/bash
# Build info_crc_probe against the model sources in the repo root.
# Usage: ./build.sh [out-binary [repo-dir]]
# Run: ./build/info_crc_probe
set -e
cd "$(dirname "$0")"
REPO_ROOT="$(cd "../../.." && pwd)"
OUT="${1:-./build/info_crc_probe}"
R="${2:-$REPO_ROOT}"
QT="$HOME/qt/6.11.2/gcc_64"
mkdir -p build
"$QT/libexec/moc" "$R/src/ui/packetlistmodel.h" -o build/moc_packetlistmodel.cpp
"$QT/libexec/moc" "$R/3rdparty/qslog/QsLogDestFunctor.h" -o build/moc_QsLogDestFunctor.cpp
g++ -std=c++17 -fPIC \
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
  -L$QT/lib -L$HOME/workspace/build_deps/libfix \
  -lQt6Widgets -lQt6Gui -lQt6Core -lQt6Concurrent -lEGL -lGL -o "$OUT"
chmod +x "$OUT"
echo "built $OUT"
