#!/bin/bash
# MSDU CRC32 三态门控探针(用户 2026-11 裁决)—— 跨平台构建/运行
# 用法:
#   QT_ROOT=C:/Qt/6.11.2/mingw_64 bash build.sh    # Windows
#   QT_ROOT=/usr/lib/qt6 bash build.sh              # Linux / CI
# 产物: build/msdu_crc_gate_probe ; 运行 exit 0 = 全部断言通过
set -e
cd "$(dirname "$0")"
REPO_ROOT="$(cd ../../.. && pwd)"

native_path() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}

# Windows:Qt 自带 MinGW 工具链通常不在 PATH 上
for tb in /c/Qt/Tools/mingw*/bin /c/Qt/Tools/*/bin; do
    if [ -d "$tb" ]; then PATH="$tb:$PATH"; export PATH; break; fi
done

QT="${QT_ROOT:-${QT:-}}"
if [ -z "$QT" ]; then
    # 本机 Qt 可能已升级(6.11.2 → 6.11.3):按版本倒序取最新,别写死单一版本
    for cand in $(ls -d /c/Qt/6.*/mingw_64 2>/dev/null | sort -Vr); do
        if [ -d "$cand/include/QtCore" ]; then QT="$cand"; break; fi
    done
fi
if [ -z "$QT" ]; then
    for cand in "$HOME/qt/6.11.2/gcc_64" "/usr/lib/qt6" "/usr"; do
        if [ -d "$cand/include/QtCore" ]; then QT="$cand"; break; fi
    done
fi
[ -n "$QT" ] || { echo "未找到 Qt,请用 QT_ROOT= 指定" >&2; exit 1; }
QT="$(native_path "$QT")"
REPO_ROOT="$(native_path "$REPO_ROOT")"

NW21="$REPO_ROOT/src/protocol/nw_protocol/nw_2021"
NW26="$REPO_ROOT/src/protocol/nw_protocol/nw_2026"
GW26="$REPO_ROOT/src/protocol/gw_protocol/gw_2026"
GW22="$REPO_ROOT/src/protocol/gw_protocol/gw_2022"
FIXTURE="$(native_path "$REPO_ROOT/unit_test/frames/frame-probe/nw_log_tail_pb_crc_fail.bin")"
GW_FIXTURE="$(native_path "$REPO_ROOT/unit_test/frames/frame-probe/gw2026_ofdma_sim.bin")"
WIRE_FIXTURE="$(native_path "$REPO_ROOT/unit_test/frames/frame-probe/nw_log_tail_wire_escaped.bin")"

INC="-I$REPO_ROOT/src -I$REPO_ROOT/src/common -I$REPO_ROOT/src/io -I$REPO_ROOT/src/protocol \
  -I$REPO_ROOT/src/protocol/common -I$REPO_ROOT/src/ui -I$NW21 -I$NW26 -I$GW26 -I$GW26/beacon \
  -I$GW26/sof -I$GW26/coord -I$GW26/ack \
  -I$GW22 -I$GW22/beacon -I$GW22/sof -I$GW22/coord -I$GW22/ack \
  -I$REPO_ROOT/3rdparty/qslog \
  -I$QT/include -I$QT/include/QtCore -I$QT/include/QtGui -I$QT/include/QtWidgets \
  -I$QT/include/QtConcurrent"

mkdir -p build

MOC=""
for cand in "$QT/bin/moc.exe" "$QT/bin/moc" "$QT/libexec/moc" "$QT/libexec/moc.exe"; do
    if [ -x "$cand" ]; then MOC="$cand"; break; fi
done
[ -n "$MOC" ] || { echo "未找到 moc" >&2; exit 1; }
"$MOC" "$REPO_ROOT/3rdparty/qslog/QsLogDestFunctor.h" -o build/moc_QsLogDestFunctor.cpp
"$MOC" "$REPO_ROOT/src/ui/packetlistmodel.h" -o build/moc_packetlistmodel.cpp

QSLOG="$REPO_ROOT/3rdparty/qslog/QsLog.cpp $REPO_ROOT/3rdparty/qslog/QsLogDest.cpp \
  $REPO_ROOT/3rdparty/qslog/QsLogDestConsole.cpp $REPO_ROOT/3rdparty/qslog/QsLogDestFile.cpp \
  $REPO_ROOT/3rdparty/qslog/QsLogDestFunctor.cpp"

# shellcheck disable=SC2086
g++ -std=c++17 -O1 -fPIC $INC \
  -DFIXTURE_PATH="\"$FIXTURE\"" -DGW_FIXTURE_PATH="\"$GW_FIXTURE\"" -DWIRE_FIXTURE="\"$WIRE_FIXTURE\"" \
  msdu_crc_gate_probe.cpp \
  "$NW21/nw_2021_parser.cpp" "$NW21/nw_2021_msdu_parser.cpp" "$NW21/nw_2021_beacon_parser.cpp" \
  "$NW26/nw_2026_parser.cpp" "$NW26/nw_2026_msdu_parser.cpp" "$NW26/nw_2026_beacon_parser.cpp" \
  "$GW26/gw_2026_parser.cpp" "$GW26/gw_2026_msdu_parser.cpp" "$GW26/gw_2026_tree.cpp" \
  "$GW26/beacon/gw_2026_beacon_parser.cpp" "$GW26/sof/gw_2026_sof_parser.cpp" \
  "$GW26/coord/gw_2026_coord_parser.cpp" "$GW26/ack/gw_2026_ack_parser.cpp" \
  "$GW22/gw_2022_parser.cpp" "$GW22/gw_2022_msdu_parser.cpp" "$GW22/gw_2022_tree.cpp" \
  "$GW22/beacon/gw_2022_beacon_parser.cpp" "$GW22/sof/gw_2022_sof_parser.cpp" \
  "$GW22/coord/gw_2022_coord_parser.cpp" "$GW22/ack/gw_2022_ack_parser.cpp" \
  "$REPO_ROOT/src/protocol/protocol_tree_builder.cpp" \
  "$REPO_ROOT/src/common/i18n.cpp" "$REPO_ROOT/src/ui/packetlistmodel.cpp" \
  $QSLOG build/moc_QsLogDestFunctor.cpp build/moc_packetlistmodel.cpp \
  -L"$QT/lib" -lQt6Widgets -lQt6Gui -lQt6Core -lQt6Concurrent \
  -o build/msdu_crc_gate_probe
chmod +x build/msdu_crc_gate_probe
echo "built build/msdu_crc_gate_probe"
