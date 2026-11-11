#!/bin/bash
# Build gw_topo_merge_probe against the parser sources in the repo root.
# Adapted from the original script: repo dir defaults to the checkout root
# (unit_test/protocol-gw/gw-topo-merge-probe/../../..), output defaults to
# ./build/gw_topo_merge_probe, and the QsLogDestFunctor moc file is generated
# at build time (never committed).
# Usage: ./build.sh [out-binary [repo-dir]]
set -e
cd "$(dirname "$0")"
REPO_ROOT="$(cd "../../.." && pwd)"
# 本仓工具链是原生 MinGW/Linux 程序:MSYS 的 /d/... 路径原生程序读不了,
# 需要时用 cygpath -m 转成 D:/... (Linux 上 cygpath 不存在,原样返回)
native_path() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}
OUT="${1:-./build/gw_topo_merge_probe}"
R="$(native_path "${2:-$REPO_ROOT}")"
QT="${QT_ROOT:-${QT:-}}"
if [ -z "$QT" ]; then
    # 本机 Qt 版本会升级:按版本倒序取最新的 mingw_64,别写死单一版本
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
# moc 位置随平台不同:Linux 在 libexec/,Windows 在 bin/moc.exe
if [ -x "$QT/libexec/moc" ]; then MOC="$QT/libexec/moc"
elif [ -x "$QT/bin/moc.exe" ]; then MOC="$QT/bin/moc.exe"
elif [ -x "$QT/bin/moc" ]; then MOC="$QT/bin/moc"
else echo "未找到 moc(检查 $QT)" >&2; exit 1; fi
mkdir -p build
"$MOC" "$R/3rdparty/qslog/QsLogDestFunctor.h" -o build/moc_QsLogDestFunctor.cpp
# 仅 Linux/CI 需要 EGL/GL(Windows 无此库),按 libEGL.so 是否存在决定
EGL_LIBS=""
for d in /usr/lib/x86_64-linux-gnu /usr/lib64 /usr/lib /usr/local/lib; do
    if [ -e "$d/libEGL.so" ]; then EGL_LIBS="-lEGL -lGL"; break; fi
done

g++ -std=c++17 -fPIC \
  -I$R/src -I$R/src/protocol -I$R/src/protocol/common \
  -I$R/src/protocol/gw_protocol/gw_2026 -I$R/src/protocol/gw_protocol/gw_2026/beacon \
  -I$R/src/protocol/gw_protocol/gw_2026/sof -I$R/src/protocol/gw_protocol/gw_2026/ack \
  -I$R/src/protocol/gw_protocol/gw_2026/coord \
  -I$R/src/protocol/gw_protocol/gw_2022 -I$R/src/protocol/gw_protocol/gw_2022/beacon \
  -I$R/src/protocol/gw_protocol/gw_2022/sof -I$R/src/protocol/gw_protocol/gw_2022/ack \
  -I$R/src/protocol/gw_protocol/gw_2022/coord \
  -I$R/src/common -I$R/src/topo -I$R/3rdparty/qslog \
  -I$QT/include -I$QT/include/QtCore -I$QT/include/QtGui -I$QT/include/QtWidgets \
  gw_topo_merge_probe.cpp build/moc_QsLogDestFunctor.cpp \
  $R/src/common/i18n.cpp \
  $R/src/topo/topo_state.cpp \
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
