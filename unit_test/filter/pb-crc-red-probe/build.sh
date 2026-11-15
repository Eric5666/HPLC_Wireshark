#!/bin/bash
# 构建 pb_crc_red_probe(qmake 影子构建,产物 build/pb_crc_red_probe[.exe])
# qmake 查找顺序: $QMAKE → $QT_ROOT/bin/qmake → PATH 上的 qmake/qmake6
# 用法: bash build.sh && ./build/pb_crc_red_probe
set -e
cd "$(dirname "$0")"
QM="${QMAKE:-}"
if [ -z "$QM" ] && [ -n "${QT_ROOT:-}" ]; then
    for c in "$QT_ROOT/bin/qmake" "$QT_ROOT/bin/qmake.exe" "$QT_ROOT/bin/qmake6"; do
        [ -x "$c" ] && { QM="$c"; break; }
    done
fi
[ -n "$QM" ] || QM="$(command -v qmake || command -v qmake6 || true)"
[ -n "$QM" ] || { echo "qmake not found: set QMAKE= or QT_ROOT= or put qmake on PATH" >&2; exit 1; }
for tb in /c/Qt/Tools/mingw*/bin; do [ -d "$tb" ] && { PATH="$tb:$PATH"; export PATH; break; }; done
MK=make; command -v mingw32-make >/dev/null 2>&1 && ! command -v make >/dev/null 2>&1 && MK=mingw32-make
mkdir -p build
cd build
"$QM" ../pb_crc_red_probe.pro CONFIG+=release CONFIG-=debug
"$MK" -j"${JOBS:-2}"
[ -x release/pb_crc_red_probe.exe ] && cp release/pb_crc_red_probe.exe . || true
echo "built build/pb_crc_red_probe"
