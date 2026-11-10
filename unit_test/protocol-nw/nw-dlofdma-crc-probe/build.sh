#!/bin/bash
# NW DL-OFDMA CRC24 判定探针
# 跨平台构建(Qt 路径不写死;优先 QT_ROOT,其次按版本倒序探测):
#   QT_ROOT=C:/Qt/6.11.3/mingw_64 bash build.sh   # Windows
#   QT_ROOT=/usr/lib/qt6 bash build.sh             # Linux / CI
# 产物: build/nw_dlofdma_crc_probe/
set -e
cd "$(dirname "$0")"

native_path() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}

# Windows:Qt 自带 MinGW 工具链通常不在 PATH 上
for tb in /c/Qt/Tools/mingw*/bin /c/Qt/Tools/*/bin; do
    if [ -d "$tb" ]; then PATH="$tb:$PATH"; export PATH; break; fi
done

QT="${QT_ROOT:-${QT:-}}"
if [ -z "$QT" ]; then
    # 本机 Qt 可能升级(6.11.2 → 6.11.3):按版本倒序取最新,别写死单一版本
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

# make 选择:Windows 只有 mingw32-make
if command -v mingw32-make >/dev/null 2>&1; then MAKE_BIN=mingw32-make
elif command -v make >/dev/null 2>&1; then MAKE_BIN=make
else echo "未找到 make/mingw32-make" >&2; exit 1; fi


for pro in nw_dlofdma_crc_probe.pro; do
  name="$(basename "$pro" .pro)"
  mkdir -p "build/$name"
  ( cd "build/$name" && "$QT/bin/qmake" "../../$pro" CONFIG+=release CONFIG-=debug && "$MAKE_BIN" -j4 )
  echo "built build/$name/"
done
