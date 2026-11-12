#!/bin/bash
# H1 get_bits 边界检查探针:ASan 下喂截断帧,验证拒收/不崩。
# 用法: ./build.sh [norun]  (默认构建并运行;传 norun 只构建)
# Qt 路径走环境变量 QT_ROOT,未设时默认 ~/Qt/6.11.3/6.11.3/gcc_64。
set -e
cd "$(dirname "$0")"
QT_ROOT="${QT_ROOT:-$HOME/Qt/6.11.3/6.11.3/gcc_64}"
export LD_LIBRARY_PATH="$QT_ROOT/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
mkdir -p build/h1_getbits_probe
(cd build/h1_getbits_probe && "$QT_ROOT/bin/qmake" "SANITIZERS=address" ../../h1_getbits_probe.pro && make)
echo "built build/h1_getbits_probe/"
if [ "$1" != "norun" ]; then
  QT_QPA_PLATFORM=offscreen ./build/h1_getbits_probe/h1_getbits_probe
fi
