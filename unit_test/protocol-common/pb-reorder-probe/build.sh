#!/bin/bash
# Build this probe with qmake (Qt 6.11.2) into ./build/<name>/.
# Linux: QT=$HOME/qt/6.11.2/gcc_64   Windows: QT=C:/Qt/6.11.2/mingw_64
set -e
cd "$(dirname "$0")"
QT="${QT:-$HOME/qt/6.11.2/gcc_64}"
name="pb_reorder_probe"
mkdir -p "build/$name"
(cd "build/$name" && "$QT/bin/qmake" "../../$name.pro" && make -j4)
echo "built build/$name/"
