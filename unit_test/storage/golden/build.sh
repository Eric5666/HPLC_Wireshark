#!/bin/bash
# Build this case with qmake (Qt 6.11.2) in shadow build dirs under ./build/.
# Each .pro builds into build/<basename>/ so the case directory stays clean
# (build/, Makefile, *.o, moc_*.cpp are git-ignored).
# Usage: ./build.sh
set -e
cd "$(dirname "$0")"
QT="${QT_ROOT:-$HOME/qt/6.11.2/gcc_64}"   # QT_ROOT(Qt 前缀或 CI 的 symlink farm)优先
export LIBRARY_PATH="$HOME/workspace/build_deps/libfix${LIBRARY_PATH:+:$LIBRARY_PATH}"
export LD_LIBRARY_PATH="$HOME/workspace/build_deps/libfix:$QT/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
for pro in golden.pro; do
  name="$(basename "$pro" .pro)"
  mkdir -p "build/$name"
  (cd "build/$name" && "$QT/bin/qmake" "../../$pro" && make -j"${JOBS:-2}")
  echo "built build/$name/"
done
