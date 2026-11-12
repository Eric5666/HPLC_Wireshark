#!/bin/bash
# Build this case with qmake in shadow build dirs under ./build/.
# Each .pro builds into build/<basename>/ so the case directory stays clean
# (build/, Makefile, *.o, moc_*.cpp are git-ignored).
# Usage: ./build.sh
set -e
cd "$(dirname "$0")"
# qmake 查找顺序: $QMAKE → $QT_ROOT/bin/qmake → PATH 上的 qmake → 旧默认 $HOME/qt/6.11.2/gcc_64
QT="${QT_ROOT:-$HOME/qt/6.11.2/gcc_64}"
QMAKE="${QMAKE:-}"
[ -z "$QMAKE" ] && [ -x "$QT/bin/qmake" ] && QMAKE="$QT/bin/qmake"
[ -z "$QMAKE" ] && QMAKE="$(command -v qmake || command -v qmake6 || true)"
[ -n "$QMAKE" ] || { echo "qmake not found: set QMAKE= or QT_ROOT= or put qmake on PATH" >&2; exit 1; }
export LIBRARY_PATH="$HOME/workspace/build_deps/libfix${LIBRARY_PATH:+:$LIBRARY_PATH}"
export LD_LIBRARY_PATH="$HOME/workspace/build_deps/libfix:$("$QMAKE" -query QT_INSTALL_LIBS)${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
for pro in probe.pro fb/probe_fb.pro; do
  name="$(basename "$pro" .pro)"
  mkdir -p "build/$name"
  (cd "build/$name" && "$QMAKE" "../../$pro" && make)
  echo "built build/$name/"
done
