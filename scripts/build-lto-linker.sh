#!/usr/bin/env bash
# Preserve the original ld64; build an LTO-capable matching linker separately.
set -euo pipefail
DEVICE=/mnt/g/UniXNU-Port/ports/UniXNU-pdx234
WORK=/root/unixnu-build/pdx234-lto-linker
OUT=$DEVICE/out/lto-linker-${1:?fresh attempt label required}
LLVM=/root/unixnu-build/pdx234-pac-clang-build
CLT=/root/unixnu-toolchain/CommandLineTools/usr
test ! -e "$OUT"
mkdir -p "$OUT" "$WORK"
cmake -S /root/unixnu-build/pdx234-pac-clang/llvm -B "$LLVM" \
  -DCMAKE_SHARED_LINKER_FLAGS=-fuse-ld=lld > "$OUT/llvm-configure.log" 2>&1
if ! ninja -C "$LLVM" -j4 LTO llvm-config > "$OUT/llvm-lto.log" 2>&1; then
  tail -60 "$OUT/llvm-lto.log"
  exit 1
fi
if [ ! -d "$WORK/source/.git" ]; then
  git clone --depth 1 --branch 1030.6.3-ld64-956.6 https://github.com/tpoechtrager/cctools-port.git "$WORK/source" > "$OUT/fetch.log" 2>&1
fi
export CC=/usr/bin/clang CXX=/usr/bin/clang++ LD_LIBRARY_PATH="$LLVM/lib:${LD_LIBRARY_PATH:-}"
export CPPFLAGS="-I/root/unixnu-build/pdx234-pac-clang/llvm/include -I$LLVM/include"
cd "$WORK/source/cctools"
if ! ./configure --prefix="$WORK/install" --target=arm64-apple-darwin --program-prefix= \
  --enable-lto-support --with-llvm-config="$LLVM/bin/llvm-config" \
  --with-libdispatch="$CLT/libdispatch" --with-libblocksruntime="$CLT/libdispatch" > "$OUT/configure.log" 2>&1; then
  tail -60 "$OUT/configure.log"
  exit 1
fi
if ! make -j4 PROGRAM_PREFIX= > "$OUT/build.log" 2>&1; then
  tail -60 "$OUT/build.log"
  exit 1
fi
make install PROGRAM_PREFIX= > "$OUT/install.log" 2>&1
if [ ! -e "$WORK/install/bin/ld-classic" ]; then
  ln -s ld "$WORK/install/bin/ld-classic"
fi
"$WORK/install/bin/ld" -v > "$OUT/version.log" 2>&1
cat "$OUT/version.log"
