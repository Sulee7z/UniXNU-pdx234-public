#!/usr/bin/env bash
# Build the repaired compiler in an isolated prefix. Never overwrite the old toolchain.
set -euo pipefail
DEVICE=/mnt/g/UniXNU-Port/ports/UniXNU-pdx234
SOURCE=/root/unixnu-build/pdx234-pac-clang
BUILD=/root/unixnu-build/pdx234-pac-clang-build
PREFIX=/root/unixnu-build/pdx234-pac-toolchain
OUT=$DEVICE/out/pac-clang-build-${1:?fresh attempt label required}
test ! -e "$OUT"
mkdir -p "$OUT" "$PREFIX"
git -C "$SOURCE" diff --check
git -C "$SOURCE" diff -- clang > "$OUT/llvm-authenticated-null.patch"
if ! cmake -G Ninja -S "$SOURCE/llvm" -B "$BUILD" \
  -DLLVM_ENABLE_PROJECTS=clang -DLLVM_TARGETS_TO_BUILD=AArch64 \
  -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_ASSERTIONS=ON \
  -DLLVM_INCLUDE_TESTS=OFF -DLLVM_INCLUDE_EXAMPLES=OFF -DLLVM_INCLUDE_BENCHMARKS=OFF \
  -DCLANG_ENABLE_STATIC_ANALYZER=OFF -DCLANG_ENABLE_ARCMT=OFF \
  -DLLVM_PARALLEL_LINK_JOBS=1 -DLLVM_INSTALL_UTILS=ON \
  -DCMAKE_C_COMPILER=/usr/bin/clang -DCMAKE_CXX_COMPILER=/usr/bin/clang++ \
  -DCMAKE_EXE_LINKER_FLAGS=-fuse-ld=lld \
  -DCMAKE_SHARED_LINKER_FLAGS=-fuse-ld=lld \
  -DCMAKE_INSTALL_PREFIX="$PREFIX/llvm" > "$OUT/configure.log" 2>&1; then
  tail -70 "$OUT/configure.log"
  exit 1
fi
echo "Building repaired PAC compiler; log: $OUT/build.log"
if ! ninja -C "$BUILD" -j4 install-clang install-clang-resource-headers FileCheck llvm-objdump llvm-readobj > "$OUT/build.log" 2>&1; then
  tail -70 "$OUT/build.log"
  exit 1
fi
for NAME in CommandLineTools XcodeDefault.xctoolchain bin; do
  if [ ! -e "$PREFIX/$NAME" ]; then
    ln -s "/root/unixnu-toolchain/$NAME" "$PREFIX/$NAME"
  fi
done
"$PREFIX/llvm/bin/clang" --version > "$OUT/version.txt"
cat "$OUT/version.txt"
