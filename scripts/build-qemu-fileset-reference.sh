#!/usr/bin/env bash
# The comparison kernel never executes; it supplies the real RELEASE layout to prelink.
set -euo pipefail
DEVICE=/mnt/g/UniXNU-Port/ports/UniXNU-pdx234
MAIN=/mnt/g/UniXNU-Port/references/xperia-mainline-20261107
TREE=/root/unixnu-build/pdx234-qemu27-out/qemu27-iphone14/ios-27.0.1-24A446-iphone14/qemu27_native_probe/tree
OUT=$DEVICE/out/qemu-fileset-reference-${1:?fresh attempt required}
test ! -e "$OUT"
mkdir -p "$OUT"
CLT=/root/unixnu-toolchain/CommandLineTools/usr
XCT=/root/unixnu-toolchain/XcodeDefault.xctoolchain/usr
LTO=/root/unixnu-build/pdx234-lto-linker/install/bin
export PATH="$LTO:$CLT/bin:/root/unixnu-toolchain/bin:$PATH"
export LD_LIBRARY_PATH="/root/unixnu-build/pdx234-pac-clang-build/lib:${LD_LIBRARY_PATH:-}"
export CROSS_CLANG=/root/unixnu-build/pdx234-pac-toolchain/llvm/bin/clang
export DARWIN_TRIPLE=arm64e-apple-ios27.0
export CROSS_EXTRA_FLAGS='-fptrauth-function-pointer-type-discrimination -mllvm -disable-atexit-based-global-dtor-lowering'
export XNU_TOOLCHAIN_BIN="$LTO $CLT/bin $XCT/bin" CLT_PREFIX="$CLT" XCTOOLCHAIN_PREFIX="$XCT"
export UNIXNU_SDKROOT="$TREE/.cache/fakeroot" UNIXNU_SDK_VERSION=27.0 UNIXNU_PLATFORM_PATH="$TREE/.cache/fakeroot/Platforms/iPhoneOS.platform"
export UNIXNU_XNU_ARCH=arm64e UNIXNU_IOS_VERSION=27.0 UNIXNU_XNU_VERSION=12377.121.6 UNIXNU_XNU_DARWIN=25.5.0
export CCC_OVERRIDE_OPTIONS='# +-Wno-missing-designated-field-initializers +-Wno-unused-but-set-global'
echo "Building RELEASE fileset reference; log: $OUT/build.log"
if ! python3 -u -B "$MAIN/scripts/build-fileset-release-reference.py" --tree "$TREE" --lto > "$OUT/build.log" 2>&1; then
  tail -60 "$OUT/build.log"
  exit 1
fi
tail -12 "$OUT/build.log"
