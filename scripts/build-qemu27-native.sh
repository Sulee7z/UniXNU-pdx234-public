#!/usr/bin/env bash
set -euo pipefail
DEVICE=/mnt/g/UniXNU-Port/ports/UniXNU-pdx234
MAIN=/root/unixnu-build/pdx234-qemu27-mainline
BOARD=/root/unixnu-build/pdx234-qemu27-device
OUT=/root/unixnu-build/pdx234-qemu27-out
LOG=$DEVICE/out/qemu27-native-${1:?fresh attempt label required}
test ! -e "$LOG"
mkdir -p "$LOG"
export UNIXNU_TOOLCHAIN=/root/unixnu-build/pdx234-pac-toolchain
export PATH="/root/unixnu-build/pdx234-lto-linker/install/bin:$PATH"
export LD_LIBRARY_PATH="/root/unixnu-build/pdx234-pac-clang-build/lib:${LD_LIBRARY_PATH:-}"
ARGS=(-D "$BOARD" --out "$OUT" \
  --local-module driver:ArmVirtPlatform=/root/unixnu-build/pdx234-qemu-components/ArmVirtPlatform \
  --local-module "driver:ArmCpu=$DEVICE/.cache/firmware-components/ArmCpu" \
  --local-module "driver:DarwinBoot=$DEVICE/.cache/firmware-components/DarwinBoot" \
  --local-module "kit:XnuPrelink=$DEVICE/.cache/firmware-components/XnuPrelink")
cd "$MAIN"
python3 -B unixnu defconfig qemu27_native_probe_defconfig "${ARGS[@]}" > "$LOG/defconfig.log" 2>&1
python3 -B unixnu fetch "${ARGS[@]}" > "$LOG/fetch.log" 2>&1
python3 -B unixnu status --json "${ARGS[@]}" > "$LOG/status.json"
echo "Building native arm64e virtual kernel; log: $LOG/build.log"
if ! python3 -u -B unixnu build kernel --skip-prelink -j4 "${ARGS[@]}" > "$LOG/build.log" 2>&1; then
  tail -65 "$LOG/build.log"
  exit 1
fi
echo 'Native virtual-kernel build finished; no handset image or device operations'
