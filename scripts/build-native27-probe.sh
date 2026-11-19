#!/usr/bin/env bash
# Explicit native-only compiler probe; not final iPhone userland or a storage deployment.
set -euo pipefail
BASE=/mnt/g/UniXNU-Port
DEVICE=$BASE/ports/UniXNU-pdx234
ROOT=/root/unixnu-build/pdx234-mainline
PROBE=/root/unixnu-build/pdx234-native-probe-device
OUT=/root/unixnu-build/pdx234-native27-out
LOG=$DEVICE/out/native27-probe-${1:-001}
test ! -e "$LOG"
mkdir -p "$LOG"
export UNIXNU_TOOLCHAIN=/root/unixnu-toolchain
ARGS=(-D "$PROBE" --out "$OUT" --local-module "driver:ArmCpu=$DEVICE/.cache/firmware-components/ArmCpu" \
      --local-module "driver:ArmDTPlatform=$DEVICE/.cache/firmware-components/ArmDTPlatform" \
      --local-module "driver:DarwinBoot=$DEVICE/.cache/firmware-components/DarwinBoot" \
      --local-module "kit:XnuPrelink=$DEVICE/.cache/firmware-components/XnuPrelink")
cd "$ROOT"
echo 'Preparing the official arm64e/XNU12377 native compiler probe'
python3 -B unixnu defconfig pdx234_native27_probe_defconfig "${ARGS[@]}" > "$LOG/defconfig.log" 2>&1
python3 -B unixnu fetch "${ARGS[@]}" > "$LOG/fetch.log" 2>&1
python3 -B unixnu status --json "${ARGS[@]}" > "$LOG/status.json"
echo "Building native-only 27 probe; full log: $LOG/build.log"
if ! python3 -u -B unixnu build kernel --skip-prelink -j8 "${ARGS[@]}" > "$LOG/build.log" 2>&1; then
  tail -60 "$LOG/build.log"
  exit 1
fi
echo 'Native compiler probe completed; no kernelcache kexts or phone operations'
