#!/usr/bin/env bash
# Actual unchanged Android GKI through the official Unixnu Linux/EFI-stub path.
set -euo pipefail
DEVICE=/mnt/g/UniXNU-Port/ports/UniXNU-pdx234
MAINLINE=/mnt/g/UniXNU-Port/references/xperia-mainline-20261107
ATTEMPT=${1:?provide a fresh attempt label}
[[ "$ATTEMPT" =~ ^[A-Za-z0-9]+$ ]]
OUT=$DEVICE/out/qemu-android-linux-$ATTEMPT
WORK=/root/unixnu-build/pdx234-qemu-android-linux-$ATTEMPT
export TMPDIR=/root/unixnu-build
EXTRA=()
if [[ "${2:-full}" == minimal ]]; then EXTRA+=(--minimal-peripherals); fi
python3 -B "$DEVICE/scripts/prepare-android-linux-esp.py" --out "$OUT" --work "$WORK" "${EXTRA[@]}"
cp "$MAINLINE/package/Scripts/qemu-run.py" "$WORK/qemu-run.py"
git -C "$WORK" apply --check "$DEVICE/patches/host/qemu-run-cpu-option.patch"
git -C "$WORK" apply "$DEVICE/patches/host/qemu-run-cpu-option.patch"
if python3 "$WORK/qemu-run.py" "$OUT/esp" --cpu max --cpus 1 --timeout 120 \
  --finish-on-expect --menu-marker 'UNIXNU: menu: shown' --screenshot "$OUT/menu.png" \
  --log "$OUT/guest.log" --expect 'QEMU-ANDROID-LINUX: PASS pid=1 machine=aarch64 release=5.15.211' \
  --reject 'QEMU-ANDROID-LINUX: FAIL' --reject 'Synchronous Exception' \
  --reject 'Kernel panic' > "$OUT/run.log" 2>&1; then
  RESULT=0
else
  RESULT=$?
fi
cat "$OUT/run.log"
exit "$RESULT"
