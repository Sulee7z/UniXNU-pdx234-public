#!/usr/bin/env bash
# Official common-UEFI QEMU scenarios. A pass is NOT an iOS/SpringBoard qualification.
set -euo pipefail
BASE=/mnt/g/UniXNU-Port
DEVICE=$BASE/ports/UniXNU-pdx234
SOURCE=$BASE/references/xperia-mainline-20261107
ATTEMPT=${1:?provide a fresh attempt label}
[[ "$ATTEMPT" =~ ^[A-Za-z0-9]+$ ]]
OUT=$DEVICE/out/qemu-common-$ATTEMPT
WORK=/root/unixnu-build/pdx234-qemu-common-$ATTEMPT
test ! -e "$OUT"
test ! -e "$WORK"
mkdir -p "$OUT" "$WORK/package"
rsync -rlt --exclude=Build --exclude=.git "$SOURCE/package/" "$WORK/package/"
# The pinned source's built-in config includes Tools as its fourth entry.
# Preserve attempt001's failed strict count, and correct only the test expectation.
git -C "$WORK/package" apply --check "$DEVICE/patches/host/qemu-smoke-built-in-tools.patch"
git -C "$WORK/package" apply "$DEVICE/patches/host/qemu-smoke-built-in-tools.patch"
cp "$DEVICE/patches/host/qemu-smoke-built-in-tools.patch" "$OUT/"
export UNIXNU_EDK2=/root/unixnu-build/uefi-pdx234/Mu_Basecore
export PATH="/root/unixnu-build/mu-venv/bin:$UNIXNU_EDK2/BaseTools/BinWrappers/PosixLike:$PATH"
export CLANG_BIN=/usr/bin/ JOBS=8 TMPDIR=/root/unixnu-build
echo "Official QEMU common-UEFI scenarios; full log: $OUT/smoke.log"
if bash "$WORK/package/Scripts/smoke.sh" > "$OUT/smoke.log" 2>&1; then
  RESULT=0
else
  RESULT=$?
fi
if [ -d "$WORK/package/Build/Smoke" ]; then
  rsync -rlt "$WORK/package/Build/Smoke/" "$OUT/scenarios/"
fi
if [ -d "$WORK/package/Build/Out" ]; then
  rsync -rlt "$WORK/package/Build/Out/" "$OUT/efi/"
fi
tail -60 "$OUT/smoke.log"
exit "$RESULT"
