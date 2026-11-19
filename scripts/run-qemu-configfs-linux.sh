#!/usr/bin/env bash
# Historical candidate007 qualification, not the active iOS-only menu route.
set -euo pipefail
DEVICE=/mnt/g/UniXNU-Port/ports/UniXNU-pdx234
SOURCE=/mnt/g/UniXNU-Port/ports/uefi-pdx234/Platforms/Sony/pdx234Pkg
MAINLINE=/mnt/g/UniXNU-Port/references/xperia-mainline-20261107
ATTEMPT=${1:?provide a fresh attempt label}
[[ "$ATTEMPT" =~ ^[A-Za-z0-9]+$ ]]
OUT=$DEVICE/out/qemu-configfs-linux-$ATTEMPT
WORK=/root/unixnu-build/pdx234-qemu-configfs-linux-$ATTEMPT
export TMPDIR=/root/unixnu-build
python3 -B "$DEVICE/scripts/prepare-android-linux-esp.py" --out "$OUT" --work "$WORK" --minimal-peripherals
mkdir -p "$WORK/AndroidLinux" "$WORK/pdx234Pkg/Drivers/PdxConfigFsDxe" "$WORK/pdx234Pkg/Include" "$WORK/Conf" "$OUT/esp/EFI/Drivers"
cp "$DEVICE/tests/qemu/AndroidLinux/ConfigFsProbe."{c,inf,dsc} "$WORK/AndroidLinux/"
UEFI_REPO=/mnt/g/UniXNU-Port/ports/uefi-pdx234
REVISION=25c178d79fbbda894730a47be33c38a93b099053
for NAME in PdxConfigFs.c PdxConfigFsDxe.inf; do
  git -C "$UEFI_REPO" show "$REVISION:Platforms/Sony/pdx234Pkg/Drivers/PdxConfigFsDxe/$NAME" > "$WORK/pdx234Pkg/Drivers/PdxConfigFsDxe/$NAME"
done
git -C "$UEFI_REPO" show "$REVISION:Platforms/Sony/pdx234Pkg/Include/PdxBootSource.h" > "$WORK/pdx234Pkg/Include/PdxBootSource.h"
EDK=/root/unixnu-build/uefi-pdx234/Mu_Basecore
export WORKSPACE=$WORK PACKAGES_PATH="$WORK:$EDK" EDK_TOOLS_PATH=$EDK/BaseTools CONF_PATH=$WORK/Conf
export PATH="/root/unixnu-build/mu-venv/bin:$EDK/BaseTools/BinWrappers/PosixLike:$EDK/BaseTools/Source/C/bin:$PATH"
export CLANG_BIN=/usr/bin/ PYTHON_COMMAND=python3
for NAME in target tools_def build_rule; do cp "$EDK/BaseTools/Conf/$NAME.template" "$WORK/Conf/$NAME.txt"; done
if ! build -p AndroidLinux/ConfigFsProbe.dsc -a AARCH64 -b DEBUG -t CLANGPDB -n8 > "$OUT/build.log" 2>&1; then tail -70 "$OUT/build.log"; exit 1; fi
mv "$OUT/esp/EFI/BOOT/BOOTAA64.EFI" "$OUT/esp/EFI/UniXNU/UniXNU.efi"
mv "$OUT/esp/EFI/UniXNU/unixnu.toml" "$OUT/fixture-request.toml"
cp "$WORK/Build/PdxQemuConfigFs/DEBUG_CLANGPDB/AARCH64/ConfigFsProbe.efi" "$OUT/esp/EFI/BOOT/BOOTAA64.EFI"
cp "$WORK/Build/PdxQemuConfigFs/DEBUG_CLANGPDB/AARCH64/PdxConfigFsDxe.efi" "$OUT/esp/EFI/Drivers/"
cp "$MAINLINE/package/Scripts/qemu-run.py" "$WORK/qemu-run.py"
git -C "$WORK" apply --check "$DEVICE/patches/host/qemu-run-cpu-option.patch"
git -C "$WORK" apply "$DEVICE/patches/host/qemu-run-cpu-option.patch"
if python3 "$WORK/qemu-run.py" "$OUT/esp" --cpu max --cpus 1 --timeout 120 \
  --keys ret --finish-on-expect --screenshot "$OUT/menu.png" --log "$OUT/guest.log" \
  --expect 'QEMU-CONFIGFS: PASS actual readonly volume and inherited inputs' \
  --expect 'QEMU-ANDROID-LINUX: PASS pid=1 machine=aarch64 release=5.15.211' \
  --reject 'QEMU-CONFIGFS: FAIL' --reject 'QEMU-ANDROID-LINUX: FAIL' \
  --reject 'Synchronous Exception' --reject 'Kernel panic' > "$OUT/run.log" 2>&1; then RESULT=0; else RESULT=$?; fi
cat "$OUT/run.log"
exit "$RESULT"
