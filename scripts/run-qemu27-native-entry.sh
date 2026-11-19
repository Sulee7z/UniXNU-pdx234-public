#!/usr/bin/env bash
# Real native XNU entry test; this does not yet contain Apple kext/root/display closure.
set -euo pipefail
DEVICE=/mnt/g/UniXNU-Port/ports/UniXNU-pdx234
MAIN=/mnt/g/UniXNU-Port/references/xperia-mainline-20261107
WORK=/root/unixnu-build/pdx234-qemu-native-entry-${1:?fresh attempt label required}
FINAL=$DEVICE/out/qemu-native-entry-$1
OUT=$WORK/result
KERNEL=${2:-/root/unixnu-build/pdx234-qemu27-out/qemu27-iphone14/ios-27.0.1-24A446-iphone14/qemu27_native_probe/kernel/kernel.macho}
test ! -e "$WORK"
test ! -e "$FINAL"
test -f "$KERNEL"
python3 -B "$DEVICE/scripts/check-native-entry-format.py" "$KERNEL"
mkdir -p "$WORK/Conf" "$OUT/esp/EFI/BOOT" "$OUT/esp/EFI/UniXNU/Payloads" "$OUT/esp/EFI/UniXNU/Drivers"
rsync -rlt --exclude=.git "$DEVICE/.cache/firmware-components/DarwinBoot/" "$WORK/"
EDK=/root/unixnu-build/uefi-pdx234/Mu_Basecore
PACKAGE=/root/unixnu-build/pdx234-qemu-common-002/package
export WORKSPACE=$WORK PACKAGES_PATH="$WORK:$PACKAGE:$EDK" CONF_PATH=$WORK/Conf EDK_TOOLS_PATH=$EDK/BaseTools
export PATH="/root/unixnu-build/mu-venv/bin:$EDK/BaseTools/BinWrappers/PosixLike:$EDK/BaseTools/Source/C/bin:$PATH"
export CLANG_BIN=/usr/bin/ PYTHON_COMMAND=python3 TMPDIR=/root/unixnu-build
for NAME in target tools_def build_rule; do cp "$EDK/BaseTools/Conf/$NAME.template" "$WORK/Conf/$NAME.txt"; done
if ! build -p DarwinBootPkg/DarwinBoot.dsc -a AARCH64 -b DEBUG -t CLANGPDB -n4 > "$OUT/loader-build.log" 2>&1; then
  tail -60 "$OUT/loader-build.log"
  exit 1
fi
cp "$DEVICE/out/qemu-common-002/efi/AARCH64-DEBUG/UniXNU.efi" "$OUT/esp/EFI/BOOT/BOOTAA64.EFI"
cp "$WORK/build/DarwinBoot/DEBUG_CLANGPDB/AARCH64/DarwinBoot.efi" "$OUT/esp/EFI/UniXNU/Drivers/"
cp "$KERNEL" "$OUT/esp/EFI/UniXNU/Payloads/kernel.macho"
python3 -B "$MAIN/scripts/qemu-entry/make-dt.py" --armvirt --armcpu --nvram-proxy --qemu-vmm-present \
  --osenvironment main --crypto-hash-method sha2-384 --owned-memory-size 0x20000000 --dram-size 0x100000000 \
  --output "$OUT/esp/EFI/UniXNU/Payloads/kernel.macho.adt" > "$OUT/adt.log"
cat > "$OUT/esp/EFI/UniXNU/unixnu.toml" <<'CFG'
version = 1
[boot]
timeout = 1
default = "native"
[kits]
autoload = false
[[driver]]
path = "Drivers/DarwinBoot.efi"
[[entry]]
id = "native"
title = "Native arm64e XNU - not SpringBoard"
type = "xnu"
path = "Payloads/kernel.macho"
args = "-v serial=3 debug=0x14e cpus=1"
CFG
# The entry fixture must follow the same final-code POST seal as payload.py.
# Never disable POST to get past a checksum of an earlier kernel/probe copy.
UNIXNU_XNU_ARCH=arm64e UNIXNU_IOS_VERSION=27.0 python3 -B \
  /mnt/g/UniXNU-Port/references/pdx234-mainline-20261108/scripts/seal-source-crypto-kernel.py \
  "$OUT/esp/EFI/UniXNU/Payloads/kernel.macho" \
  --kernel-args '-v serial=3 debug=0x14e cpus=1' > "$OUT/crypto-seal.log" 2>&1
cp "$MAIN/package/Scripts/qemu-run.py" "$WORK/qemu-run.py"
git -C "$WORK" apply --check "$DEVICE/patches/host/qemu-run-cpu-option.patch"
git -C "$WORK" apply "$DEVICE/patches/host/qemu-run-cpu-option.patch"
git -C "$WORK" apply --unidiff-zero --check "$DEVICE/patches/host/qemu-run-kernel-options.patch"
git -C "$WORK" apply --unidiff-zero "$DEVICE/patches/host/qemu-run-kernel-options.patch"
if python3 "$WORK/qemu-run.py" "$OUT/esp" --cpu max,pauth=on --machine virt,gic-version=3 \
  --memory-mib 4096 --cpus 1 --timeout 90 --log "$OUT/guest.log" --screenshot "$OUT/menu.png" \
  --expect 'DARWINBOOT: inputs validated; exiting boot services' --expect 'Darwin Kernel Version' \
  --reject 'DARWINBOOT: boot refused' --reject ASSERT > "$OUT/run.log" 2>&1; then
  RESULT=0
else
  RESULT=$?
fi
cat "$OUT/run.log"
mkdir "$FINAL"
cp -a "$OUT/." "$FINAL/"
exit "$RESULT"
