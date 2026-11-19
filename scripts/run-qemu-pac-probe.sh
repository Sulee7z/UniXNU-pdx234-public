#!/usr/bin/env bash
# Execute a real EL1 PAC probe in QEMU; never claim it boots iOS or proves Sony PAC.
set -euo pipefail
DEVICE=/mnt/g/UniXNU-Port/ports/UniXNU-pdx234
MAINLINE=/mnt/g/UniXNU-Port/references/xperia-mainline-20261107
ATTEMPT=${1:?provide a fresh attempt label}
[[ "$ATTEMPT" =~ ^[A-Za-z0-9]+$ ]]
OUT=$DEVICE/out/qemu-pac-$ATTEMPT
WORK=/root/unixnu-build/pdx234-qemu-pac-$ATTEMPT
test ! -e "$OUT"
test ! -e "$WORK"
mkdir -p "$OUT/esp/EFI/BOOT" "$WORK/PacProbe" "$WORK/Conf"
rsync -rlt "$DEVICE/tests/qemu/PacProbe/" "$WORK/PacProbe/"
cp "$WORK/PacProbe/PacProbe.c" "$OUT/PacProbe.source.c"
EDK=/root/unixnu-build/uefi-pdx234/Mu_Basecore
export WORKSPACE=$WORK PACKAGES_PATH="$WORK:$EDK" EDK_TOOLS_PATH=$EDK/BaseTools CONF_PATH=$WORK/Conf
export PATH="/root/unixnu-build/mu-venv/bin:$EDK/BaseTools/BinWrappers/PosixLike:$EDK/BaseTools/Source/C/bin:$PATH"
export CLANG_BIN=/usr/bin/ PYTHON_COMMAND=python3 TMPDIR=/root/unixnu-build
for NAME in target tools_def build_rule; do
  cp "$EDK/BaseTools/Conf/$NAME.template" "$WORK/Conf/$NAME.txt"
done
echo "QEMU EL1 PAC probe; logs: $OUT"
if ! build -p PacProbe/PacProbe.dsc -a AARCH64 -b DEBUG -t CLANGPDB -n8 > "$OUT/build.log" 2>&1; then
  tail -70 "$OUT/build.log"
  exit 1
fi
cp "$WORK/Build/PdxQemuPacProbe/DEBUG_CLANGPDB/AARCH64/PacProbe.efi" "$OUT/esp/EFI/BOOT/BOOTAA64.EFI"
cp "$MAINLINE/package/Scripts/qemu-run.py" "$WORK/qemu-run.py"
git -C "$WORK" apply --check "$DEVICE/patches/host/qemu-run-cpu-option.patch"
git -C "$WORK" apply "$DEVICE/patches/host/qemu-run-cpu-option.patch"
if python3 "$WORK/qemu-run.py" "$OUT/esp" --cpu max,pauth=on --cpus 1 --timeout 40 \
  --finish-on-expect --menu-marker 'QEMU-PAC-PROBE: PASS' --screenshot "$OUT/pac.png" \
  --log "$OUT/guest.log" --expect 'QEMU-PAC-PROBE: PASS EL1 keys5 PACIA AUTIA' \
  --reject 'QEMU-PAC-PROBE: (FAIL|SKIP)' --reject ASSERT > "$OUT/run.log" 2>&1; then
  RESULT=0
else
  RESULT=$?
fi
cat "$OUT/run.log"
exit "$RESULT"
