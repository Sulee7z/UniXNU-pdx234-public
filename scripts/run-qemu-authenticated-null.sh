#!/usr/bin/env bash
set -euo pipefail
DEVICE=/mnt/g/UniXNU-Port/ports/UniXNU-pdx234
MAIN=/mnt/g/UniXNU-Port/references/xperia-mainline-20261107
WORK=/root/unixnu-build/pdx234-qemu-auth-null-${1:?fresh attempt label required}
OUT=$DEVICE/out/qemu-auth-null-$1
test ! -e "$WORK"
test ! -e "$OUT"
mkdir -p "$WORK/AuthNullProbe" "$WORK/Conf" "$OUT/esp/EFI/BOOT"
python3 -B "$DEVICE/scripts/build-auth-null-runtime-blob.py" \
  --compiler /root/unixnu-build/pdx234-pac-toolchain/llvm/bin/clang --out "$WORK/Fixture" > "$OUT/blob-build.log" 2>&1
rsync -rlt "$DEVICE/tests/qemu/AuthNullProbe/" "$WORK/AuthNullProbe/"
cp "$WORK/Fixture/Blob.S" "$WORK/Fixture/BlobOffsets.h" "$WORK/AuthNullProbe/"
python3 - "$DEVICE/tests/qemu/PacProbe/PacProbe.dsc" "$WORK/AuthNullProbe/AuthNullProbe.dsc" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text().replace('PdxQemuPacProbe', 'PdxQemuAuthNull')
text = text.replace('PacProbe/PacProbe.inf', 'AuthNullProbe/AuthNullProbe.inf')
Path(sys.argv[2]).write_text(text)
PY
EDK=/root/unixnu-build/uefi-pdx234/Mu_Basecore
export WORKSPACE=$WORK PACKAGES_PATH="$WORK:$EDK" CONF_PATH=$WORK/Conf EDK_TOOLS_PATH=$EDK/BaseTools
export PATH="/root/unixnu-build/mu-venv/bin:$EDK/BaseTools/BinWrappers/PosixLike:$EDK/BaseTools/Source/C/bin:$PATH"
export CLANG_BIN=/usr/bin/ PYTHON_COMMAND=python3 TMPDIR=/root/unixnu-build
for NAME in target tools_def build_rule; do cp "$EDK/BaseTools/Conf/$NAME.template" "$WORK/Conf/$NAME.txt"; done
if ! build -p AuthNullProbe/AuthNullProbe.dsc -a AARCH64 -b DEBUG -t CLANGPDB -n4 > "$OUT/build.log" 2>&1; then
  tail -65 "$OUT/build.log"
  exit 1
fi
cp "$WORK/Build/PdxQemuAuthNull/DEBUG_CLANGPDB/AARCH64/AuthNullProbe.efi" "$OUT/esp/EFI/BOOT/BOOTAA64.EFI"
cp "$MAIN/package/Scripts/qemu-run.py" "$WORK/qemu-run.py"
git -C "$WORK" apply --check "$DEVICE/patches/host/qemu-run-cpu-option.patch"
git -C "$WORK" apply "$DEVICE/patches/host/qemu-run-cpu-option.patch"
if python3 "$WORK/qemu-run.py" "$OUT/esp" --cpu max,pauth=on --cpus 1 --timeout 45 \
  --finish-on-expect --menu-marker QEMU-AUTH-NULL --screenshot "$OUT/guest.png" \
  --log "$OUT/guest.log" --expect 'QEMU-AUTH-NULL: PASS compiled signed-null store/load/copy/transitions' \
  --reject 'QEMU-AUTH-NULL: FAIL' --reject ASSERT > "$OUT/run.log" 2>&1; then
  RESULT=0
else
  RESULT=$?
fi
cp "$WORK/Fixture/blob.json" "$OUT/"
cat "$OUT/run.log"
exit "$RESULT"
