#!/usr/bin/env bash
# Build the Sony-owned firmware platform against the declared Mu and catalog pins.
set -euo pipefail
BASE=/mnt/g/UniXNU-Port
UEFI=${PDX_UEFI_WORK:-/root/unixnu-build/uefi-pdx234}
SOURCE=$BASE/ports/uefi-pdx234
DEVICE=$BASE/ports/UniXNU-pdx234
MAINLINE=$BASE/references/xperia-mainline-20261107
OUT=$DEVICE/out/firmware-${1:?provide a new attempt name}
EDK=$UEFI/Mu_Basecore
test ! -e "$OUT"
mkdir -p "$OUT"
rsync -rlt "$SOURCE/Platforms/Sony/" "$UEFI/Platforms/Sony/"
cp "$SOURCE/Silicon/Silicium/SiliciumPkg/Sec/Sec.c" "$UEFI/Silicon/Silicium/SiliciumPkg/Sec/Sec.c"
cp "$SOURCE/Silicon/Silicium/SiliciumPkg/Sec/AArch64/ModuleEntryPoint.S" "$UEFI/Silicon/Silicium/SiliciumPkg/Sec/AArch64/ModuleEntryPoint.S"
cp "$SOURCE/Resources/Configs/pdx234.toml" "$UEFI/Resources/Configs/pdx234.toml"
PACKAGE_BUILD=${PDX_PACKAGE_WORK:-/root/unixnu-build/pdx234-unixnu-package}
DARWIN_BUILD=${PDX_DARWIN_WORK:-/root/unixnu-build/pdx234-DarwinBoot}
mkdir -p "$PACKAGE_BUILD" "$DARWIN_BUILD"
rsync -rlt "$MAINLINE/package/" "$PACKAGE_BUILD/"
rsync -rlt --exclude=.git "$DEVICE/.cache/firmware-components/DarwinBoot/" "$DARWIN_BUILD/"
# Apply the reviewed component fix only to the disposable Linux build copy.
# Keep the canonical catalog checkout untouched and make repeated builds deterministic.
DARWIN_SOURCE=$DEVICE/.cache/firmware-components/DarwinBoot
test "$(git -C "$DARWIN_SOURCE" rev-parse HEAD)" = 3c75734014cdab0acd9541e88057b7606ee7ae08
# The Windows checkout uses CRLF; compare with its Git normalization, then export LF.
git -c core.autocrlf=true -C "$DARWIN_SOURCE" diff --exit-code HEAD -- DarwinBootPkg/Driver/DarwinBoot.c > "$OUT/darwinboot-source-check.log"
git -C "$DARWIN_SOURCE" show HEAD:DarwinBootPkg/Driver/DarwinBoot.c > "$DARWIN_BUILD/DarwinBootPkg/Driver/DarwinBoot.c"
git -C "$DARWIN_BUILD" apply --check "$DEVICE/patches/firmware/darwinboot-dxe-log.patch"
git -C "$DARWIN_BUILD" apply "$DEVICE/patches/firmware/darwinboot-dxe-log.patch"
git -C "$DARWIN_BUILD" apply --check "$DEVICE/patches/firmware/darwinboot-sony-entry-bank.patch"
git -C "$DARWIN_BUILD" apply "$DEVICE/patches/firmware/darwinboot-sony-entry-bank.patch"
cp "$DARWIN_BUILD/DarwinBootPkg/Driver/DarwinBoot.c" "$OUT/DarwinBoot.patched.c"
cp "$DEVICE/patches/firmware/darwinboot-dxe-log.patch" "$OUT/"
cp "$DEVICE/patches/firmware/darwinboot-sony-entry-bank.patch" "$OUT/"
export WORKSPACE=$UEFI EDK_TOOLS_PATH=$EDK/BaseTools CONF_PATH=$UEFI/Conf
export PACKAGES_PATH="$UEFI:$UEFI/Platforms/Sony:$UEFI/Platforms/Xiaomi:$UEFI/Common/Mu:$UEFI/Common/Mu_OEM_Sample:$EDK:$UEFI/Silicon/Qualcomm:$UEFI/Silicon/Silicium:$UEFI/Silicium-ACPI:$UEFI/Silicium-ACPI/Silicon/Qualcomm:$PACKAGE_BUILD:$DARWIN_BUILD"
export CLANG_BIN=/usr/bin/ PYTHON_COMMAND=python3
export PATH="/root/unixnu-build/mu-venv/bin:$EDK_TOOLS_PATH/BinWrappers/PosixLike:$EDK_TOOLS_PATH/Source/C/bin:$PATH"
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$SOURCE" log -1 --format=%ct)}
export TMPDIR=${PDX_TMPDIR:-$OUT/tmp}
mkdir -p "$TMPDIR"
export PYTHONDONTWRITEBYTECODE=1
mkdir -p "$CONF_PATH"
for name in target tools_def build_rule; do
  if [ ! -f "$CONF_PATH/$name.txt" ]; then cp "$EDK_TOOLS_PATH/Conf/$name.template" "$CONF_PATH/$name.txt"; fi
done
if [ ! -x "$EDK_TOOLS_PATH/Source/C/bin/GenFw" ]; then
  echo 'Building source BaseTools'
  if ! make -C "$EDK_TOOLS_PATH/Source/C" -j8 > "$OUT/basetools.log" 2>&1; then tail -60 "$OUT/basetools.log"; exit 1; fi
fi
echo "Building Sony pdx234 firmware; full log: $OUT/build.log"
cd "$UEFI"
if ! build -p Platforms/Sony/pdx234Pkg/pdx234.dsc -a AARCH64 -b DEBUG -t CLANGPDB -n8 \
  -D FD_BASE=0xA7100000 -D FD_SIZE=0x300000 -D FD_BLOCKS=768 \
  -D ENABLE_SECUREBOOT=0 -D MEMORY_PROTECTION=TRUE -D SHIP_MODE=FALSE \
  -D DEVICE_MODEL=pdx234 -D BUILDID_STRING=pdx234-research \
  -y "$OUT/build-report.txt" -Y PCD -Y LIBRARY -Y BUILD_FLAGS -Y FLASH > "$OUT/build.log" 2>&1; then
  tail -80 "$OUT/build.log"
  exit 1
fi
cp "$UEFI/Build/pdx234Pkg/DEBUG_CLANGPDB/FV/SILICIUM_UEFI.fd" "$OUT/"
for name in UniXNU UniXNUDxe DarwinBoot Sec DxeCore BdsDxe CapsuleRuntimeDxe VariableRuntimeDxe; do
  cp "$UEFI/Build/pdx234Pkg/DEBUG_CLANGPDB/AARCH64/$name.efi" "$OUT/"
done
# Retain the uncompressed FV and module map for service/DEPEX regression checks.
for name in FVMAIN.Fv FVMAIN.Fv.map Guid.xref; do
  cp "$UEFI/Build/pdx234Pkg/DEBUG_CLANGPDB/FV/$name" "$OUT/"
done
python3 "$DEVICE/scripts/check-firmware-services.py" "$OUT/SILICIUM_UEFI.fd" --report "$OUT/service-check.json"
sha256sum "$OUT/SILICIUM_UEFI.fd"
echo 'Sony firmware compiled; hardware execution not yet tested'
