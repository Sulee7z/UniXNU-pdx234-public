#!/usr/bin/env bash
# Strict target fileset emission; no allow-missing or foreign iPad fixture.
set -euo pipefail
DEVICE=/mnt/g/UniXNU-Port/ports/UniXNU-pdx234
TREE=/root/unixnu-build/pdx234-qemu27-out/qemu27-iphone14/ios-27.0.1-24A446-iphone14/qemu27_native_probe/tree
OUT=$DEVICE/out/qemu27-prelink-${1:?fresh attempt required}
test ! -e "$OUT"
mkdir -p "$OUT"
NATIVE=$DEVICE/out/qemu27-native-004/native-chained-kernel.macho
ORIGINAL=$DEVICE/.cache/iphone14-ios27/ipsw/24A446/kernelcache.decompressed
REFERENCE=$TREE/build/xnu/fileset-reference/mach.release.bcm2837.unstripped.noctf
python3 - "$ORIGINAL" <<'PY'
from pathlib import Path
import hashlib,sys
p=Path(sys.argv[1])
assert hashlib.sha256(p.read_bytes()).hexdigest() == 'c28f4fc9b83cde00087e81f890c82d566b9e98b5ac228dfecd83afdf34070445'
PY
echo "Strict iPhone14 fileset prelink; log: $OUT/prelink.log"
if ! python3 -u -B "$DEVICE/.cache/firmware-components/XnuPrelink/emit_prelink.py" \
  --kernel "$NATIVE" --prelinked "$ORIGINAL" --fileset-reference "$REFERENCE" --slide=0 \
  --root com.apple.filesystems.apfs --root com.apple.driver.AppleMobileFileIntegrity \
  --root com.apple.security.AppleImage4 --root com.apple.kext.CoreTrust \
  --root com.apple.kec.corecrypto --root com.apple.iokit.IOStorageFamily \
  --root com.apple.AppleFSCompression.AppleFSCompressionTypeZlib \
  --output "$OUT/kernel.macho" > "$OUT/prelink.log" 2>&1; then
  tail -45 "$OUT/prelink.log"
  exit 1
fi
tail -12 "$OUT/prelink.log"
