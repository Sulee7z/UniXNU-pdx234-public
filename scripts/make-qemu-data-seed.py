#!/usr/bin/env python3
"""Create a fresh guest-only APFS Data image, never reuse another device's Data."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import uuid

FORMATTER = Path('/root/unixnu-build/venus-apfs-tools/apfsprogs/mkapfs/mkapfs')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--gib', type=int, default=3, choices=range(3, 9))
    args = parser.parse_args()
    if not FORMATTER.is_file():
        raise RuntimeError('Host APFS formatter is missing')
    args.out.mkdir()
    image = args.out / 'Data.raw'
    container_uuid, volume_uuid = str(uuid.uuid4()).upper(), str(uuid.uuid4()).upper()
    with image.open('xb') as target:
        target.truncate(args.gib << 30)
    with (args.out / 'format.log').open('xb') as log:
        subprocess.run([str(FORMATTER), '-L', 'QEMU iPhone14 Data', '-U', container_uuid,
                        '-u', volume_uuid, str(image)], stdout=log, stderr=subprocess.STDOUT, check=True)
    with FORMATTER.open('rb') as source:
        formatter_sha = hashlib.file_digest(source, 'sha256').hexdigest()
    report = dict(path=str(image), bytes=image.stat().st_size, container_uuid=container_uuid,
                  volume_uuid=volume_uuid, formatter=str(FORMATTER), formatter_sha256=formatter_sha,
                  target='iPhone14,7 / iOS27 QEMU guest', reused_data=False,
                  populated=False, mounted_in_guest=False, device_operations=False)
    (args.out / 'seed.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
