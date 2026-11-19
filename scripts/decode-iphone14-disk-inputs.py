#!/usr/bin/env python3
"""Convert verified target DMGs to raw guest disks using the official UDIF decoder."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

MAIN = Path('/mnt/g/UniXNU-Port/sources/UniXNU-main-20261109')

BLOCK = 8 << 20


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--mainline', type=Path, default=MAIN)
    args = parser.parse_args()
    sys.path.insert(0, str(args.mainline.resolve() / 'scripts'))
    from unixnu.udif import Image
    args.out.mkdir()
    inputs = json.loads(args.inputs.read_text())
    if inputs['product'] != 'iPhone14,7' or inputs['build'] != '24A446':
        raise RuntimeError('Wrong target disk inputs')
    report = dict(product=inputs['product'], build=inputs['build'], disks=[], device_operations=False)
    for entry in inputs['inputs']:
        path = Path(entry['decoded']['path'])
        if path.stat().st_size != entry['decoded']['bytes']:
            raise RuntimeError('Input size changed')
        with path.open('rb') as source:
            if hashlib.file_digest(source, 'sha256').hexdigest() != entry['decoded']['sha256']:
                raise RuntimeError('Decrypted input hash changed')
        image = Image(path)
        name = entry['component'].replace(',', '-')
        output = args.out / (name + '.raw')
        if image.chunks is None:
            # A verified raw cryptex is already the correct guest disk; don't duplicate it.
            output = path
            digest = entry['decoded']['sha256']
        else:
            if min(shutil.disk_usage(args.out).free, shutil.disk_usage('/mnt/g').free) < image.size + (2 << 30):
                raise RuntimeError('Insufficient raw-disk capacity')
            temporary = output.with_suffix('.partial')
            done, sha = 0, hashlib.sha256()
            with temporary.open('xb') as target:
                for data in image.blocks():
                    sha.update(data)
                    if not any(data):
                        target.seek(len(data), os.SEEK_CUR)
                    else:
                        target.write(data)
                    done += len(data)
                target.truncate(done)
            if done != image.size:
                raise RuntimeError('Raw disk output size differs')
            temporary.rename(output)
            digest = sha.hexdigest()
        report['disks'].append(dict(component=entry['component'], path=str(output),
                                    bytes=image.size, sha256=digest))
        (args.out / 'disks.json').write_text(json.dumps(report, indent=2))
        print(name, image.size, digest, flush=True)


if __name__ == '__main__':
    main()
