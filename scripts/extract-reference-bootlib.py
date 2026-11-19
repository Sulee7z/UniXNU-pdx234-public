#!/usr/bin/env python3
"""Copy a bounded Sony reference bootloader source subset from the provided tar."""
import hashlib
import json
from pathlib import Path
import tarfile

DEVICE = Path(__file__).resolve().parents[1]
PROJECT = DEVICE.parents[1]
SOURCE = Path('G:/67.2.A.3.141.tar_.bz2')
OUT = PROJECT / 'references/xperia-bootlib-67.2.A.3.141'
NAMES = {'BootLinux.c', 'BootLinux.h', 'Bootconfig.c', 'LinuxLoader.c', 'LinuxLoaderLib.c',
         'UpdateDeviceTree.c', 'FastbootCmds.c', 'Board.c', 'Decompress.c', 'uefiplat.cfg'}


def main():
    OUT.mkdir()
    record = dict(reference_only=True, not_current_running_kernel_source=True, files=[])
    with tarfile.open(SOURCE, 'r|bz2') as archive:
        for item in archive:
            name = Path(item.name).name
            if name not in NAMES or not item.isfile() or item.size > 1 << 20:
                continue
            if ('QcomModulePkg/' not in item.name and
                    not item.name.endswith('QcomPkg/SocPkg/Kailua/Common/uefiplat.cfg')):
                continue
            raw = archive.extractfile(item).read()
            with (OUT / name).open('xb') as output:
                output.write(raw)
            record['files'].append(dict(name=name, source=item.name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
    (OUT / 'manifest.json').write_text(json.dumps(record, indent=2))
    print(json.dumps(record, indent=2), flush=True)


if __name__ == '__main__':
    main()
