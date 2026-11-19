#!/usr/bin/env python3
"""Export a build-only native probe context; it cannot be treated as the finished Sony port."""
import json
from pathlib import Path
import shutil

PROJECT = Path('/mnt/g/UniXNU-Port')
SOURCE = PROJECT / 'ports/UniXNU-pdx234'
OUT = Path('/root/unixnu-build/pdx234-native-probe-device')
MAIN = Path('/root/unixnu-build/pdx234-mainline')


def main():
    if OUT.exists() or MAIN.exists():
        raise RuntimeError('Preserve an existing native build context')
    OUT.mkdir()
    for name in ('configs', 'dts', 'patches'):
        shutil.copytree(SOURCE / name, OUT / name)
    for name in ('feeds.toml', 'AGENTS.md', 'porting.toml'):
        shutil.copyfile(SOURCE / name, OUT / name)
    board = (SOURCE / 'board.toml').read_text()
    # This separate context is for the official --skip-prelink native build only.
    # The canonical deployment board remains guarded. No firmware/root deployment is selected here.
    board = board.replace('example = true', 'example = false')
    board = board.replace('"SoftwareAES", ', '').replace(', "component:SoftwareAES"', '')
    (OUT / 'board.toml').write_text(board)
    shutil.copytree(PROJECT / 'references/xperia-mainline-20261107', MAIN,
                    ignore=shutil.ignore_patterns('.git', 'out', 'build', '.cache', '__pycache__'))
    (OUT / 'BUILD-ONLY.json').write_text(json.dumps(dict(purpose='native-only ELF/Mach-O entry probe',
        canonical_deployment_guard_unchanged=True, firmware_or_root_ready=False,
        allowed_pipeline='defconfig/fetch/build kernel --skip-prelink',
        device_operations=False), indent=2))
    print('Prepared native-only probe context; no deployment readiness asserted')


if __name__ == '__main__':
    main()
