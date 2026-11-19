#!/usr/bin/env python3
"""Create an isolated iPhone14 arm64e virtual-platform native-kernel build context."""
import json
from pathlib import Path
import shutil
import subprocess

DEVICE = Path('/mnt/g/UniXNU-Port/ports/UniXNU-pdx234')
SOURCE = Path('/mnt/g/UniXNU-Port/references/xperia-mainline-20261107')
BOARD = Path('/root/unixnu-build/pdx234-qemu27-device')
MAIN = Path('/root/unixnu-build/pdx234-qemu27-mainline')


def main() -> None:
    if BOARD.exists() or MAIN.exists():
        raise RuntimeError('Preserve the existing virtual build contexts')
    BOARD.mkdir()
    (BOARD / 'configs').mkdir()
    shutil.copyfile(DEVICE / 'configs/qemu27_native_probe_defconfig', BOARD / 'configs/qemu27_native_probe_defconfig')
    shutil.copytree(DEVICE / 'profiles/qemu-virt', BOARD / 'soc')
    shutil.copytree(SOURCE, MAIN, ignore=shutil.ignore_patterns('.git', 'out', 'build', 'Build', '.cache', '__pycache__'))
    target = MAIN / 'profiles/os/ios-27.0.1-24A446-iphone14'
    shutil.copytree(DEVICE / 'profiles/ios-27.0.1-24A446-iphone14', target, dirs_exist_ok=True)
    # The shared OS diagnostics include one Sheng-only PMGR context hunk.
    # QEMU has no such block; preserve every generic diagnostic hunk instead
    # of importing an unrelated Qualcomm board call just to satisfy context.
    progress = MAIN / 'patches/xnu-12377/zzz-boot-progress.patch'
    lines = progress.read_text().splitlines(keepends=True)
    ranges = []
    for index, line in enumerate(lines):
        if line.startswith('@@'):
            end = next((j for j in range(index + 1, len(lines))
                        if lines[j].startswith(('@@', 'diff --git'))), len(lines))
            if 'XNU_SHENG_PMGR' in ''.join(lines[index:end]):
                ranges.append((index, end))
    if len(ranges) != 1:
        raise RuntimeError('Expected one board-only diagnostic hunk')
    start, end = ranges[0]
    progress.write_text(''.join(lines[:start] + lines[end:]))
    # The official fetch step operates on the checkout's submodule metadata.
    subprocess.run(['git', '-C', str(MAIN), 'init', '--initial-branch=qemu27'], check=True)
    subprocess.run(['git', '-C', str(MAIN), 'add', '.'], check=True)
    subprocess.run(['git', '-C', str(MAIN), '-c', 'user.name=OpenCode', '-c',
                    'user.email=opencode@localhost', 'commit', '-m',
                    'QEMU27 native context from pinned UniXNU and iPhone14 inputs'], check=True)
    (BOARD / 'board.toml').write_text('''schema_version = 2
[board]
name = "qemu27-iphone14"
soc = "QEMU-virt"
soc_source = "qemu-virt"
os_profile = "ios-27.0.1-24A446-iphone14"
kit = "qemu27-iphone14"
example = false
description = "Native kernel compile context only; not an iOS deployment or handset image"
[components]
include = ["ArmVirtPlatform", "ArmCpu", "DarwinBoot", "XnuPrelink"]
[kernel]
defconfig = "qemu27_native_probe_defconfig"
config_fragments = ["arch:configs/common.config", "os:configs/ios.config"]
patch_series = ["arch:patches/xnu/series", "os:patches/xnu/series"]
archives = ["prepare-xnu-source.py", "build-corecrypto-14.py", "build-corecrypto-14.py --namespace", "component:ArmVirtPlatform", "component:ArmCpu", "build-libpthread-kernel.py"]
''')
    (BOARD / 'feeds.toml').write_text('''[[source]]
name = "qemu-virt"
kind = "soc"
local = "soc"
''')
    (BOARD / 'BUILD-ONLY.json').write_text(json.dumps(dict(
        purpose='native QEMU virt arm64e/iOS27 kernel compiler qualification',
        handset_board_or_android_modified=False, storage_and_display_ready=False,
        allowed_pipeline='defconfig/fetch/build kernel --skip-prelink',
        device_operations=False), indent=2))
    print(BOARD)
    print(MAIN)


if __name__ == '__main__':
    main()
