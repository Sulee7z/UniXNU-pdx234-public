#!/usr/bin/env python3
"""Stage the unchanged Sony GKI and a minimal real PID1 for official Linux-path QEMU."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import stat
import subprocess

DEVICE = Path(__file__).resolve().parents[1]
PROJECT = DEVICE.parents[1]
KERNEL_SHA = '92321cba44b4d5f32355e694ed918125b8e56810ff2580b7a904cef0f719549f'


def cpio_entry(name, data=b'', mode=stat.S_IFREG | 0o755, major=0, minor=0):
    encoded = name.encode('ascii') + b'\0'
    fields = [1, mode, 0, 0, 1, 0, len(data), 0, 0, major, minor, len(encoded), 0]
    header = b'070701' + b''.join(f'{field:08x}'.encode('ascii') for field in fields)
    prefix = header + encoded
    return prefix + bytes(-len(prefix) % 4) + data + bytes(-len(data) % 4)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--minimal-peripherals', action='store_true', help='Disable unused virtual AMBA GPIO/RTC nodes in this fixture only')
    args = parser.parse_args()
    args.out.mkdir()
    args.work.mkdir()
    esp = args.out / 'esp'
    boot = esp / 'EFI/BOOT'
    android = esp / 'EFI/UniXNU/Android'
    boot.mkdir(parents=True)
    android.mkdir(parents=True)
    kernel = PROJECT / 'diagnostics/xperia-boot-audit-20261107/current-android-kernel.bin'
    raw = kernel.read_bytes()
    if hashlib.sha256(raw).hexdigest() != KERNEL_SHA:
        raise RuntimeError('Captured current Android kernel changed')
    shutil.copyfile(kernel, android / 'Image')
    unixnu = DEVICE / 'out/qemu-common-002/efi/AARCH64-DEBUG/UniXNU.efi'
    shutil.copyfile(unixnu, boot / 'BOOTAA64.EFI')
    init = args.work / 'init'
    subprocess.run(['clang', '--target=aarch64-linux-gnu', '-static', '-nostdlib',
                    '-fuse-ld=lld', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
                    '-Wl,-e,_start', '-Os', str(DEVICE / 'tests/qemu/AndroidLinux/init.c'),
                    '-o', str(init)], check=True)
    archive = cpio_entry('dev', mode=stat.S_IFDIR | 0o755)
    archive += cpio_entry('dev/console', mode=stat.S_IFCHR | 0o600, major=5, minor=1)
    archive += cpio_entry('init', init.read_bytes()) + cpio_entry('TRAILER!!!', mode=0)
    (android / 'initrd.img').write_bytes(archive + bytes(-len(archive) % 512))
    subprocess.run(['qemu-system-aarch64', '-M', 'virt,dumpdtb=' + str(android / 'virt.dtb'),
                    '-cpu', 'max', '-m', '1024', '-smp', '1'], check=True)
    disabled = []
    if args.minimal_peripherals:
        disabled = ['/pl061@9030000', '/pl031@9010000', '/gpio-keys']
        for node in disabled:
            subprocess.run(['fdtput', '-t', 's', str(android / 'virt.dtb'), node, 'status', 'disabled'], check=True)
    (esp / 'EFI/UniXNU/unixnu.toml').write_text('''version = 1
[boot]
timeout = 0
default = "android"
[ui]
console = "text"
[[entry]]
id = "android"
title = "Original Sony GKI - real Linux PID1 fixture"
type = "linux"
path = "Android/Image"
dtb = "Android/virt.dtb"
initrd = "Android/initrd.img"
args = "console=ttyAMA0,115200 earlycon=pl011,0x09000000 loglevel=8 nokaslr rdinit=/init panic=-1"
''', encoding='ascii')
    manifest = {'kernel_sha256': KERNEL_SHA, 'kernel_is_original_captured_sony_gki': True,
                'unixnu_sha256': hashlib.sha256(unixnu.read_bytes()).hexdigest(),
                'initrd_sha256': hashlib.sha256((android / 'initrd.img').read_bytes()).hexdigest(),
                'disabled_fixture_nodes': disabled,
                'fixture': 'QEMU virt with generated DTB and own minimal Linux PID1, not Android userland',
                'device_operations': False}
    (args.out / 'inputs.json').write_text(json.dumps(manifest, indent=2), encoding='ascii')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
