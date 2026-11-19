#!/usr/bin/env python3
"""Offline gate: refuse changed Android boot inputs before future dual-boot packing."""
import hashlib
import json
from pathlib import Path
import struct

DEVICE = Path(__file__).resolve().parents[1]
PROJECT = DEVICE.parents[1]


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    identity = json.loads((DEVICE / 'evidence/android-preservation.json').read_text())
    captures = PROJECT / 'evidence/Xperia-XQ-DQ72/20261107T092807Z'
    manifest = json.loads((captures / 'manifest.json').read_text())
    if manifest['serial'] != identity['serial'] or manifest['slot'] != '_a':
        raise RuntimeError('Captured Android device/slot differs')
    for item in manifest['partitions']:
        name = item['label'].removesuffix('_a')
        path = captures / (name + '.img')
        if (path.stat().st_size != item['bytes'] or digest(path) != item['sha256'] or
                item['phone_before_sha256'] != item['sha256'] or
                item['phone_after_sha256'] != item['sha256']):
            raise RuntimeError('Android baseline changed: ' + name)
    boot = (captures / 'boot.img').read_bytes()
    if hashlib.sha256(boot).hexdigest() != identity['boot_partition']['sha256']:
        raise RuntimeError('Boot partition differs from the selected baseline')
    if boot[:8] != b'ANDROID!' or struct.unpack_from('<I', boot, 40)[0] != 4:
        raise RuntimeError('Unexpected Android v4 boot header')
    size = struct.unpack_from('<I', boot, 8)[0]
    kernel = boot[4096:4096 + size]
    if (size != identity['android_kernel_field']['bytes'] or
            hashlib.sha256(kernel).hexdigest() != identity['android_kernel_field']['sha256']):
        raise RuntimeError('Current Android kernel was replaced')
    pe = struct.unpack_from('<I', kernel, 60)[0]
    if (kernel[:2] != b'MZ' or kernel[56:60] != b'ARM\x64' or
            kernel[pe:pe+4] != b'PE\0\0' or struct.unpack_from('<H', kernel, pe+4)[0] != 0xaa64):
        raise RuntimeError('Android EFI-stub identity changed')
    print(json.dumps(dict(result='Android-baseline-unchanged', verified_partition_images=len(manifest['partitions']),
                          kernel_bytes=size, kernel_sha256=identity['android_kernel_field']['sha256'],
                          runtime_dual_boot_verified=False, device_operations=False), indent=2))


if __name__ == '__main__':
    main()
