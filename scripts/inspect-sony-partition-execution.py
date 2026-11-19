#!/usr/bin/env python3
"""Read tools, active mappings and recovery headers; never mutate the phone."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', required=True)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    command = [args.adb, '-s', args.serial, 'exec-out']

    def call(text):
        return subprocess.run([*command, text], capture_output=True, timeout=90)

    if call('id -u').stdout.strip() != b'0' or call('getprop ro.product.device').stdout.strip() != b'XQ-DQ72':
        raise RuntimeError('Need the existing identified root Sony connection')
    args.out.mkdir(parents=True, exist_ok=False)
    report = {'serial': args.serial, 'scope': 'Read-only inspection; no reboot, upload, mount, resize, erase or partition write',
              'captures': {}, 'recovery': {}}
    reads = {
        'identity.txt': 'id; getprop ro.product.device; getprop ro.bootmode; getprop sys.boot_completed; getprop ro.twrp.version; getprop ro.boot.slot_suffix; uname -a',
        'tools.txt': 'for n in sh dd blockdev sha256sum cmp sync umount sgdisk resize.f2fs mkfs.f2fs make_f2fs mke2fs dmctl busybox toybox; do command -v "$n"; done',
        'mounts.txt': 'cat /proc/mounts',
        'mapping.txt': 'for p in /sys/class/block/sda96/holders/*; do [ -e "$p" ] || continue; echo "$p"; cat "$p/dm/name" 2>/dev/null; done; dmctl status userdata',
        'recovery-partitions.txt': 'ls -l /dev/block/by-name/recovery_a /dev/block/by-name/recovery_b; blockdev --getsize64 /dev/block/by-name/recovery_a; blockdev --getsize64 /dev/block/by-name/recovery_b',
        'resize-capability.txt': 'grep -E " (f2fs_resize_fs|f2fs_ioc_resize_fs)$" /proc/kallsyms | while read address kind name; do echo "$kind $name"; done',
        'resize-help.txt': 'resize.f2fs -h',
    }
    for name, text in reads.items():
        result = call(text)
        (args.out / name).write_bytes(result.stdout)
        (args.out / (name + '.stderr')).write_bytes(result.stderr)
        report['captures'][name] = {'command': text, 'exit': result.returncode,
            'bytes': len(result.stdout), 'sha256': hashlib.sha256(result.stdout).hexdigest()}
    for label in ('recovery_a', 'recovery_b'):
        result = call(f'dd if=/dev/block/by-name/{label} bs=4096 count=1 2>/dev/null')
        if result.returncode or len(result.stdout) != 4096:
            raise RuntimeError('Recovery header read failed: ' + label)
        raw = result.stdout
        (args.out / (label + '.header.bin')).write_bytes(raw)
        info = {'header_sha256': hashlib.sha256(raw).hexdigest(), 'magic': raw[:8].hex()}
        if raw[:8] == b'ANDROID!':
            version = struct.unpack_from('<I', raw, 40)[0]
            kernel = struct.unpack_from('<I', raw, 8)[0]
            if version in (3, 4):
                page = 4096
                size = struct.unpack_from('<I', raw, 12)[0]
            elif version in (0, 1, 2):
                page = struct.unpack_from('<I', raw, 36)[0]
                size = struct.unpack_from('<I', raw, 16)[0]
            else:
                page, size = 0, 0
            info.update(header_version=version, kernel_bytes=kernel,
                        ramdisk_bytes=size, page_size=page)
            if page in (2048, 4096, 8192, 16384) and 0 < size <= 64 << 20:
                offset = page + ((kernel + page - 1) // page) * page
                if offset % 4096:
                    info['ramdisk_capture'] = 'unaligned extent; not read by this tool'
                else:
                    count = (size + 4095) // 4096
                    text = f'dd if=/dev/block/by-name/{label} bs=4096 skip={offset // 4096} count={count} 2>/dev/null'
                    data = call(text)
                    if data.returncode or len(data.stdout) != count * 4096:
                        raise RuntimeError('Recovery ramdisk read failed: ' + label)
                    data = data.stdout[:size]
                    (args.out / (label + '.ramdisk.bin')).write_bytes(data)
                    info.update(ramdisk_offset=offset, ramdisk_sha256=hashlib.sha256(data).hexdigest())
        report['recovery'][label] = info
    report['completed'] = True
    (args.out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report['recovery'], indent=2))


if __name__ == '__main__':
    main()
