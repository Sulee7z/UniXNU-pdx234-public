#!/usr/bin/env python3
"""Collect bounded, read-only PDX234 GPT/F2FS evidence; never resize or upload."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', required=True)
    parser.add_argument('--serial', default='PDX_DEVICE_SERIAL')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    adb = [args.adb, '-s', args.serial]
    captures = {}

    def capture(name, command, expected=None):
        done = subprocess.run([*adb, 'exec-out', command], capture_output=True, timeout=30)
        if done.returncode or expected is not None and len(done.stdout) != expected:
            raise RuntimeError(f'{name}: read failed or byte count differs: {done.stderr.decode(errors="replace")}')
        (args.out / name).write_bytes(done.stdout)
        captures[name] = dict(command=command, bytes=len(done.stdout),
                              sha256=hashlib.sha256(done.stdout).hexdigest())
        return done.stdout

    if capture('uid.txt', 'id -u').strip() != b'0':
        raise ValueError('Requires existing root ADB, without changing adbd state')
    raw = capture('userdata-path.txt', 'readlink -f /dev/block/by-name/userdata').decode().strip()
    if raw != '/dev/block/sda96':
        raise ValueError('PDX234 userdata identity changed')
    mounts = capture('mounts.txt', 'cat /proc/mounts').decode()
    rows = [line.split() for line in mounts.splitlines() if len(line.split()) > 2 and line.split()[1] == '/data']
    if len(rows) != 1 or rows[0][2] != 'f2fs' or not rows[0][0].startswith('/dev/block/dm-'):
        raise ValueError('Unexpected mounted /data filesystem or mapping')
    mapped = rows[0][0]
    sector = int(capture('sector.txt', 'blockdev --getss /dev/block/sda'))
    capacity = int(capture('disk-bytes.txt', 'blockdev --getsize64 /dev/block/sda'))
    if sector != 4096 or capacity != 255844155392:
        raise ValueError('Unexpected captured Sony disk geometry')
    device_sizes = {}
    for label, path in (('userdata', raw), ('mapped', mapped), ('metadata', '/dev/block/by-name/metadata')):
        device_sizes[label] = int(capture(label + '-bytes.txt', f'blockdev --getsize64 {path}'))
    capture('df.txt', 'df -k /data')
    capture('statfs.txt', 'stat -f /data')
    capture('mapper-topology.txt',
            f'cat /sys/block/{Path(mapped).name}/dm/name; ls /sys/block/{Path(mapped).name}/slaves; '
            f'ls /sys/block/{Path(mapped).name}/holders; ls /sys/class/block/sda96/holders; '
            'cat /sys/class/block/sda96/start /sys/class/block/sda96/size')
    capture('f2fs-sysfs.txt',
            f'for p in /sys/fs/f2fs/{Path(mapped).name} /sys/fs/f2fs/features; do '
            'echo "$p"; ls "$p"; done')
    capture('resize-symbols.txt',
            'cat /proc/kallsyms | grep -E " (f2fs_resize_fs|f2fs_ioc_resize_fs|free_segment_range)$" | '
            'while read address kind name; do echo "$kind $name"; done')
    capture('fstab.txt',
            'for p in /vendor/etc/fstab* /odm/etc/fstab* /system/etc/fstab* /first_stage_ramdisk/fstab*; '
            'do if [ -f "$p" ]; then echo "$p"; cat "$p"; fi; done')
    capture('recovery-state.txt', 'getprop ro.twrp.version; getprop sys.boot_completed; uname -r')
    capture('f2fs-superblocks.bin', f'dd if={mapped} bs=4096 count=2 2>/dev/null', 8192)
    # Full reserved GPT regions include undeclared entries/padding and protective MBR.
    primary = capture('gpt-primary-region.bin', 'dd if=/dev/block/sda bs=4096 count=6 2>/dev/null', 24576)
    backup = capture('gpt-backup-region.bin',
                     f'dd if=/dev/block/sda bs=4096 skip={capacity // sector - 5} count=5 2>/dev/null', 20480)
    capture('gpt-primary-region-after.bin', 'dd if=/dev/block/sda bs=4096 count=6 2>/dev/null', 24576)
    capture('gpt-backup-region-after.bin',
            f'dd if=/dev/block/sda bs=4096 skip={capacity // sector - 5} count=5 2>/dev/null', 20480)
    if ((args.out / 'gpt-primary-region-after.bin').read_bytes() != primary or
            (args.out / 'gpt-backup-region-after.bin').read_bytes() != backup):
        raise ValueError('GPT changed during read-only capture')
    report = dict(serial=args.serial, captured_utc=datetime.now(timezone.utc).isoformat(),
                  sector_bytes=sector, disk_bytes=capacity, userdata=raw, mapped=mapped,
                  device_bytes=device_sizes, captures=captures, device_writes=False,
                  resize_ioctl_issued=False, github_actions_invoked=False)
    (args.out / 'capture.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'captures'}, indent=2))


if __name__ == '__main__':
    main()
