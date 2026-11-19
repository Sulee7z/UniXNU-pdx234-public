#!/usr/bin/env python3
"""Capture current recovery identity and repeated GPT bytes. No device writes."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb', required=True)
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args()
    adb = [args.adb, '-s', 'PDX_DEVICE_SERIAL']
    captures = {}

    def read(command, binary=False):
        # Windows adb shell changes stdout LF to CRLF even without a PTY.
        mode = ['exec-out'] if binary else ['shell', '-T']
        raw = subprocess.run([*adb, *mode, command], check=True,
                             capture_output=True, timeout=45).stdout
        return raw if binary else raw.replace(b'\r\n', b'\n')

    if subprocess.check_output([*adb, 'get-state'], timeout=15).strip() != b'recovery':
        raise ValueError('Not recovery')
    if read('id -u').strip() != b'0' or read('getprop ro.product.device').strip() != b'XQ-DQ72':
        raise ValueError('Unexpected identity or privileges')
    if read('getprop sys.boot_completed').strip() == b'1':
        raise ValueError('Android running')
    args.out.mkdir(parents=True, exist_ok=False)

    def capture(name, command, size=None):
        raw = read(command, binary=size is not None)
        if size is not None and len(raw) != size:
            raise ValueError('Unexpected length: ' + name)
        (args.out / name).write_bytes(raw)
        captures[name] = dict(command=command, bytes=len(raw),
                              sha256=hashlib.sha256(raw).hexdigest())
        return raw

    capture('identity.txt', 'id; getprop ro.serialno; getprop ro.boot.serialno; getprop ro.product.device; uname -r; cat /proc/sys/kernel/random/boot_id')
    mounts = capture('mountinfo.txt', 'cat /proc/self/mountinfo').decode()
    for line in mounts.splitlines():
        fields = line.split()
        if len(fields) > 4 and (fields[4] in ('/data', '/metadata') or fields[2] in ('8:96', '8:52')):
            raise ValueError('Data/metadata still mounted')
    for label, expected in [('userdata', '/dev/block/sda96'), ('rddata', '/dev/block/sda97'), ('metadata', '/dev/block/sda52')]:
        if capture(label + '-path.txt', 'readlink -f /dev/block/by-name/' + label).decode().strip() != expected:
            raise ValueError('Changed mapping: ' + label)
    holders = capture('holders.txt', 'find /sys/class/block/sda96/holders /sys/class/block/sda52/holders -mindepth 1 -maxdepth 1').strip()
    if holders:
        raise ValueError('Active holders')
    sector = int(capture('sector.txt', 'blockdev --getss /dev/block/sda'))
    capacity = int(capture('disk-bytes.txt', 'blockdev --getsize64 /dev/block/sda'))
    if (sector, capacity) != (4096, 255844155392):
        raise ValueError('Unexpected geometry')
    capture('topology.txt', 'cat /sys/class/block/sda96/start /sys/class/block/sda96/size /sys/class/block/sda97/start /sys/class/block/sda97/size; cat /proc/partitions')
    for suffix in ('', '-after'):
        capture('gpt-primary-region' + suffix + '.bin', 'dd if=/dev/block/sda bs=4096 count=6 2>/dev/null', 24576)
        capture('gpt-backup-region' + suffix + '.bin', 'dd if=/dev/block/sda bs=4096 skip=62461947 count=5 2>/dev/null', 20480)
    for side in ('primary', 'backup'):
        if (args.out / f'gpt-{side}-region.bin').read_bytes() != (args.out / f'gpt-{side}-region-after.bin').read_bytes():
            raise ValueError('GPT changed during capture')
    report = dict(serial='PDX_DEVICE_SERIAL', captured_utc=datetime.now(timezone.utc).isoformat(),
                  sector_bytes=sector, disk_bytes=capacity, captures=captures,
                  environment='root recovery', device_writes=False)
    (args.out / 'capture.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
