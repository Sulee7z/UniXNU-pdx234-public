#!/usr/bin/env python3
"""Enter the installed recovery once and inspect it; never repartition or format."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', required=True)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    adb = [args.adb, '-s', args.serial]
    if args.serial != 'PDX_DEVICE_SERIAL':
        parser.error('This inspection is scoped to the identified Sony')

    def read(command):
        return subprocess.run([*adb, 'exec-out', command], capture_output=True, timeout=60)

    if read('getprop ro.product.device').stdout.strip() != b'XQ-DQ72':
        raise RuntimeError('Unexpected device')
    args.out.mkdir(parents=True, exist_ok=False)
    record = {'serial': args.serial, 'reboot_recovery_authorized': True,
              'partition_writes': False, 'formatting': False, 'resize': False}
    misc = read('dd if=/dev/block/by-name/misc bs=4096 count=1 2>/dev/null')
    if misc.returncode or len(misc.stdout) != 4096:
        raise RuntimeError('Cannot check pending recovery commands')
    (args.out / 'misc-command.before.bin').write_bytes(misc.stdout)
    message = misc.stdout[:2048]
    if any(value in message for value in [b'--wipe', b'--update_package', b'--prompt_and_wipe_data', b'--sideload']):
        raise RuntimeError('Pending recovery operation found; do not reboot blindly')
    record['misc_command_sha256'] = hashlib.sha256(misc.stdout).hexdigest()
    (args.out / 'execution.json').write_text(json.dumps(record, indent=2) + '\n')
    reboot = subprocess.run([*adb, 'reboot', 'recovery'], capture_output=True, timeout=30)
    (args.out / 'reboot.log').write_bytes(reboot.stdout + reboot.stderr)
    reboot.check_returncode()
    record['reboot_command_completed'] = True
    try:
        ready = subprocess.run([*adb, 'wait-for-device'], capture_output=True, timeout=150)
        ready.check_returncode()
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as error:
        record['recovery_adb_available'] = False
        record['error'] = str(error)
        (args.out / 'execution.json').write_text(json.dumps(record, indent=2) + '\n')
        raise SystemExit('Recovery ADB unavailable; no further operation attempted')
    commands = {
        'identity.txt': 'id; getprop ro.product.device; getprop ro.bootmode; getprop sys.boot_completed; getprop ro.twrp.version; uname -a',
        'mounts.txt': 'cat /proc/mounts',
        'tools.txt': 'for n in sh dd blockdev sha256sum cmp sync umount make_f2fs fsck.f2fs resize.f2fs sgdisk; do command -v "$n"; done',
        'topology.txt': 'readlink -f /dev/block/by-name/userdata; readlink -f /dev/block/by-name/rddata; blockdev --getss /dev/block/sda; blockdev --getsize64 /dev/block/sda; ls -l /sys/class/block/sda96/holders; cat /sys/class/block/sda96/start /sys/class/block/sda96/size',
    }
    record['recovery_adb_available'] = True
    for name, command in commands.items():
        result = read(command)
        (args.out / name).write_bytes(result.stdout)
        (args.out / (name + '.stderr')).write_bytes(result.stderr)
        record.setdefault('read_exits', {})[name] = result.returncode
    record['root_in_recovery'] = read('id -u').stdout.strip() == b'0'
    record['android_boot_completed'] = read('getprop sys.boot_completed').stdout.strip() == b'1'
    (args.out / 'execution.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
