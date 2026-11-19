#!/usr/bin/env python3
"""Read live Sony driver/DT inventory without probing registers or writing devices."""
import argparse
from datetime import datetime, timezone
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
    adb = [args.adb, '-s', args.serial, 'exec-out']

    def execute(command):
        return subprocess.run([*adb, command], capture_output=True, timeout=60)

    result = execute('id -u')
    if result.returncode or result.stdout.strip() != b'0':
        raise RuntimeError('Use the existing root session; do not restart adbd')
    result = execute('getprop ro.product.device')
    if result.stdout.strip() != b'XQ-DQ72':
        raise RuntimeError('Unexpected phone; preserve target scope')
    args.out.mkdir(parents=True, exist_ok=False)
    report = {'serial': args.serial, 'captured_at': datetime.now(timezone.utc).isoformat(),
              'scope': 'Read-only DT/sysfs/log inventory; no MMIO probes, writes, flashing or reboot',
              'captures': {}}
    reads = {
        'identity.txt': 'id; uname -a; cat /proc/version; getprop ro.product.device; getprop ro.product.model; getprop ro.soc.model; getprop ro.boot.slot_suffix; getprop sys.boot_completed; cat /sys/devices/soc0/machine /sys/devices/soc0/soc_id /sys/devices/soc0/revision',
        'bootconfig.txt': 'cat /proc/bootconfig',
        'cmdline.txt': 'cat /proc/cmdline',
        'input-devices.txt': 'cat /proc/bus/input/devices',
        'interrupts.txt': 'cat /proc/interrupts',
        'gpio-debug.txt': 'cat /sys/kernel/debug/gpio',
        'touch-sysfs.txt': 'for p in /sys/bus/i2c/devices/2-0028 /sys/bus/i2c/drivers/lxs_ts /sys/class/input/event4/device; do [ -e "$p" ] || continue; echo "$p"; readlink -f "$p/driver"; readlink -f "$p/of_node"; find "$p" -maxdepth 2 -type f -print 2>/dev/null; for f in "$p"/irq "$p"/modalias "$p"/name "$p"/power/runtime_status "$p"/power/control; do [ -r "$f" ] && { echo "$f"; cat "$f"; }; done; done',
        'getevent-props.txt': 'getevent -lp /dev/input/event4',
        'logcat.txt': 'logcat -d -t 1000',
        'kernel-modules.txt': 'cat /proc/modules',
        'dmesg.txt': 'dmesg',
        'audio.txt': 'cat /proc/asound/cards /proc/asound/pcm; ls -l /sys/class/sound; for p in /sys/bus/swr/devices/* /sys/bus/soundwire/devices/*; do [ -e "$p" ] || continue; echo "$p"; readlink -f "$p/driver"; cat "$p/name" "$p/modalias" "$p/uevent" 2>/dev/null; done',
        'display.txt': 'wm size; wm density; dumpsys SurfaceFlinger --display-id; for p in /sys/class/backlight/*; do [ -e "$p" ] || continue; echo "$p"; readlink -f "$p/device"; cat "$p/type" "$p/max_brightness" "$p/actual_brightness" "$p/uevent" 2>/dev/null; done; for p in /sys/class/drm/*; do [ -e "$p" ] || continue; echo "$p"; cat "$p/status" "$p/modes" 2>/dev/null; done',
        'i2c-spi-devices.txt': 'for p in /sys/bus/i2c/devices/* /sys/bus/spi/devices/*; do [ -e "$p" ] || continue; echo "$p"; readlink -f "$p/driver"; readlink -f "$p/of_node"; cat "$p/name" "$p/modalias" "$p/uevent" 2>/dev/null; done',
        'pci-radio.txt': 'for p in /sys/bus/pci/devices/* /sys/bus/sdio/devices/*; do [ -e "$p" ] || continue; echo "$p"; readlink -f "$p/driver"; readlink -f "$p/of_node"; cat "$p/vendor" "$p/device" "$p/subsystem_vendor" "$p/subsystem_device" "$p/class" "$p/modalias" 2>/dev/null; done',
        'platform-drivers.txt': 'for p in /sys/bus/platform/devices/*; do n=${p##*/}; case "$n" in *wlan*|*wifi*|*bluetooth*|*kgsl*|*gpu*|*display*|*dsi*|*mdss*|*adsp*|*audio*|*sound*|*codec*|*usb*|*dwc3*|*pmic*|*battery*|*charger*|*lxs*|*touch*|*swr*) echo "$p"; readlink -f "$p/driver"; readlink -f "$p/of_node"; cat "$p/modalias" "$p/uevent" 2>/dev/null;; esac; done',
        'power-usb.txt': 'for p in /sys/class/power_supply/*; do [ -e "$p" ] || continue; echo "$p"; readlink -f "$p/device"; cat "$p/type" "$p/model_name" "$p/manufacturer" "$p/technology" 2>/dev/null; done; for p in /sys/class/udc/*; do [ -e "$p" ] || continue; echo "$p"; readlink -f "$p/device"; cat "$p/state" "$p/current_speed" "$p/maximum_speed" 2>/dev/null; done',
        'firmware-paths.txt': 'find /vendor/firmware_mnt/image /vendor/firmware /odm/firmware -maxdepth 2 -type f -print 2>/dev/null',
        'vendor-module-paths.txt': 'find /vendor/lib/modules /odm/lib/modules /vendor_dlkm/lib/modules -maxdepth 2 -type f -print 2>/dev/null',
    }
    for name, command in reads.items():
        result = execute(command)
        if len(result.stdout) > 16 << 20:
            raise RuntimeError('Unexpected capture size: ' + name)
        (args.out / name).write_bytes(result.stdout)
        (args.out / (name + '.stderr')).write_bytes(result.stderr)
        report['captures'][name] = {'command': command, 'exit': result.returncode,
            'bytes': len(result.stdout), 'sha256': hashlib.sha256(result.stdout).hexdigest()}
        (args.out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
        print(name, len(result.stdout), 'exit', result.returncode, flush=True)
    before = execute('sha256sum /sys/firmware/fdt')
    data = execute('cat /sys/firmware/fdt')
    after = execute('sha256sum /sys/firmware/fdt')
    if not data.returncode and data.stdout[:4] == b'\xd0\x0d\xfe\xed' and len(data.stdout) <= 16 << 20:
        digest = hashlib.sha256(data.stdout).hexdigest()
        if before.stdout.split()[0].decode() != digest or after.stdout.split()[0].decode() != digest:
            raise RuntimeError('Live DT transfer hash changed')
        (args.out / 'live.dtb').write_bytes(data.stdout)
        report['captures']['live.dtb'] = {'command': 'cat /sys/firmware/fdt',
            'bytes': len(data.stdout), 'sha256': digest, 'phone_hash_before_after_matches': True}
    else:
        report['live_fdt_unavailable'] = True
    report['completed'] = True
    (args.out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print('Read-only inventory complete:', args.out)


if __name__ == '__main__':
    main()
