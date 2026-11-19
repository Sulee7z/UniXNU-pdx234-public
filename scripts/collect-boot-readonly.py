#!/usr/bin/env python3
"""Capture active Xperia boot inputs with read-only dd and binary-safe ADB."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

PROJECT = Path(__file__).resolve().parents[3]
ADB = PROJECT / 'tools/platform-tools/adb.exe'
SERIAL = 'PDX_DEVICE_SERIAL'
OUT = PROJECT / 'evidence/Xperia-XQ-DQ72' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')


def text(command):
    result = subprocess.run([str(ADB), '-P', '5037', '-s', SERIAL, 'shell', command],
                            capture_output=True, timeout=60, check=True)
    return result.stdout.decode('utf-8', 'replace').strip()


def stream_capture(command, path, size):
    partial = path.with_suffix(path.suffix + '.partial')
    digest = hashlib.sha256()
    with partial.open('xb') as target:
        process = subprocess.Popen([str(ADB), '-P', '5037', '-s', SERIAL, 'exec-out', command],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            count = 0
            while True:
                data = process.stdout.read(1 << 20)
                if not data:
                    break
                count += len(data)
                if count > size:
                    raise RuntimeError('ADB stream exceeds declared input size')
                target.write(data)
                digest.update(data)
            error = process.stderr.read().decode('utf-8', 'replace')
            code = process.wait(timeout=30)
            if code or error.strip() or count != size:
                raise RuntimeError(f'Binary capture refused: exit={code}, bytes={count}/{size}, stderr={error}')
            target.flush()
            os.fsync(target.fileno())
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    partial.rename(path)
    return digest.hexdigest()


def main():
    if text('getprop ro.product.device') != 'XQ-DQ72' or text('getprop sys.boot_completed') != '1':
        raise RuntimeError('Unexpected device or Android not booted')
    if 'uid=0(' not in text('id'):
        raise RuntimeError('Read-only extraction requires the existing root ADB session')
    slot = text('getprop ro.boot.slot_suffix')
    if slot not in ('_a', '_b'):
        raise RuntimeError('Invalid current boot slot')
    OUT.mkdir(parents=True)
    record = dict(serial=SERIAL, slot=slot, device_operations='read-only; no reboot/flash/device file writes',
                  reference_sources_not_running_kernel=True, current_kernel_must_be_preserved=True,
                  partitions=[], captured_at=datetime.now(timezone.utc).isoformat())
    properties = ('ro.product.model', 'ro.product.device', 'ro.soc.model', 'ro.soc.manufacturer',
                  'ro.build.fingerprint', 'ro.boot.verifiedbootstate', 'ro.boot.flash.locked',
                  'ro.boot.vbmeta.device_state', 'ro.boot.bootloader', 'ro.boot.hardware',
                  'ro.boot.slot_suffix', 'sys.boot_completed')
    record['properties'] = {name: text('getprop ' + name) for name in properties}

    def save():
        with (OUT / 'manifest.json').open('w', encoding='utf-8') as target:
            json.dump(record, target, indent=2, ensure_ascii=False)
            target.write('\n')

    save()
    reads = {
        'uname.txt': 'uname -a', 'version.txt': 'cat /proc/version',
        'cmdline.txt': 'cat /proc/cmdline', 'bootconfig.txt': 'cat /proc/bootconfig',
        'partitions.txt': 'cat /proc/partitions', 'mounts.txt': 'cat /proc/mounts',
        'meminfo.txt': 'cat /proc/meminfo', 'iomem.txt': 'cat /proc/iomem',
        'by-name.txt': 'ls -l /dev/block/by-name',
        'board-id.txt': 'cat /sys/devices/soc0/soc_id /sys/devices/soc0/machine /sys/devices/soc0/family',
        'input-devices.txt': 'cat /proc/bus/input/devices',
        'cpu-topology.txt': 'cat /sys/devices/system/cpu/present /sys/devices/system/cpu/online',
    }
    for name, command in reads.items():
        try:
            (OUT / name).write_text(text(command) + '\n', encoding='utf-8')
        except subprocess.CalledProcessError as error:
            record.setdefault('unavailable_reads', []).append({'name': name, 'error': str(error)})
    for base in ('boot', 'init_boot', 'vendor_boot', 'dtbo', 'vbmeta', 'vbmeta_system', 'vbmeta_vendor'):
        label = base + slot
        path = '/dev/block/by-name/' + label
        if text(f'test -e {path} && echo yes || echo no') != 'yes':
            continue
        size = int(text(f'blockdev --getsize64 {path}'))
        if not 0 < size <= 256 << 20:
            raise RuntimeError(f'Unexpected partition size for {label}: {size}')
        before = text(f'sha256sum {path}').split()[0]
        resolved = text(f'readlink -f {path}')
        print(f'Read-only capture {label}: {size} bytes', flush=True)
        digest = stream_capture(f'dd if={path} bs=1048576 2>/dev/null', OUT / (base + '.img'), size)
        after = text(f'sha256sum {path}').split()[0]
        if not re.fullmatch('[a-f0-9]{64}', before) or before != digest or after != digest:
            raise RuntimeError(f'Phone/host hashes differ for {label}')
        record['partitions'].append(dict(label=label, path=path, resolved=resolved, bytes=size,
                                          sha256=digest, phone_before_sha256=before,
                                          phone_after_sha256=after, matched=True))
        save()
    fdt = '/sys/firmware/fdt'
    if text(f'test -f {fdt} && echo yes || echo no') == 'yes':
        size = int(text(f'wc -c < {fdt}'))
        if not 0 < size <= 16 << 20:
            raise RuntimeError('Unexpected live FDT size')
        before = text(f'sha256sum {fdt}').split()[0]
        digest = stream_capture(f'cat {fdt}', OUT / 'live.dtb', size)
        after = text(f'sha256sum {fdt}').split()[0]
        if before != digest or after != digest:
            raise RuntimeError('Live FDT hashes differ')
        record['live_fdt'] = dict(bytes=size, sha256=digest, source=fdt)
    record.update(result='active-boot-inputs-captured-and-hash-verified', output=str(OUT))
    save()
    print(json.dumps(record, ensure_ascii=False, indent=2), flush=True)


if __name__ == '__main__':
    main()
