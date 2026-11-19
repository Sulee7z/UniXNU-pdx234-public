#!/usr/bin/env python3
"""Read-only verify the user's independently flashed probe and retained Android payload."""
import hashlib
import importlib.util
import json
from pathlib import Path

DEVICE = Path(__file__).resolve().parents[1]
PROJECT = DEVICE.parents[1]


def main():
    spec = importlib.util.spec_from_file_location('capture', DEVICE/'scripts/collect-boot-readonly.py')
    capture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(capture)
    slot = capture.text('getprop ro.boot.slot_suffix')
    if slot != '_a' or capture.text('getprop sys.boot_completed') != '1':
        raise RuntimeError('Unexpected active slot or Android not ready')
    output = PROJECT/'evidence/Xperia-XQ-DQ72/post-user-flash-001'
    output.mkdir()
    source = '/dev/block/by-name/boot_a'
    size = int(capture.text('blockdev --getsize64 '+source))
    before = capture.text('sha256sum '+source).split()[0]
    actual = capture.stream_capture('dd if='+source+' bs=1048576 2>/dev/null', output/'boot.img', size)
    after = capture.text('sha256sum '+source).split()[0]
    if before != actual or actual != after:
        raise RuntimeError('User-flashed boot readback hashes differ')
    data = (output/'boot.img').read_bytes()
    probe = (DEVICE/'out/combo-probe-001/boot-pdx234-combo-RAM-PROBE.img').read_bytes()
    original = (DEVICE/'out/combo-probe-001/Android.original.Image').read_bytes()
    prefix_match = data[:len(probe)] == probe
    retained = data[4096+(2<<20):4096+(2<<20)+len(original)] == original
    record = dict(serial='PDX_DEVICE_SERIAL', slot='a', user_report='User independently flashed; reboot entered Android',
                  device_boot_partition_sha256=actual, captured_bytes=size, probe_prefix_matches=prefix_match,
                  original_android_payload_unchanged=retained, original_kernel_sha256=hashlib.sha256(original).hexdigest(),
                  current_proc_version=capture.text('cat /proc/version'), boot_completed=True,
                  flash_performed_by_agent=False, reads_only=True, menu_verified=False,
                  ram_boot_supported_user_report=False)
    (output/'readback.json').write_text(json.dumps(record,indent=2))
    (DEVICE/'evidence/user-flash-001-readback.json').write_text(json.dumps(record,indent=2))
    print(json.dumps(record,indent=2))


if __name__ == '__main__':
    main()
