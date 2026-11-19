#!/usr/bin/env python3
"""Capture Sony UEFI/bootloader inputs using read-only, hash-qualified ADB streams."""
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[2]
OUT = PROJECT / 'evidence/Xperia-XQ-DQ72/20261107T092807Z/firmware'


def main():
    spec = importlib.util.spec_from_file_location('capture', HERE / 'collect-boot-readonly.py')
    capture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(capture)
    if capture.text('getprop ro.product.device') != 'XQ-DQ72' or capture.text('getprop ro.boot.slot_suffix') != '_a':
        raise RuntimeError('Unexpected Sony device/slot')
    OUT.mkdir()
    result = dict(serial='PDX_DEVICE_SERIAL', slot='a', device_writes=False, firmware=[], complete=False)
    for name in ('uefi', 'imagefv', 'xbl', 'xbl_config', 'abl'):
        source = '/dev/block/by-name/' + name + '_a'
        size = int(capture.text('blockdev --getsize64 ' + source))
        if not 0 < size <= 32 << 20:
            raise RuntimeError('Unexpected firmware partition size')
        before = capture.text('sha256sum ' + source).split()[0]
        print(f'Capturing {name}_a ({size} bytes), no device writes', flush=True)
        digest = capture.stream_capture(f'dd if={source} bs=1048576 2>/dev/null', OUT / (name + '.img'), size)
        after = capture.text('sha256sum ' + source).split()[0]
        if digest != before or digest != after:
            raise RuntimeError('Firmware before/after and host hashes differ')
        result['firmware'].append(dict(name=name, source=source, bytes=size, sha256=digest,
                                       phone_before_sha256=before, phone_after_sha256=after))
        (OUT / 'manifest.json').write_text(json.dumps(result, indent=2))
    result['complete'] = True
    (OUT / 'manifest.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
