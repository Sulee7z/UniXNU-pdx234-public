#!/usr/bin/env python3
"""Flash the reviewed Sony boot image to the active slot and read it back.

Only `boot_a` is written. The Android kernel inside the image is byte-identical
to the original, so the slot still boots Android by default. The unixnu root
objects are never touched here.
"""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adbroot as A

FASTBOOT = r'G:\UniXNU-Port\tools\platform-tools\fastboot.exe'
PARTITION = 'boot_a'
DEVICE_PART = '/dev/block/by-name/boot_a'


def fb(*args, timeout=1800):
    done = subprocess.run([FASTBOOT, *args], capture_output=True, timeout=timeout)
    out = (done.stdout + done.stderr).decode(errors='replace')
    print(f'fastboot {" ".join(args)} -> {out.strip()}', flush=True)
    return done.returncode, out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--execute', action='store_true')
    args = p.parse_args()
    if not args.execute:
        p.error('Use --execute only for the already authorized flash')

    image = args.image
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    size = image.stat().st_size
    result = dict(started_utc=datetime.now(timezone.utc).isoformat(), image=str(image),
                  image_bytes=size, image_sha256=digest, partition=PARTITION,
                  device_writes=True, unixnu_written=False, gpt_written=False,
                  android_userdata_written=False)
    args.out.mkdir(parents=True, exist_ok=True)

    def record():
        (args.out / 'execution.json').write_text(json.dumps(result, indent=2) + '\n')

    try:
        code, out = fb('devices')
        if 'fastboot' not in out:
            raise RuntimeError('device is not in fastboot')
        code, out = fb('getvar', 'current-slot')
        if 'current-slot: a' not in out:
            raise RuntimeError('unexpected active slot: ' + out)
        result['active_slot'] = 'a'
        record()

        code, out = fb('flash', PARTITION, str(image), timeout=3600)
        if code:
            raise RuntimeError('fastboot flash failed: ' + out)
        result['flash_succeeded'] = True
        record()

        # Read the written partition back from the device and compare the image bytes.
        code, out = fb('reboot', 'recovery')
        if code:
            raise RuntimeError('fastboot reboot recovery failed: ' + out)
        deadline = 240
        seen = False
        for _ in range(deadline // 5):
            state = subprocess.run([A.ADB, 'devices'], capture_output=True, timeout=60).stdout.decode(errors='replace')
            if 'PDX_DEVICE_SERIAL' in state and 'recovery' in state:
                seen = True
                break
            import time
            time.sleep(5)
        if not seen:
            raise RuntimeError('recovery did not come back after the flash')
        readback = A.binary(f'dd if={DEVICE_PART} bs=1048576 count={size} iflag=count_bytes status=none', size)
        actual = hashlib.sha256(readback).hexdigest()
        if actual != digest:
            raise ValueError('partition readback differs: ' + actual)
        result['readback_sha256'] = actual
        result['readback_bytes'] = len(readback)
        result['readback_matches_image'] = True
        result['completed_utc'] = datetime.now(timezone.utc).isoformat()
        record()
        print(json.dumps(result, indent=2), flush=True)
    except BaseException as error:
        result['error'] = repr(error)
        record()
        raise


if __name__ == '__main__':
    main()
