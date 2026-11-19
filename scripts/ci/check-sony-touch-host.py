#!/usr/bin/env python3
"""Exercise the actual Sony touch protocol, FIFO and HID report sources with sanitizers."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--firmware', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    driver = ROOT / 'drivers/SonyLxsTouch'
    sources = [ROOT / 'tests/sony_touch_host.c', *(driver / (name + '.c') for name in
               ('Sw82907', 'GeniI2c', 'HidTouchReport', 'GeniInit'))]
    command = ['clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
               '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-I', str(driver),
               '-I','/mnt/e/UniXNU-sheng27-sony-20261113/sources/sheng/package',
               *map(str, sources), '-o', str(args.out / 'sony-touch-host')]
    subprocess.run(command, check=True, timeout=60)
    firmware=args.firmware/'sony-geni-i2c.bin'
    if hashlib.sha256(firmware.read_bytes()).hexdigest()!='0840aa323be767f134050cf8ff365b9e4675063863a8a34adc18343b978224e4':
        raise ValueError('Sony OEM firmware identity changed')
    done = subprocess.run([str(args.out / 'sony-touch-host'),str(firmware)],
                          capture_output=True, text=True, timeout=30)
    (args.out/'run.log').write_text(done.stdout+done.stderr)
    if done.returncode:raise RuntimeError(done.stdout+done.stderr)
    files = [*sources, *(driver / name for name in ('Sw82907.h', 'GeniI2c.h', 'HidTouchReport.h','GeniInit.h')),
             Path('/mnt/e/UniXNU-sheng27-sony-20261113/sources/sheng/package/SmmuBypass.h')]
    record = {'passed': True, 'command': command, 'output': done.stdout,
              'sources': {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in files},
              'firmware_sha256':hashlib.sha256(firmware.read_bytes()).hexdigest(),
              'sanitizers': ['address', 'undefined'], 'phone_operations': False,
              'hardware_verified': False, 'hid_service_runtime_verified': False}
    (args.out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    print(done.stdout, end='')


if __name__ == '__main__':
    main()
