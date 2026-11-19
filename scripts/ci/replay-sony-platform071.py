#!/usr/bin/env python3
"""Replay the frozen PDX071 kernel and package on a compatible Linux host."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

DEVICE = Path(__file__).resolve().parents[2]
INPUTS = Path('/mnt/f/UniXNU-Port-artifacts/platform069-20261118')
EXPECTED = '56d09a18ddf1217c44664a2de754840c780a73f9fd8b2ad5b0e20b2d2637dd64'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True, help='New directory under the replay artifact root')
    parser.add_argument('--frozen-native', action='store_true', help='Use the original linked native image')
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to(INPUTS) or out == INPUTS:
        parser.error(f'use a new output directory under {INPUTS}')
    out.mkdir()

    def run(script, stage, *switches, **options):
        command = [sys.executable, '-B', str(DEVICE / 'scripts/ci' / script), *switches]
        for name, value in options.items():
            command.extend(('--' + name.replace('_', '-'), str(value)))
        logfile = out / (stage + '.log')
        with logfile.open('x') as log:
            result = subprocess.run(command, cwd=DEVICE, stdout=log, stderr=subprocess.STDOUT, timeout=950)
        if result.returncode:
            print(logfile.read_text(errors='replace')[-4000:], file=sys.stderr)
            raise SystemExit(f'{stage} failed: {logfile}')
        print(f'{stage}: {logfile}', flush=True)

    native = INPUTS / 'native-final071-001' if args.frozen_native else out / 'native'
    if not args.frozen_native:
        run('relink-sony-platform069.py', 'native', plan=INPUTS / 'plan-final071-001/plan.json', out=native)
    strict = out / 'strict'
    run('finish-sony-platform069.py', 'strict', '--expanded-native-data', build=native, out=strict,
        profile=DEVICE / 'profiles/ios-27.0.1-24A446-iphone14/graphics-prelink.toml',
        symbol_evidence=INPUTS / 'strict-final069-001/XnuPrelink/fixtures/fileset-d27-graphics-symbols.json')
    run('verify-sony-platform069-handset.py', 'handset-audit', native=native, strict=strict, out=out/'handset-audit',
        touch=INPUTS/'verify-final069-touch-input-001',
        block_tests='/mnt/e/UniXNU-sheng27-sony-20261113/block-descriptor-test-008/result.json')
    run('check-sony-platform069-linked.py', 'linked-audit', native=native, strict=strict, out=out/'linked-audit',
        requirements=INPUTS/'linked-requirements071-001/requirements.json')
    run('package-sony-platform069.py', 'package', version='071', work=out/'package', out=out/'release',
        native=native, strict=strict, verification=out/'handset-audit', platform_verification=out/'linked-audit',
        policy=INPUTS/'policy-final071-001', runtime=INPUTS/'runtime070-001',
        adt_receipt=INPUTS/'radio-adt-address-qualified069-003', skip_setup=INPUTS/'skip-setup-seed-001',
        seed_tests=INPUTS.parent/'platform067-20261118/volatile-seed-tests-001',
        skip_seed_tests=INPUTS/'skip-setup-native-sparse-001/test')
    with (out/'release/boot-pdx234-pac-abi-071.img').open('rb') as f:
        actual = hashlib.file_digest(f, 'sha256').hexdigest()
    record = {'image_sha256': actual, 'expected_sha256': EXPECTED, 'byte_identical': actual == EXPECTED}
    (out/'replay.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))
    if actual != EXPECTED:
        raise SystemExit('New image differs from the frozen PDX071 release')


if __name__ == '__main__':
    main()
