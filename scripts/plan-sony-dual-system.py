#!/usr/bin/env python3
"""Validate a fresh read-only capture and generate a Sony-specific offline plan.

No ADB upload, reboot, formatter, ioctl or block-device writes are implemented.
Generated GPT bytes are review artifacts, not a recovery apply bundle.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

DEVICE = Path(__file__).resolve().parents[1]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', required=True, type=Path)
    parser.add_argument('--official-dual-sys', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    if args.out.exists():
        parser.error('Preserve prior plans; choose a new output directory')
    record = json.loads((args.capture / 'capture.json').read_text())
    if record['serial'] != 'PDX_DEVICE_SERIAL' or record.get('device_writes') is not False:
        raise ValueError('Need the identified Sony read-only capture')
    for name, item in record['captures'].items():
        raw = (args.capture / name).read_bytes()
        if len(raw) != item['bytes'] or sha(raw) != item['sha256']:
            raise ValueError('Capture changed: ' + name)
    a = (args.capture / 'gpt-primary-region.bin').read_bytes()
    b = (args.capture / 'gpt-backup-region.bin').read_bytes()
    if a != (args.capture / 'gpt-primary-region-after.bin').read_bytes() or b != (args.capture / 'gpt-backup-region-after.bin').read_bytes():
        raise ValueError('GPT changed during capture')
    sys.path.insert(0, str(args.official_dual_sys.resolve()))
    import gpt
    spec = importlib.util.spec_from_file_location('sony_layout', DEVICE / 'ci/dual_sys/sony_layout.py')
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    primary, backup, plan = adapter.plan(a, b, record['sector_bytes'],
        record['disk_bytes'] // record['sector_bytes'], 64 << 30, gpt)
    plan.update(serial=record['serial'], captured_utc=record['captured_utc'],
        before_sha256={'primary': sha(a), 'backup': sha(b)},
        after_sha256={'primary': sha(primary), 'backup': sha(backup)},
        official_gpt_parser_sha256=sha((args.official_dual_sys / 'gpt.py').read_bytes()),
        layout_adapter_sha256=sha((DEVICE / 'ci/dual_sys/sony_layout.py').read_bytes()),
        device_writes=False, formatting_executed=False)
    args.out.mkdir(parents=True, exist_ok=False)
    for name, raw in [('gpt-primary.before', a), ('gpt-backup.before', b),
                      ('gpt-primary.after', primary), ('gpt-backup.after', backup)]:
        (args.out / name).write_bytes(raw)
    (args.out / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    print(json.dumps(plan, indent=2))


if __name__ == '__main__':
    main()
