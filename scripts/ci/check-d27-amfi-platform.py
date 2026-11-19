#!/usr/bin/env python3
"""Observe original D27 AMFI's PMGR decision with only the input ADT changed."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

DEVICE = Path(__file__).resolve().parents[2]
PROJECT = DEVICE.parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--esp', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    codec = load('qemu_adt', PROJECT / 'sources/UniXNU-qemu-20261110/scripts/make-qemu-adt.py')
    reader = load('apple_device_tree', DEVICE / 'scripts/apple-device-tree.py')
    sys.path.insert(0, str(DEVICE / 'ci/XnuPrelink'))
    from kc_image import Image
    data = (args.esp / 'EFI/UniXNU/Payloads/kernel.macho').read_bytes()
    collection = Image(data)
    original = (DEVICE / '.cache/iphone14-ios27/ipsw/24A446/kernelcache.decompressed').read_bytes()
    stock = Image(original)
    # These exact original instructions read the flag and select PMGR/VM paths.
    address = 0xfffffff008e8949c
    if collection.read(address, 12) != stock.read(address, 12):
        raise ValueError('Original AMFI decision bytes changed')
    # Validate the decoded LDRB/TBZ sequence independently of the ADRP encoding.
    if collection.read(address + 4, 8).hex() != '08c57239a8000036':
        raise ValueError('D27 AMFI flag branch differs')
    native = Image(data, collection.entries['com.apple.kernel'][1])
    names = {name: va for va, entries in native.symbols().items() for name in entries}
    rows = []
    for value in (1, 0):
        out = args.out / f'vmm-{value}'
        esp = out / 'esp'
        shutil.copytree(args.esp, esp)
        adt = esp / 'EFI/UniXNU/Payloads/kernel.macho.adt'
        tree, end = codec.parse(adt.read_bytes())
        if end != adt.stat().st_size:
            raise ValueError('Incomplete input ADT')
        codec.put(codec.child(tree, 'defaults'), 'vmm-present', struct.pack('<I', value))
        adt.write_bytes(codec.serialize(tree))
        if reader.u32(reader.parse(adt.read_bytes()), '/defaults', 'vmm-present') != value:
            raise ValueError('ADT value differs')
        target = 0xfffffff008e894a8 if value else 0xfffffff008e894b8
        opposite = 0xfffffff008e894b8 if value else 0xfffffff008e894a8
        command = ['python3', '-B', str(PROJECT / 'sources/UniXNU-main-20261109/scripts/qemu-entry/gdb-stop.py'),
                   hex(target), '--esp', str(esp), '--kernel', str(esp / 'EFI/UniXNU/Payloads/kernel.macho'),
                   '--fixture', str(out / 'observation'), '--gic-version', '3', '--qemu-memory-mib', '4096',
                   '--system-registers', '--qemu-ramfb', '--firmware', '/usr/share/AAVMF/AAVMF_CODE.fd',
                   '--timeout', '150', '--also-stop', hex(opposite), '--also-stop', hex(names['_panic']),
                   '--read-memory', 'fffffff007e68cb1:1']
        env = dict(os.environ, TMPDIR=str(out.resolve()), PYTHONDONTWRITEBYTECODE='1')
        with (out / 'run.log').open('w') as log:
            done = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
        report = out / 'observation/gdb-stop.json'
        observation = json.loads(report.read_text()) if report.exists() else {}
        flag = observation.get('memory', {}).get('fffffff007e68cb1:1')
        passed = done.returncode == 0 and observation.get('pc') == hex(target) and flag == f'{value:02x}'
        rows.append(dict(vmm_present=value, command=command, exit_code=done.returncode,
                         actual_pc=observation.get('pc'), amfi_flag=flag, expected_pc=hex(target),
                         passed=passed, adt_sha256=hashlib.sha256(adt.read_bytes()).hexdigest()))
        (args.out / 'report.json').write_text(json.dumps(dict(
            kernel_sha256=hashlib.sha256(data).hexdigest(), original_amfi_decision_preserved=True,
            cases=rows, passed=len(rows) == 2 and all(r['passed'] for r in rows),
            device_operations=False, sony_ufs_read_verified=False), indent=2) + '\n')
    print(json.dumps(rows, indent=2))
    raise SystemExit(0 if all(r['passed'] for r in rows) else 1)


if __name__ == '__main__':
    main()
