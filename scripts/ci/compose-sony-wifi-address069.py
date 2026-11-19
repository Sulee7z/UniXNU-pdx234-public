#!/usr/bin/env python3
"""Compose only the qualified build007 Wi-Fi address overlay into a private Sony archive copy."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ci'))
from block_descriptor_abi import enabled
from compile_dependencies import valid


def sha(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def members(archive: Path) -> dict[str, str]:
    names = subprocess.check_output(['llvm-ar', 't', str(archive)], text=True).splitlines()
    if not names or len(names) != len(set(names)):
        raise ValueError('Base radio archive has no members or duplicate names')
    return {
        name: hashlib.sha256(subprocess.check_output(['llvm-ar', 'p', str(archive), name])).hexdigest()
        for name in names
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualification', type=Path, required=True,
                        help='successful check-sony-radio-adt069.py result directory')
    parser.add_argument('--base-provider', type=Path, required=True,
                        help='immutable radio-provider069-007 result directory')
    parser.add_argument('--out', type=Path, required=True, help='new, empty private output directory')
    args = parser.parse_args()
    qualification, base, out = args.qualification.resolve(), args.base_provider.resolve(), args.out.resolve()
    q = json.loads((qualification / 'result.json').read_text())
    provider = json.loads((base / 'result.json').read_text())
    if (q.get('passed') is not True or q.get('host_only') is not True or
            q.get('native_linked') is not False or q.get('strict_prelink_verified') is not False):
        raise ValueError('Qualification is not the expected host-only record')
    if provider.get('passed') is not True or provider.get('board_archive') is None:
        raise ValueError('Base provider is missing its immutable board-archive receipt')
    if sha(Path(provider['board_archive'])) != provider['board_sha256']:
        raise ValueError('Frozen provider007 archive checksum changed')
    if q['original_wifi_compile_receipt'] != str(base / 'objects/WifiProbe.o.dependencies.json'):
        raise ValueError('Qualification was not built from this provider007 Wi-Fi source/compiler receipt')
    original_receipt = Path(q['original_wifi_compile_receipt'])
    if sha(original_receipt) != q['original_wifi_compile_receipt_sha256']:
        raise ValueError('Original build007 Wi-Fi compile receipt changed')
    original_object_sha = json.loads(original_receipt.read_text())['object_sha256']
    selected = {Path(row['object']).name: row for row in q['target_objects']}
    if len(q['target_objects']) != 2 or set(selected) != {'WifiProbe.o', 'SonyWifiAddress069.o'}:
        raise ValueError('Only final WifiProbe.o and the independent address helper may be composed')
    for row in selected.values():
        obj, receipt = Path(row['object']), Path(row['dependency_receipt'])
        if (sha(obj) != row['object_sha256'] or sha(Path(row['source'])) != row['source_sha256'] or
                sha(receipt) != row['dependency_receipt_sha256']):
            raise ValueError('Qualified target object changed: ' + str(obj))
        dependency = json.loads(receipt.read_text())
        if (not valid(dependency) or not enabled(dependency['command']) or
                dependency.get('source') != row['source'] or dependency.get('object') != row['object'] or
                dependency.get('object_sha256') != row['object_sha256']):
            raise ValueError('Qualified arm64e/PAC compiler receipt differs: ' + str(receipt))
    address_source = ROOT / 'drivers/SonyWcn/platform069/SonyWifiAddress069.cpp'
    address_row = selected['SonyWifiAddress069.o']
    if (sha(address_source) != address_row['source_sha256'] or
            q.get('source_sha256', {}).get(str(address_source)) != address_row['source_sha256']):
        raise ValueError('Current dedicated address source differs from the checked qualification')
    for check in ('build007_source_reproduced_byte_for_byte', 'worker_source_unchanged',
                  'compiled_publication_before_worker', 'compiled_worker_firmware_gate_before_address_and_mapping'):
        if q.get(check) is not True:
            raise ValueError('Required build007 qualification is missing: ' + check)
    if members(Path(provider['board_archive'])).get('WifiProbe.o') != original_object_sha:
        raise ValueError('The original Wi-Fi object in the board archive differs from its compile receipt')

    out.mkdir(parents=True, exist_ok=False)
    archive = out / 'libSonyWcn-WifiAddress069.a'
    shutil.copyfile(provider['board_archive'], archive)
    before = members(archive)
    if 'WifiProbe.o' not in before or 'SonyWifiAddress069.o' in before:
        raise ValueError('Base archive member layout differs from expected provider007')
    subprocess.run(['llvm-ar', 'r', str(archive), str(selected['WifiProbe.o']['object']),
                    str(selected['SonyWifiAddress069.o']['object'])], check=True, timeout=30)
    after = members(archive)
    changed = {name for name in before.keys() & after.keys() if before[name] != after[name]}
    added = set(after) - set(before)
    if changed != {'WifiProbe.o'} or added != {'SonyWifiAddress069.o'} or before.keys() - after.keys():
        raise ValueError(f'Archive delta differs: changed={sorted(changed)}, added={sorted(added)}')
    if any(after[name] != row['object_sha256'] for name, row in selected.items()):
        raise ValueError('Composed archive member differs from qualified object')

    nm = subprocess.check_output(['llvm-nm', '-g', str(archive)], text=True)
    for symbol in ('_native_sony_wifi_publish', '_native_sony_wifi_start'):
        count = sum(len(fields := line.split()) >= 2 and fields[-1] == symbol and fields[-2] != 'U'
                    for line in nm.splitlines())
        if count != 1:
            raise ValueError(f'Expected one composed definition of {symbol}; found {count}')
    result = {
        'passed': True, 'private_archive_copy': str(archive), 'archive_sha256': sha(archive),
        'base_archive': provider['board_archive'], 'base_archive_sha256': provider['board_sha256'],
        'qualification_result': str(qualification / 'result.json'), 'qualification_sha256': sha(qualification / 'result.json'),
        'replaced_members': {'WifiProbe.o': {'old_sha256': before['WifiProbe.o'],
                                              'new_sha256': after['WifiProbe.o']}},
        'added_members': {'SonyWifiAddress069.o': after['SonyWifiAddress069.o']},
        'all_other_members_byte_identical': True, 'expected_member_delta_only': True,
        'kernel_or_native_linked': False, 'strict_prelink_verified': False,
        'device_operations': False,
        'next_integration': 'Main may supply this private archive to its native relink plan; re-run full native/strict/prelink/PAC qualification before selection.',
    }
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
