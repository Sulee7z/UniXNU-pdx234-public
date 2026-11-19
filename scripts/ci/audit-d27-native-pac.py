#!/usr/bin/env python3
"""Collect the three native PAC facts before the flag-only rebuild."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
PAC_FLAG = '-fptrauth-function-pointer-type-discrimination'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def targets(arguments):
    result = []
    for index, argument in enumerate(arguments):
        if argument.startswith(('--target=', '-target=')):
            result.append(argument.split('=', 1)[1])
        elif index and arguments[index - 1] in ('--target', '-target'):
            result.append(argument)
    return result


def identity(path):
    data = Path(path).read_bytes()
    magic, cpu, subtype, kind, count = struct.unpack_from('<5I', data)
    if (magic, cpu, subtype & 255, kind) != (0xfeedfacf, 0x100000c, 2, 1):
        raise ValueError('Not an arm64e object: ' + str(path))
    at, versions = 32, []
    for _ in range(count):
        cmd, size = struct.unpack_from('<II', data, at)
        if cmd == 0x32:
            versions.append(struct.unpack_from('<II', data, at + 8))
        at += size
    if versions != [(2, 27 << 16)]:
        raise ValueError('Not an iOS27 object: ' + str(path))
    return dict(cpu=hex(cpu), subtype=hex(subtype), platform='iOS', minimum='27.0')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    options = parser.parse_args()
    out = options.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    baseline = json.loads((BASE / 'strict-006/result.json').read_text())
    command = baseline['command']
    native = Path(command[command.index('--kernel') + 1])
    cache = Path(command[command.index('--prelinked') + 1])
    if sha(native) != baseline['inputs'][str(native)] or sha(cache) != baseline['inputs'][str(cache)]:
        raise ValueError('The frozen native/cache changed')
    sys.path.insert(0, str(BASE / 'strict-006/XnuPrelink'))
    from kc_image import Image
    image = Image(native.read_bytes())
    symbols, fixups = image.symbols(), image.fixups()
    section_types = {}
    for cmd, at, _ in image.commands:
        if cmd != 0x19:
            continue
        for index in range(struct.unpack_from('<I', image.data, at + 64)[0]):
            section = at + 72 + 80 * index
            name = image.data[section:section + 16].rstrip(b'\0').decode()
            section_types[name] = struct.unpack_from('<I', image.data, section + 64)[0] & 255
    tables = []
    for section in image.sections:
        if section['name'] != '__auth_ptr' and section_types[section['name']] not in (6, 7):
            continue
        rows = []
        for site, (target, auth, key, diversity, addrdiv) in sorted(fixups.items()):
            if section['va'] <= site < section['va'] + section['size']:
                rows.append(dict(site=hex(site), target=hex(target), symbols=symbols.get(target, []),
                                 authentication=bool(auth), key=key, diversity=diversity,
                                 address_diversity=bool(addrdiv)))
        histogram = Counter((r['authentication'], r['key'], r['diversity'], r['address_diversity']) for r in rows)
        tables.append(dict(section=section['segment'] + ',' + section['name'],
                           section_type=section_types[section['name']], bytes=section['size'],
                           slots=section['size'] // 8, fixups=len(rows), rows=rows,
                           histogram=[dict(authentication=k[0], key=k[1], diversity=k[2],
                                           address_diversity=k[3], count=v) for k, v in histogram.items()]))
    got = dict(native=str(native), native_sha256=sha(native), tables=tables,
               conventional_got_sections=sum(section_types[s['name']] in (6, 7) for s in image.sections),
               note='__auth_ptr is S_REGULAR, not a conventional Mach-O GOT. Do not equate its IA/0 schema with typed callback fields.')
    write(out / 'native-pointer-tables.json', got)

    obj = native.parent
    records, no_target = [], []
    for path in sorted(obj.rglob('*.o.json')):
        record = json.JSONDecoder().raw_decode(path.read_text().lstrip())[0]
        selected = targets(record['arguments'])
        row = dict(receipt=str(path), targets=selected)
        records.append(row)
        if not selected:
            no_target.append(row)
    gssd_path = obj / 'osfmk/DEVELOPMENT/gssd_mach.o.json'
    gssd = json.JSONDecoder().raw_decode(gssd_path.read_text().lstrip())[0]
    write(out / 'gssd-original-receipt.json', gssd)
    source = (Path(gssd['directory']) / gssd['file']).resolve()
    clang = Path(gssd['arguments'][0])
    env = dict(os.environ, CROSS_CLANG=str(clang), DARWIN_TRIPLE='arm64e-apple-ios27.0',
               CROSS_EXTRA_FLAGS='-mllvm -disable-atexit-based-global-dtor-lowering')
    # Diagnostic driver expansion only. Never compile an arm64/host object.
    args, skip = [], False
    for argument in gssd['arguments'][1:]:
        if skip:
            skip = False
            continue
        if argument in ('--target', '-target', '-MJ', '-MF', '-MT', '-MQ'):
            skip = True
            continue
        if argument.startswith(('--target=', '-target=')):
            continue
        args.append(argument)
    wrapper = Path('/root/unixnu-build/pdx234-pac-toolchain/CommandLineTools/usr/bin/clang')
    expanded = subprocess.run([str(wrapper), '-###', *args], cwd=gssd['directory'], env=env,
                              capture_output=True, text=True, timeout=30)
    (out / 'gssd-no-target-driver.txt').write_text(expanded.stdout + expanded.stderr)
    triples = re.findall(r'"-triple"\s+"([^"]+)"', expanded.stderr)
    if expanded.returncode or not triples or not triples[-1].startswith('arm64e-apple-ios27.'):
        raise ValueError('The no-target wrapper did not select arm64e/iOS27')
    receipt = dict(total_records=len(records), records_without_target=no_target,
                   gssd_receipt=str(gssd_path), gssd_receipt_sha256=sha(gssd_path),
                   gssd_source=str(source), gssd_source_sha256=sha(source),
                   gssd_recorded_targets=targets(gssd['arguments']),
                   gssd_object=identity(obj / 'osfmk/DEVELOPMENT/gssd_mach.o'),
                   compiler=str(clang), compiler_sha256=sha(clang),
                   wrapper=str(wrapper), wrapper_sha256=sha(wrapper),
                   no_target_control_environment={k: env[k] for k in ('CROSS_CLANG', 'DARWIN_TRIPLE', 'CROSS_EXTRA_FLAGS')},
                   no_target_control_effective_triples=triples, diagnostic_only=True,
                   policy='Accept --target= and -target forms. With no target, require the original object identity and the same wrapper/environment; never replay an unqualified direct compiler using its host default.')
    write(out / 'compile-target-evidence.json', receipt)

    site = 0xfffffff00721dfc8
    if symbols.get(site) != ['_g_crypto_funcs']:
        raise ValueError('The reported native slot is no longer g_crypto_funcs')
    layout = json.loads((BASE / 'strict-006/kernel.json').read_text())['statistics']['segment_layout']
    region = layout[image.section(site)['segment']]
    moved = site - int(region['old'], 16) + int(region['new'], 16)
    final = Image((BASE / 'strict-008-kmod-pac/kernel.macho').read_bytes())
    member = Image(final.data, final.entries['com.apple.kernel'][1])
    if member.symbols().get(moved) != ['_g_crypto_funcs']:
        raise ValueError('The placed symbol does not match the native slot')
    owner = dict(native_site=hex(site), native_symbols=symbols[site],
                 native_section=image.section(site), native_raw_bytes=image.read(site, 8).hex(),
                 is_chained_fixup=site in fixups, owner='native XNU libkern/crypto/register_crypto.c',
                 declaration='SECURITY_READ_ONLY_LATE(crypto_functions_t) g_crypto_funcs = NULL;',
                 writer='register_crypto_functions', provider='registered crypto_functions table',
                 placed_site=hex(moved), placed_symbols=member.symbols()[moved],
                 note='This is a table pointer global, not a signed function slot. Its zero file initializer does not prove a runtime NULL or authentication failure.')
    write(out / 'failure-slot-owner.json', owner)
    evidence = dict(native_sha256=sha(native), original_cache_sha256=sha(cache),
                    pointer_table_evidence=True, compile_target_evidence=True, slot_owner_evidence=True,
                    gate_passed=True, permitted_build_delta=[PAC_FLAG], source_changes=False,
                    auth_instruction_patches=False, pac_enabled=True, architecture='arm64e',
                    device_operations=False, runtime_qualified=False)
    write(out / 'evidence.json', evidence)
    print(json.dumps(dict(evidence=evidence, pointer_tables=[{k: v for k, v in t.items() if k != 'rows'} for t in tables],
                          gssd_targets=receipt['gssd_recorded_targets'], no_target_records=len(no_target),
                          owner=owner), indent=2))


if __name__ == '__main__':
    main()
