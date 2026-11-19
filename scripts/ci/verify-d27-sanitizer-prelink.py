#!/usr/bin/env python3
"""Independently check strict completeness and the real Sandbox getter import."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

DEVICE = Path(__file__).resolve().parents[2]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def check(candidate, report, original, mapping):
    sys.path.insert(0, str(DEVICE / 'ci/XnuPrelink'))
    from kc_image import Image
    raw, old = candidate.read_bytes(), original.read_bytes()
    result = json.loads(report.read_text())
    if not result.get('candidate_written') or not result.get('mapping_complete'):
        raise ValueError('Strict candidate is not complete')
    if result.get('allow_missing') is not False or result.get('missing') or result.get('stubbed'):
        raise ValueError('Unresolved or stubbed references are not accepted')
    if digest(raw) != result.get('candidate_sha256'):
        raise ValueError('Candidate digest differs from the final report')
    seal = result.get('source_crypto_final_seal', {})
    if seal.get('exit_code') != 0 or seal.get('sha256') != digest(raw):
        raise ValueError('Final source-crypto seal receipt is absent or stale')
    if digest(old) != 'c28f4fc9b83cde00087e81f890c82d566b9e98b5ac228dfecd83afdf34070445':
        raise ValueError('Not the reviewed D27 original')
    pairs = json.loads(mapping.read_text())
    identity = pairs['functions']['0xfffffff00a226184']
    if (identity.get('name'), identity.get('addend'), identity.get('how')) != (
            '_task_get_sanitizer_config', 0, 'reviewed'):
        raise ValueError('Missing raw sanitizer getter identity')
    cache, source = Image(raw), Image(old)
    member = Image(raw, cache.entries['com.apple.kernel'][1])
    targets = [address for address, names in member.symbols().items()
               if '_task_get_sanitizer_config' in names]
    if len(targets) != 1 or targets[0] not in member.function_starts():
        raise ValueError('Getter does not resolve to one actual kernel function')
    target = targets[0]
    pointer = cache.fixups().get(0xfffffff0080cfe38)
    if pointer != (target, 1, 0, 0, 1):
        raise ValueError('Actual Sandbox authenticated import does not reach native getter')
    instructions = struct.unpack('<7I', member.read(target, 28))
    # Normal DEVELOPMENT assert guard plus the complete typed raw byte return.
    if instructions[:4] != (0x14000003, 0x3960d000, 0xd65f03c0, 0xb5ffffc0):
        raise ValueError('Getter no longer has the reviewed raw-byte load/return contract')
    components = []
    for name in ('com.apple.security.sandbox', 'com.apple.kext.AppleMatch'):
        before = Image(old, source.entries[name][1])
        after = Image(raw, cache.entries[name][1])
        left = next(s for s in before.segments if s['name'] == '__TEXT_EXEC')
        right = next(s for s in after.segments if s['name'] == '__TEXT_EXEC')
        a, b = before.read(left['va'], left['filesize']), after.read(right['va'], right['filesize'])
        if a != b:
            raise ValueError('Original component executable bytes changed: ' + name)
        components.append({'name': name, 'bytes': len(a), 'sha256': digest(a), 'unchanged': True})
    return {'candidate_sha256': digest(raw), 'missing': {}, 'stubbed': {},
            'allow_missing': False, 'final_seal_verified': True,
            'sandbox_import_site': '0xfffffff0080cfe38', 'getter': hex(target),
            'getter_auth': {'key': 'IA', 'diversity': 0, 'address_diversity': True},
            'getter_load_offset': 2100, 'original_components': components,
            'runtime_qualified': False, 'device_operations': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--strict', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Preserve existing verification results')
    final = args.strict / 'final'
    result = check(final / 'kernel.macho', final / 'kernel.json',
                   DEVICE / '.cache/iphone14-ios27/ipsw/24A446/kernelcache.decompressed',
                   final / 'kernel.map.json')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
