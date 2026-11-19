#!/usr/bin/env python3
"""Reuse exact-input runner naming identities, never its native addresses.

Only missing function identities established by the same reference matcher are
transferred. Each address is resolved from the local kernel's own symbol table.
This is not a new ABI or runtime qualification, and strict prelink still runs.
"""
import argparse
from bisect import bisect_right
from collections import defaultdict
import copy
import hashlib
import json
from pathlib import Path
import sys


def digest(data):
    return hashlib.sha256(data).hexdigest()


def resolve_reference_function(row, local_names):
    if not row or row.get('how') not in ('reference-symbol', 'reference-order'):
        return None
    name = row.get('name', '')
    targets = local_names.get(name, set())
    if (not name.startswith('_') or any(token in name for token in
            ('.cold.', 'OUTLINED_FUNCTION', '.llvm.')) or len(targets) != 1):
        return None
    return name, next(iter(targets))


def additive_reviewed_snapshot(runner_kit, local_kit):
    """Allow new reviewed anchors, not changed matcher rules or old evidence."""
    runner_kit, local_kit = Path(runner_kit), Path(local_kit)
    signature = hashlib.sha256()
    files = ['fileset_match.py', 'kc_image.py', 'fileset_shape.py']
    for name in files:
        left = (runner_kit / name).read_bytes()
        right = (local_kit / name).read_bytes()
        if left.replace(b'\r\n', b'\n') != right.replace(b'\r\n', b'\n'):
            raise ValueError('Runner matching rules changed: ' + name)
    for path in [runner_kit / 'fileset_match.py', runner_kit / 'kc_image.py',
                 runner_kit / 'fileset_shape.py', *sorted((runner_kit / 'fixtures').glob('fileset-*-symbols.json'))]:
        signature.update(path.name.encode() + b'\0' + path.read_bytes())
        if path.parent.name != 'fixtures':
            continue
        old = json.loads(path.read_text())
        new = json.loads((local_kit / 'fixtures' / path.name).read_text())
        if old['inputs'] != new['inputs'] or old.get('recovery') != new.get('recovery'):
            raise ValueError('Runner fixture provenance changed: ' + path.name)
        for field in ('functions', 'data', 'sites'):
            key = 'site' if field == 'sites' else 'original'
            entries = {entry[key]: entry for entry in new.get(field, [])}
            if any(entries.get(entry[key]) != entry for entry in old.get(field, [])):
                raise ValueError('Runner reviewed evidence changed: ' + path.name)
    return signature.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runner-map', required=True, type=Path)
    parser.add_argument('--local-map', required=True, type=Path)
    parser.add_argument('--local-failure', required=True, type=Path)
    parser.add_argument('--kernelcache', required=True, type=Path)
    parser.add_argument('--native', required=True, type=Path)
    parser.add_argument('--kit', required=True, type=Path)
    parser.add_argument('--runner-kit', type=Path,
                        help='Exact archived runner kit; only additive reviewed fixture changes may differ')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Preserve the existing derived map')
    sys.path.insert(0, str(args.kit.resolve()))
    from kc_image import Image
    from fileset_match import EXEC_SEGMENTS, matcher_signature, MATCHER_VERSION
    runner = json.loads(args.runner_map.read_text())
    local = json.loads(args.local_map.read_text())
    raw, native_bytes = args.kernelcache.read_bytes(), args.native.read_bytes()
    expected = {'kernelcache_sha256': digest(raw), 'native_sha256': digest(native_bytes), 'entry': 'com.apple.kernel'}
    if local.get('inputs') != expected:
        raise ValueError('Local map is not bound to the actual inputs')
    runner_signature = additive_reviewed_snapshot(args.runner_kit, args.kit) if args.runner_kit else matcher_signature()
    for record, signature in ((runner, runner_signature), (local, matcher_signature())):
        if (record.get('inputs', {}).get('kernelcache_sha256') != expected['kernelcache_sha256'] or
                record.get('inputs', {}).get('entry') != expected['entry'] or
                record.get('matcher_version') != MATCHER_VERSION or
                record.get('matcher_signature') != signature):
            raise ValueError('Naming record uses different original bytes or matching checks')
    cache = Image(raw)
    original = Image(raw, cache.entries['com.apple.kernel'][1])
    native = Image(native_bytes)
    original_starts, native_starts = sorted(original.function_starts()), sorted(native.function_starts())
    original_set, native_set = set(original_starts), set(native_starts)
    names = defaultdict(set)
    for address, values in native.symbols().items():
        if address in native_set:
            for name in values:
                names[name].add(address)
    missing = {address for entries in json.loads(args.local_failure.read_text()).get('missing', {}).values()
               for address in entries}
    result = copy.deepcopy(local)
    accepted, deferred = [], []
    for address in sorted(missing):
        row = runner.get('functions', {}).get(address)
        identity = resolve_reference_function(row, names)
        if identity is None:
            deferred.append(address)
            continue
        name, new = identity
        old = int(address, 16)
        if old not in original_set or row.get('addend', 0) != 0:
            deferred.append(address)
            continue
        for image, start in ((original, old), (native, new)):
            if not any(s['name'] in EXEC_SEGMENTS and s['va'] <= start < s['va'] + s['filesize'] for s in image.segments):
                raise ValueError('Named function is not in actual executable bytes')
        previous = result['functions'].get(address)
        if previous and previous.get('name') not in (name, None, 'CHECKPOINT'):
            raise ValueError('Runner identity contradicts an existing local named pair: ' + address)
        old_end = original_starts[bisect_right(original_starts, old)]
        new_end = native_starts[bisect_right(native_starts, new)]
        original_digest = digest(original.read(old, old_end - old))
        if row.get('original_sha256') is not None and row['original_sha256'] != original_digest:
            raise ValueError('Archived naming evidence has a different original body: ' + address)
        if row.get('original_size') is not None and row['original_size'] != old_end - old:
            raise ValueError('Archived naming evidence has a different original range: ' + address)
        proof = {'original': address, 'name': name, 'runner_method': row['how'],
                 'original_size': old_end - old, 'original_sha256': original_digest,
                 'local_native_size': new_end - new, 'local_native_sha256': digest(native.read(new, new_end - new))}
        result['functions'][address] = {'native': hex(new), 'name': name, 'addend': 0,
                                       'how': 'runner-reference-name'}
        accepted.append(proof)
    result['portable_naming_provenance'] = {
        'runner_map_sha256': digest(args.runner_map.read_bytes()),
        'runner_reference_sha256': runner.get('reference_sha256'),
        'local_native_sha256': expected['native_sha256'],
        'accepted': accepted, 'deferred': deferred,
        'runner_addresses_copied': False, 'data_offsets_transferred': False,
        'new_abi_qualification_claimed': False, 'runtime_qualified': False,
        'runner_kit': str(args.runner_kit.resolve()) if args.runner_kit else str(args.kit.resolve()),
        'runner_matcher_signature': runner_signature,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')
    print(f'Reused {len(accepted)} exact-original reference identities; local addresses resolved by symbol; {len(deferred)} deferred')


if __name__ == '__main__':
    main()
