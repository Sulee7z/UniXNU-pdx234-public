#!/usr/bin/env python3
"""Strictly prelink the flag-only native; retain original Apple PAC metadata."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tomllib

BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
DEVICE = Path(__file__).resolve().parents[2]


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n')


def names(image):
    result = {}
    for address, symbols in image.symbols().items():
        for symbol in symbols:
            result.setdefault(symbol, set()).add(address)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--reuse-map', type=Path, help='Previous strict map, only for an exactly guarded generated continuation-constant change')
    parser.add_argument('--mapped-native', type=Path, help='The immutable native input belonging to --reuse-map')
    parser.add_argument('--profile', type=Path, help='Use explicit target profile roots instead of the historical storage-only closure')
    parser.add_argument('--minimal-drivers', action='store_true', help='Suppress optional D27 M2Scaler/DART/IOAV personalities using a checked root subset')
    parser.add_argument('--symbol-evidence', type=Path, help='Additional hash-bound reviewed D27 symbol fixture')
    parser.add_argument('--expanded-native-data', action='store_true', help='Append native RW data, preserving retained kext addresses')
    args = parser.parse_args()
    result = json.loads((args.build / 'result.json').read_text())
    native = args.build / 'native.macho'
    source_allowed = (result.get('source_changes') is False or
                      (result.get('native_source_changes') is False and
                       result.get('generated_iig_compat', {}).get('authenticated_cast') is True))
    if result.get('native_source_changes'):
        sys.path.insert(0, str(DEVICE / 'ci'))
        from native_source_overlays import validate_overlays
        validate_overlays(result, sha)
        source_allowed = True
    if (sha(native) != result['native_sha256'] or not result['pac_authentication_retained'] or
            not source_allowed or result.get('auth_instruction_patches') is not False):
        raise ValueError('Require a completed, flag-only PAC build')
    old_dir = BASE / 'strict-006'
    old_result = json.loads((old_dir / 'result.json').read_text())
    command = list(old_result['command'])
    selected_profile = None
    profile = None
    profile_path = None
    if args.minimal_drivers and args.profile:
        parser.error('--minimal-drivers supplies its own profile; omit --profile')
    if args.minimal_drivers:
        profile_path = DEVICE/'profiles/ios-27.0.1-24A446-iphone14/minimal-graphics-prelink.toml'
        profile = tomllib.loads(profile_path.read_text())
        if (profile['ipsw']['product'],profile['ipsw']['device_class'],profile['ipsw']['build']) != ('iPhone14,7','d27ap','24A446'):
            raise ValueError('Minimal profile has wrong D27 identity')
        roots = profile['kernel']['prelink']['roots']
        while '--root' in command:
            at=command.index('--root');del command[at:at+2]
        command += [part for root in roots for part in ('--root',root)]
        selected_profile=dict(path=str(profile_path.resolve()),sha256=sha(profile_path),roots=roots)
    if args.profile:
        profile = tomllib.loads(args.profile.read_text())
        if (profile['ipsw']['product'], profile['ipsw']['device_class'], profile['ipsw']['build']) != ('iPhone14,7', 'd27ap', '24A446'):
            raise ValueError('Require the original D27 OS identity')
        roots = profile['kernel']['prelink']['roots']
        if not roots or len(roots) != len(set(roots)) or not all(isinstance(root, str) for root in roots):
            raise ValueError('Require unique explicit prelink roots')
        while '--root' in command:
            at = command.index('--root')
            del command[at:at + 2]
        command += [part for root in roots for part in ('--root', root)]
        selected_profile = dict(path=str(args.profile.resolve()), sha256=sha(args.profile), roots=roots)
    cache = Path(command[command.index('--prelinked') + 1])
    reference = Path(command[command.index('--fileset-reference') + 1])
    old_native = Path(command[command.index('--kernel') + 1])
    for path in (cache, reference, old_native):
        if sha(path) != old_result['inputs'][str(path)]:
            raise ValueError('Original input changed: ' + str(path))
    if selected_profile and profile['kernel']['prelink']['kernelcache_sha256'] != sha(cache):
        raise ValueError('Profile kernelcache identity differs from the retained D27 input')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    kit = out / 'XnuPrelink'
    shutil.copytree(old_dir / 'XnuPrelink', kit, ignore=shutil.ignore_patterns('__pycache__'))
    if args.expanded_native_data:
        sys.path.insert(0, str(DEVICE / 'ci'))
        from expanded_native_data import apply
        apply(kit)
    if args.symbol_evidence:
        evidence = json.loads(args.symbol_evidence.read_text())
        if evidence['inputs']['kernelcache_sha256'] != sha(cache):
            raise ValueError('Symbol evidence belongs to a different original kernel')
        shutil.copyfile(args.symbol_evidence, kit / 'fixtures/fileset-d27-graphics-symbols.json')
    if (kit / 'd27_kmod_pac.py').exists() or 'converted_pointer' in (kit / 'fileset_segmented.py').read_text():
        raise ValueError('Do not use the historical diversifier adapter')
    sys.path.insert(0, str(kit))
    from kc_image import Image
    from fileset_match import match_images
    raw, new_bytes = cache.read_bytes(), native.read_bytes()
    transferred, skipped = [], []
    bridge = None
    if args.reuse_map:
        if not args.mapped_native:
            parser.error('--reuse-map requires --mapped-native')
        mapping = json.loads(args.reuse_map.read_text())
        before, after = Image(args.mapped_native.read_bytes()), Image(new_bytes)
        if (mapping['inputs']['native_sha256'] != sha(args.mapped_native) or
                mapping['inputs']['kernelcache_sha256'] != sha(cache) or
                mapping['reference_sha256'] != sha(reference) or
                before.symbols() != after.symbols() or before.function_starts() != after.function_starts() or
                before.fixups() != after.fixups()):
            raise ValueError('Previous map identity/layout is not preserved')
        old_segments = {s['name']: s for s in before.segments if s['name'] != '__LINKEDIT'}
        new_segments = {s['name']: s for s in after.segments if s['name'] != '__LINKEDIT'}
        if old_segments.keys() != new_segments.keys() or any(
                old_segments[name]['va'] != s['va'] or old_segments[name]['size'] != s['size']
                for name, s in new_segments.items()):
            raise ValueError('Native placement changed; regenerate the map')
        start = next(a for a, symbols in before.symbols().items() if '_Call_continuation' in symbols)
        generator = json.loads((args.build / 'generated-assym/result.json').read_text())
        modifier = int(generator['discriminator'], 16)
        site, old_word, new_word = start + 0x68, 0xD2800015, 0xD2800015 | (modifier << 5)
        changes = []
        for name, segment in old_segments.items():
            if name not in ('__TEXT_EXEC', '__KLD') or not segment['filesize']:
                continue
            a, c = before.read(segment['va'], segment['filesize']), after.read(segment['va'], segment['filesize'])
            for at in range(0, len(a) - 3, 4):
                if a[at:at + 4] != c[at:at + 4]:
                    changes.append((segment['va'] + at, struct.unpack_from('<I', a, at)[0],
                                    struct.unpack_from('<I', c, at)[0]))
        generated_values = {int(value[1].lstrip('$#')) for key, value in generator['changed_defines'].items() if key.endswith('_NUM')}
        immediate_mask = 0xFFFF << 5
        allowed = all(a & 0x7F800000 in (0x52800000, 0x72800000) and
                      a & ~immediate_mask == c & ~immediate_mask and
                      (a >> 5) & 0xFFFF == 0 and (c >> 5) & 0xFFFF in generated_values
                      for _, a, c in changes)
        if (site, old_word, new_word) not in changes or not allowed:
            raise ValueError('Unexpected executable differences: ' + repr(changes[:10]))
        mapping['inputs']['native_sha256'] = sha(native)
        bridge = dict(previous_map=str(args.reuse_map), previous_native_sha256=sha(args.mapped_native),
                      changed_instruction=hex(site), old_word=hex(old_word), new_word=hex(new_word),
                      discriminator=hex(modifier), auth_instruction_unchanged=True,
                      all_generated_mov_changes=[dict(site=hex(s), old_word=hex(a), new_word=hex(c)) for s, a, c in changes],
                      symbols_function_starts_and_fixups_identical=True)
        print('Reuse strict map: only generated PAC modifier MOV immediates changed; auth instructions unchanged', flush=True)
    else:
        print('Regenerate map for the new native SHA; retain only uniquely named historical identities', flush=True)
        mapping = match_images(raw, new_bytes, reference_data=reference.read_bytes())
        previous = json.loads(Path(command[command.index('--fileset-map') + 1]).read_text())
        old_symbols = names(Image(old_native.read_bytes()))
        new_symbols = names(Image(new_bytes))
        for group in ('functions', 'data'):
            for address, entry in previous[group].items():
                symbol, addend = entry.get('name'), entry.get('addend', 0)
                old_address = int(entry['native'], 16)
                if (old_symbols.get(symbol) != {old_address - addend} or
                        len(new_symbols.get(symbol, set())) != 1):
                    skipped.append(dict(group=group, original=address, name=symbol))
                    continue
                new_address = next(iter(new_symbols[symbol])) + addend
                mapping[group][address] = dict(entry, native=hex(new_address),
                                               how='prior-strict-identity/current-unique-native-symbol')
                transferred.append(dict(group=group, original=address, name=symbol,
                                        previous_native=hex(old_address), native=hex(new_address), addend=addend))
    map_path = out / 'kernel.map.json'
    write(map_path, mapping)
    write(out / 'identity-transfer.json', dict(transferred=transferred, skipped=skipped,
                                               old_native_sha256=sha(old_native), native_sha256=sha(native),
                                               stale_native_addresses_used=False, generated_constant_bridge=bridge))
    command[2] = str(kit / 'emit_prelink.py')
    command[command.index('--kernel') + 1] = str(native)
    command[command.index('--output') + 1] = str(out / 'kernel.macho')
    command[command.index('--fileset-map') + 1] = str(map_path)
    write(out / 'command.json', command)
    with (out / 'prelink.log').open('x') as log:
        done = subprocess.run(command, cwd=kit, stdout=log, stderr=subprocess.STDOUT)
    if done.returncode:
        raise RuntimeError((out / 'prelink.log').read_text()[-6500:])
    report = json.loads((out / 'kernel.json').read_text())
    if report['missing'] or report['stubbed'] or report['allow_missing'] or not report['candidate_written']:
        raise ValueError('Strict prelink did not complete')
    candidate = Image((out / 'kernel.macho').read_bytes())
    original = Image(raw)
    expanded_data = None
    if args.expanded_native_data:
        from expanded_native_data import validate
        expanded_data = validate(original, Image(new_bytes), candidate, report['statistics']['segment_layout'])
        expanded_data['overlay_sha256'] = sha(DEVICE / 'ci/expanded_native_data.py')
        write(out / 'expanded-data.json', expanded_data)
    if selected_profile:
        required = [name for name in selected_profile['roots'] if not name.startswith('!')]
        if any(name not in original.entries or name not in candidate.entries for name in required):
            raise ValueError('Selected root absent from original or resulting fileset')
    old_fixups, new_fixups = original.fixups(), candidate.fixups()
    records = json.loads((BASE / 'strict-008-kmod-pac/result.json').read_text())['records']
    checked = []
    for entry in records:
        site = int(entry['site'], 16)
        if new_fixups.get(site) != old_fixups.get(site) or old_fixups[site][3] != 0xe4fe:
            raise ValueError('Original kmod PAC metadata changed: ' + entry['site'])
        checked.append(entry['site'])
    output = dict(native_sha256=sha(native), candidate=str(out / 'kernel.macho'),
                  candidate_sha256=sha(out / 'kernel.macho'), strict_missing={}, strict_stubbed={},
                  allow_missing=False, original_kmod_fields_verified=checked,
                  original_kmod_diversity='0xe4fe', pac_metadata_adapters=False,
                  auth_instruction_patches=False, pac_enabled=True, runtime_qualified=False,
                   generated_constant_bridge=bridge,
                   expanded_native_data=expanded_data,
                  generated_iig_compat=result.get('generated_iig_compat'),
                  recount_sparse_kind_span=result.get('recount_sparse_kind_span', False),
                  native_jop_policy=result.get('native_jop_policy', False),
                  single_cluster_qos=result.get('single_cluster_qos', False),
                  vfs_shutdown_diagnostic=result.get('vfs_shutdown_diagnostic', False),
                  usb_console=result.get('usb_console', False),
                  launchd_trace=result.get('launchd_trace', False),
                   launchd_transport=result.get('launchd_transport', False),
                   launchd_shutdown=result.get('launchd_shutdown', False),
                   selected_profile=selected_profile,
                   minimal_drivers=args.minimal_drivers,
                   symbol_evidence_sha256=sha(args.symbol_evidence) if args.symbol_evidence else None,
                   display_source=result.get('display_source'),
                   gpu_source=result.get('gpu_source'),
                    boot_screen=result.get('boot_screen'),
                    framebuffer_call_trace=result.get('framebuffer_call_trace'),
                    upstream_startup=result.get('upstream_startup', False),
                    audit_source_repairs=result.get('audit_source_repairs', False),
                   usb_sources=result.get('usb_sources', {}),
                  device_operations=False)
    write(out / 'result.json', output)
    print(json.dumps(output, indent=2), flush=True)


if __name__ == '__main__':
    main()
