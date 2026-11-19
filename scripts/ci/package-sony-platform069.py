#!/usr/bin/env python3
"""Package qualified physical069 over exact068, with two checked volatile seeds.

--capacity-probe uses the *delivered068* kernel, never a partial069 native,
does not create a boot IMG, and reports both FAT and compressed96MiB limits.
Production requires explicit final native/strict/instruction/linked receipts.
All commands run on the host; no phone or XNU/QEMU boot is performed.
"""
import argparse
import copy
import hashlib
import hmac
import importlib.util
import json
import lzma
import os
from pathlib import Path
import shutil
import signal
import struct
import subprocess
import sys
import time
import tomllib
from types import SimpleNamespace
import uuid
import zlib

ROOT = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
sys.path.insert(0, str(ROOT / 'ci'))
from darwin_boot_args import validate as validate_arguments
from pdx_boot_transport import BootTransport
from platform069.addon import append_trust, decode, trust_modules
from platform069.codesign import inspect as inspect_signature
from platform069.integration import sha
from platform069.menu import BASELINE_IMAGE_SHA, render, updated_arguments, validate_choices
from platform069.overlays import validate_overlays
from platform069.skip_setup import BUILD, PREFERENCES, official_values
from sony_menu068 import FIRMWARE_SHA, KERNEL_SHA, loader_guard

BOOT_BYTES = 96 * 1024**2
FAT_LIMIT = 128 * 1024**2  # Exact retained PdxConfigFsDxe, not the looser host decoder.
PRISTINE_SEED_SHA = '31ee5019fa0f94f09de1f450a85421d6bd5945b57ac9830897fc291e837fa480'
FIRMWARE_SOURCE_SHA = 'bf8b4f58733df5b49ccd649a26b91f8e44158cef854d7920b603988932dab095'
SHIM_SOURCE_SHA = 'd3c87b87d69672c71dfdbbc1e8419ddf7e7c02747587a8c493f7434c1d905c4a'
LOADER_SOURCES = {
    'DarwinBoot.c': '283fd6024a27d9122c73b95c79aa00d650f423d4374a1815485230d2192599f6',
    'BootArgs.h': 'db3280da9e21ca550c6b3eae71962de700726cefad610125a550c142de2299b4',
    'PackedRamdisk.h': 'b06f5b3e39571b6b595c3951ef791b78fc8723ba17528f42ddbb824ae52aff0b',
}
FEATURES = {'heat', 'refresh', 'app_exits', 'wifi', 'bluetooth', 'brightness', 'power_key', 'touch'}
PREFIX = 'EFI/UniXNU/'
ARTIFACTS = Path('/mnt/f/UniXNU-Port-artifacts/platform069-20261118')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    with path.open('x') as stream:
        stream.write(json.dumps(value, indent=2) + '\n')


def receipt(path):
    path = path / 'result.json' if path.is_dir() else path
    return path.resolve(), json.loads(path.read_text())


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts/ci' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(command, log=None, timeout=90):
    command = list(map(str, command))
    result = subprocess.run(command, capture_output=True, timeout=timeout,
        env=dict(os.environ, LC_ALL='C', TZ='UTC', PYTHONDONTWRITEBYTECODE='1'))
    if log:
        with log.open('xb') as stream:
            stream.write(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError('Command failed: ' + repr(command) + '\n' +
                           (result.stdout + result.stderr).decode(errors='replace')[-5000:])
    return result.stdout


def check_space(work):
    # Preserve the established workspace8GiB guard. All new large files go to F.
    free = shutil.disk_usage(ROOT).free
    require(free >= 8 * 1024**3, f'Workspace below8GiB guard: {free} bytes')
    parent = work
    while not parent.exists():
        parent = parent.parent
    free = shutil.disk_usage(parent).free
    require(free >= 2 * 1024**3, f'Packaging target needs2GiB free: {free} bytes')


def check_loader_sources():
    directory = ROOT / '.cache/firmware-components/DarwinBoot/DarwinBootPkg/Driver'
    for name, expected in LOADER_SOURCES.items():
        require(sha(directory / name) == expected, 'Retained loader source changed: ' + name)
    firmware = ROOT.parent / 'uefi-pdx234'
    require(sha(firmware / 'Platforms/Sony/pdx234Pkg/Drivers/PdxConfigFsDxe/PdxConfigFs.c') == FIRMWARE_SOURCE_SHA,
            'Retained128MiB firmware decoder source changed')
    require(sha(firmware / 'BootShim/Pdx234Combo.S') == SHIM_SOURCE_SHA, 'Qualified original BootShim source changed')


def baseline(release):
    _, prior = receipt(release / 'release.json')
    require(prior['label'] == 'PAC-ABI-068' and prior['sha256'] == BASELINE_IMAGE_SHA,
            'Exact actually delivered068 required')
    original = BootTransport(release / Path(prior['image']).name, BASELINE_IMAGE_SHA)
    require(len(original.raw) == prior['bytes'] and len(original.raw) <= BOOT_BYTES,
            'Baseline size/boot capacity differs')
    require(digest(original.android) == prior['original_android_sha256'] and
            digest(original.fd) == prior['firmware_sha256'] == FIRMWARE_SHA and
            digest(original.get(PREFIX + 'Payloads/kernel.macho')) == prior['payload_kernel_sha256'] == KERNEL_SHA,
            'Original068 firmware/Android/kernel identity differs')
    require(prior['gpu_enabled'] is True and prior['cdc_disabled'] is True and
            prior['xnu_cdc_enabled'] is False, 'CDC-off/GPU-on baseline required')
    require(digest(original.fat) == prior['payload_sha256'] and digest(original.blob) == prior['bundle_sha256'],
            'Actual068 FAT/bundle receipt differs')
    require(not prior['strict_missing'] and not prior['strict_stubbed'] and not prior['allow_missing'],
            'Incomplete baseline strict qualification')
    check_loader_sources()
    firmware = load('package069_firmware', '../check-firmware-services.py')
    files = firmware.volume_files(original.fd)
    require('9eb02581-63fc-44ee-a820-49ced6493f12' not in files, 'UEFI CDC driver present')
    service = uuid.UUID('765f0768-b70e-43cc-917d-8f213169dc42').bytes_le
    require(not any(service in data for sections in files.values() for kind, data in sections if kind == 0x10),
            'UEFI CDC consumer present')
    pe = next(data for kind, data in files['1b64af87-8415-4b57-9b16-680d70913b9f'] if kind == 0x10)
    actual_loader = loader_guard(pe)
    require(original.get(PREFIX + 'Payloads/scratch-data.img')[:8] == b'DBRDISK1', 'Missing packed pristine seed')
    config = tomllib.loads(original.get(PREFIX + 'unixnu.toml').decode())
    require(config['ui']['title'] == prior['menu_title'] and
            next(e for e in config['entry'] if e['id'] == 'xnu')['args'] == prior['kernel_args'],
            'Actual068 configuration differs from release')
    return original, prior, actual_loader


def validate_native(native_dir, strict_dir, verification_path, linked_path, prior):
    _, native = receipt(native_dir)
    _, strict = receipt(strict_dir)
    _, kernel = receipt(strict_dir / 'kernel.json')
    _, verification = receipt(verification_path)
    _, linked = receipt(linked_path)
    require(sha(native_dir / 'native.macho') == native['native_sha256'] == strict['native_sha256'] and
            sha(strict_dir / 'kernel.macho') == strict['candidate_sha256'] == kernel['candidate_sha256'],
            'Final native/strict binary hashes disagree')
    require(Path(native['native']).resolve() == (native_dir / 'native.macho').resolve() and
            Path(strict['candidate']).resolve() == (strict_dir / 'kernel.macho').resolve(),
            'Native/strict receipts name different binary paths')
    require(not kernel['missing'] and not kernel['stubbed'] and kernel['allow_missing'] is False and
            kernel['candidate_written'] is True and not strict['strict_missing'] and not strict['strict_stubbed'] and
            strict['allow_missing'] is False and strict['pac_enabled'] is True and
            strict['pac_metadata_adapters'] is False and strict['auth_instruction_patches'] is False,
            'Complete strict PAC-preserving collection required')
    require(native['physical_068_derived'] is True and native['virtual_backends_selected'] is False and
            native['device_operations'] is False and native['pac_authentication_retained'] is True and
            native['auth_instruction_patches'] is False, 'Physical068 source route with native PAC required')
    validate_overlays(native, sha)
    for key in ('display_source', 'gpu_source', 'boot_screen'):
        require(native[key] == strict[key] and sha(native[key]['archive']) == native[key]['sha256'],
                'Actual selected archive differs: ' + key)
    profile = strict['selected_profile']
    require(profile['roots'] == prior['selected_profile']['roots'] and len(profile['roots']) == 19 and
            sha(profile['path']) == profile['sha256'] == prior['selected_profile']['sha256'] and
            len(kernel['closure']) == 38, 'Full D27/security profile reduced or changed')
    for record in (verification, linked):
        require(record['passed'] is True and record['native_sha256'] == native['native_sha256'] and
                record['strict_sha256'] == strict['candidate_sha256'] and record['device_operations'] is False and
                bool(record['implementations']), 'Final instruction/linked verification receipt differs')
        for row in record['implementations'].values():
            require(sha(row['disassembly']) == row['disassembly_sha256'], 'Disassembly receipt changed')
    require(tuple(verification[key] for key in ('full_profile_roots', 'closure_entries',
            'matching_personalities', 'original_kmod_pac_fields')) == (19, 38, 32, 36) and
            verification['virtual_backends_selected'] is False and verification['rw_nx'] is True and
            verification['zero_fill_verified'] is True, 'Incomplete full-profile/physical instruction audit')
    block = verification['block_descriptor_abi']
    require(block['passed'] is True and block['recompiled_objects'] == 66 and block['tamper_rejected'] is True and
            block['authenticated_copy_and_resign'] is True and block['old_runtime_data_abort_reproduced'] is True and
            sha(block['runtime_tests_receipt']) == block['runtime_tests_sha256'], 'Complete real Blocks PAC regression required')
    require(linked['actual_signed_blocks_inputs_verified'] == 66 and linked['all_baseline_members_preserved'] is True and
            linked['actual_startup_branch_targets_verified'] is True and bool(linked['actual_call_edges']) and
            linked['radio_pac_slots'] == 928 and sha(linked['requirements']) == linked['requirements_sha256'],
            'Actual069 startup/radio/archive/Blocks linked audit required')
    require(linked['qca_startup_records_per_image'] == 5 and
            all(len(linked['radio_startup'][name]['radio_records']) == 5 and
                linked['radio_startup'][name]['actual_sort_stride'] == 24 and
                linked['radio_startup'][name]['actual_sort_compares_subsystem_rank'] is True
            for name in ('native', 'strict')), 'Complete native/strict Qca startup records required')
    require('radio' in linked['abi'] and
            sum(row['slots'] for name, row in linked['pac_tables'].items() if name.startswith('radio:')) == 928,
            'Final selected radio PAC tables do not contain exactly928 qualified slots')
    requirements = json.loads(Path(linked['requirements']).read_text())
    for path, expected in requirements['inputs'].items():
        require(sha(path) == expected, 'Final linked requirement input changed: ' + path)
    for name, slots in (('touch', 207), ('buttons', 207), ('oled', 168)):
        require(linked['pac_tables'][name]['slots'] == slots and name in linked['abi'],
                'Missing complete native PAC ABI: ' + name)
    require(len(set(strict['original_kmod_fields_verified'])) == len(strict['original_kmod_fields_verified']) == 36 and
            strict['expanded_native_data']['rw_nx'] is True and strict['expanded_native_data']['zero_fill_verified'] is True and
            strict['expanded_native_data']['all_native_fixups_verified'] > 0, 'Original kmod/RW-NX/fixup qualification missing')
    require(native['sony_touch']['temporary_probes_removed'] is True and
            verification['sony_touch']['temporary_probes_removed'] is True and
            verification['sony_touch']['hid_pac_slots'] == 207, 'Touch cleanup/ABI changed')
    return native, strict, verification, linked


def validate_policy(path, probe, base_arguments=None):
    if path is None:
        require(probe, 'Production requires an explicit reviewed069 policy')
        return {'argument_changes': {}, 'feature_status': {}}
    _, policy = receipt(path)
    require(policy.get('baseline_image_sha256') == BASELINE_IMAGE_SHA and bool(policy.get('inputs')),
            'Policy must bind exact068 and nonempty reviewed inputs')
    for filename, expected in policy['inputs'].items():
        require(sha(filename) == expected, 'Reviewed policy input changed: ' + filename)
    require(set(policy['feature_status']) == FEATURES, 'Explicit per-feature069 status required')
    for name, status in policy['feature_status'].items():
        require(isinstance(status.get('implemented'), bool) and status.get('hardware_verified') is False and
                bool(status.get('limits')), 'Unqualified069 feature claim: ' + name)
    if not probe:
        require(base_arguments is not None, 'Production policy validation needs exact068 arguments')
        updated_arguments(base_arguments, policy['argument_changes'])
    return policy


def validate_skip(path, original, prior):
    _, seed = receipt(path)
    normal = original.get(PREFIX + 'Payloads/scratch-data.img')
    require(digest(normal) == prior['volatile_seed']['seed_sha256'] == PRISTINE_SEED_SHA and
            prior['volatile_seed']['persistence_mode'] == 0 and prior['volatile_seed']['apfsck_passed'] is True and
            prior['volatile_seed']['nodes_bytes_uid_gid_modes_mtime_symlinks_xattrs_verified'] is True,
            'Pristine qualified068 volatile seed required')
    require(seed['passed'] is True and seed['skip_setup'] is True and sha(seed['seed']) == seed['sha256'] and
            seed['sha256'] != PRISTINE_SEED_SHA and
            seed['source_seed_sha256'] == PRISTINE_SEED_SHA and sha(seed['source_seed']) == PRISTINE_SEED_SHA and
            seed['logical_bytes'] == 2 * 1024**3 and seed['build'] == BUILD and seed['no_auto_dim'] is False and
            seed['uuid_preserved'] is True and seed['apfsck_passed'] is True and seed['uid_gid_mode_verified'] is True and
            seed['unrelated_file_bytes_preserved'] is True and seed['original_source_unchanged'] is True and
            seed['activation_record_or_server_modified'] is False and seed['device_operations'] is False,
            'Qualified optional Skip Setup seed required')
    require(seed['official_preferences'] == official_values(seed['official_tool'], no_auto_dim=False) and
            set(seed['changed_files']) == {'./mobile/Library/Preferences/' + name + '.plist' for name in PREFERENCES},
            'Skip Setup must contain exactly the official five preference changes')
    for key in ('container_uuid', 'volume_uuid'):
        require(uuid.UUID(seed[key]) == uuid.UUID(prior['volatile_seed'][key]), 'Seed UUID changed: ' + key)
    require(seed['encoded_bytes'] == Path(seed['seed']).stat().st_size and
            Path(seed['seed']).read_bytes()[:8] == b'DBRDISK1' and
            struct.unpack_from('<Q', normal, 16)[0] == seed['logical_bytes'], 'Packed seed capacity/encoding differs')
    return seed


def validate_seed_tests(path, seed_sha, native=None):
    _, test = receipt(path)
    require(test['passed'] is True and test['seed_sha256'] == seed_sha and test['logical_bytes'] == 2 * 1024**3 and
            test['persistence_required'] is False and test['device_operations'] is False and
            test['sanitizers'] == ['address', 'undefined'], 'Actual2GiB sparse import/boundary regression required')
    for source, expected in test['sources'].items():
        require(sha(source) == expected, 'Tested sparse source changed: ' + source)
    if native is not None:
        # Other libShengUfs members change in069; the actual RAM-block member
        # must still be the tested object, rather than comparing whole archives.
        matches = []
        command = json.loads(Path(native['native']).with_name('native-link.command.json').read_text())
        for token in command:
            if token.startswith('-Wl,-force_load,') and Path(token.removeprefix('-Wl,-force_load,')).name == 'libShengUfs.a':
                archive = token.removeprefix('-Wl,-force_load,')
                matches.append(digest(run(['llvm-ar', 'p', archive, 'NativeRamBlock.late.o'], timeout=30)))
        require(matches == [test['actually_linked_ramblock_object_sha256']], 'Final selected sparse RAM-block object differs')
    return test


def validate_adt(path, original, explicit=None):
    _, record = receipt(path)
    if isinstance(record.get('adt'), dict):
        require(record['passed'] is True and record['host_only'] is True and record['device_operations'] is False,
                'Unqualified combined radio ADT receipt')
        record = record['adt']
    from platform069.radio_adt import overlay_adt, verify_inputs
    expected, _ = overlay_adt(original.get(PREFIX + 'Payloads/kernel.macho.adt'))
    output = Path(record.get('output') or record.get('adt') or '')
    output_sha = record.get('output_sha256') or record.get('adt_sha256') or record.get('sha256')
    if explicit is not None:
        require(explicit.resolve() == output.resolve(), 'Explicit ADT and receipt source path differ')
    require(record['passed'] is True and record['host_only'] is True and record['device_operations'] is False and
            record['readback_matches_overlay'] is True and record['inputs'] == verify_inputs() and
            output.read_bytes() == expected and sha(output) == output_sha,
            'Qualified exact Sony069 ADT overlay required')
    return dict(record, output=str(output), output_sha256=output_sha)


def validate_runtime(path, original, prior, work):
    _, runtime = receipt(path)
    old_addon = original.get(PREFIX + 'Payloads/kernel.macho.gpuaddon')
    old_trust = original.get(PREFIX + 'Payloads/kernel.macho.trustcache')
    require(runtime['target'] == 'arm64e-apple-ios27.0' and runtime['signature_pages_verified'] is True and
            runtime['original_trust_modules_unchanged'] is True and runtime.get('device_operations', False) is False,
            'Final merged runtime signature/trust provenance differs')
    for key, expected in (('baseline_image_sha256', BASELINE_IMAGE_SHA),
                          ('source_addon_sha256', digest(old_addon)), ('source_trust_sha256', digest(old_trust))):
        if key in runtime:
            require(runtime[key] == expected, 'Runtime baseline provenance differs: ' + key)
    plan = None
    if 'plan' in runtime:
        require(sha(runtime['plan']) == runtime['plan_sha256'], 'Reviewed runtime plan hash differs')
        _, plan = receipt(Path(runtime['plan']))
        require(plan['baseline_image_sha256'] == BASELINE_IMAGE_SHA, 'Runtime plan baseline differs')
        for filename, expected in plan['inputs'].items():
            require(sha(filename) == expected, 'Reviewed runtime input changed: ' + filename)
    for name in ('addon', 'trust'):
        require(sha(runtime[name]) == runtime[name + '_sha256'], 'Runtime bytes differ: ' + name)
    before = decode(old_addon)
    after = decode(Path(runtime['addon']).read_bytes())
    expected = {row['path']: row for row in runtime['files']}
    require(len(expected) == len(runtime['files']) and set(expected) == set(after), 'Addon inventory differs')
    changed = {name for name in set(before) | set(after) if before.get(name) != after.get(name)}
    allowed = {row['path'] for row in plan['files']} if plan else set(runtime['changed_or_added_files'])
    require(not set(before) - set(after) and set(runtime['changed_or_added_files']) == allowed and changed == allowed,
            'Unreviewed runtime delta or absent reviewed replacement')
    if plan:
        for row in plan['files']:
            name = row['path']
            require(name in after and sha(row['source']) == row['sha256'] == digest(after[name]['data']) and
                    row['mode'] == after[name]['mode'], 'Runtime differs from selected plan file: ' + name)
    new_macho = set()
    for name, row in after.items():
        require((len(row['data']), digest(row['data']), row['mode']) ==
                (expected[name]['bytes'], expected[name]['sha256'], expected[name]['mode']), 'Addon file differs: ' + name)
        target = work / 'signature-check' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(row['data'])
    trust = Path(runtime['trust']).read_bytes()
    modules = trust_modules(trust)
    old_modules = trust_modules(old_trust)
    require(modules[:len(old_modules)] == old_modules, 'An original068 trust module changed')
    trusted = {m[at:at + 20].hex() for m in modules for at in range(24, len(m), 24)}
    stage = work / 'signature-check'
    selected_cdhashes = []
    for name, target in (('plugin', stage / 'addons/NativeAdrenoMetal.bundle'),
                         ('turnip', stage / 'addons/NativeAdrenoMetal.bundle/libvulkan_freedreno.dylib')):
        actual = inspect_signature(target)
        actual.pop('entitlements')
        require(actual == runtime['signature_checks'][name] == prior['metal_runtime']['signature_checks'][name] and
                actual['cdhash'] in trusted, 'Qualified Metal identity differs: ' + name)
        selected_cdhashes.append(actual['cdhash'])
    extra = runtime.get('extra_signature_checks', {})
    old_macho = {name for name, row in before.items() if row['data'][:4] == b'\xcf\xfa\xed\xfe'}
    for name, row in after.items():
        if row['data'][:4] != b'\xcf\xfa\xed\xfe':
            continue
        if name in old_macho and row == before[name]:
            continue  # The exact068 bundle/code pages were independently checked above.
        new_macho.add(name)
        require(name in extra, 'Unsigned or unreviewed new Mach-O: ' + name)
        actual = inspect_signature(stage / name)
        entitlements = actual.pop('entitlements')
        if 'entitlements_sha256' in extra[name]:
            actual['entitlements_sha256'] = digest(entitlements)
        require(all(actual.get(key) == value for key, value in extra[name].items()) and
                actual['verified_code_pages'] > 0 and actual['cdhash'] in trusted,
                'Signed runtime/trust identity differs: ' + name)
        selected_cdhashes.append(actual['cdhash'])
    require(set(extra) == new_macho, 'Extra-signature inventory differs from actual new Mach-O files')
    if 'xpc/launchd.plist' in after or 'xpc/launchd.plist.sig' in after:
        from platform069.launchd_cache import inspect_detached_signature
        require('xpc/launchd.plist' in after and 'xpc/launchd.plist.sig' in after,
                'Detached launchd cache and signature must be staged together')
        cache_bytes = after['xpc/launchd.plist']['data']
        signature_bytes = after['xpc/launchd.plist.sig']['data']
        actual = inspect_detached_signature(cache_bytes, signature_bytes,
            'launchd-' + hashlib.sha1(cache_bytes).hexdigest())
        checks = runtime.get('detached_signature_checks', {})
        require(set(checks) == {'xpc/launchd.plist'} and actual['cdhash'] in trusted,
                'Detached cache CodeDirectory is absent from trust or inventory')
        row = checks['xpc/launchd.plist']
        require(row.get('cdhash') == actual['cdhash'] and
                all(actual.get(key) == row[key] for key in actual.keys() & row.keys()) and
                row.get('signature_path') == 'xpc/launchd.plist.sig' and
                row.get('data_sha256') == digest(cache_bytes) and row.get('signature_sha256') == digest(signature_bytes),
                'Detached signature receipt differs from actual final cache/signature')
        selected_cdhashes.append(actual['cdhash'])
    else:
        raise ValueError('Required launchd cache and detached signature are missing')
    require(trust == append_trust(old_trust, selected_cdhashes),
            'Appended trust contents are not exactly the concretely verified owner identities')
    firmware = runtime.get('radio_firmware')
    require(isinstance(firmware, dict) and firmware.get('phone_hashes_matched') is True and
            isinstance(firmware.get('files'), dict) and len(firmware['files']) == 53,
            'Complete phone-hash-matched 53-file Sony radio firmware manifest required')
    for name, item in firmware['files'].items():
        require(name.startswith('firmware/') and name in after and
                (len(after[name]['data']), digest(after[name]['data']), after[name]['mode']) ==
                (item['bytes'], item['sha256'], 0o644), 'Captured Sony firmware addon member differs: ' + name)
    runtime.update(baseline_image_sha256=BASELINE_IMAGE_SHA, source_addon_sha256=digest(old_addon),
        source_trust_sha256=digest(old_trust), all068_trust_modules_retained=True, device_operations=False)
    return runtime


def inventory(fat):
    listing = run(['mdir', '-a', '-/', '-b', '-i', fat, '::/'], timeout=30).decode()
    result = {}
    for name in listing.splitlines():
        name = name.strip()
        if not name or name.endswith('/'):
            continue
        require(name.startswith('::/'), 'Unexpected FAT listing path')
        key = name[3:]
        require(key not in result and '..' not in key.split('/'), 'Ambiguous FAT inventory')
        data = run(['mtype', '-i', fat, name], timeout=30)
        result[key] = dict(bytes=len(data), sha256=digest(data))
    require(PREFIX + 'unixnu.toml' in result, 'Incomplete full FAT inventory')
    return result


def fat_capacity(fat):
    data = fat.read_bytes()
    require(1024**2 <= len(data) <= FAT_LIMIT and data[510:512] == b'\x55\xaa', 'Retained firmware FAT size/signature bound')
    bps = struct.unpack_from('<H', data, 11)[0]
    spc, nf = data[13], data[16]
    reserved, roots, fs = (struct.unpack_from('<H', data, at)[0] for at in (14, 17, 22))
    total = struct.unpack_from('<H', data, 19)[0] or struct.unpack_from('<I', data, 32)[0]
    require(bps == 512 and nf == 2 and spc in (1, 2, 4, 8, 16) and fs > 0 and total * bps == len(data),
            'Expected bounded FAT16 geometry')
    clusters = (total - reserved - nf * fs - (roots * 32 + bps - 1) // bps) // spc
    require(4085 <= clusters < 65525 and (clusters + 2) * 2 <= fs * bps, 'FAT16 table capacity differs')
    table = data[reserved * bps:(reserved + fs) * bps]
    require(table == data[(reserved + fs) * bps:(reserved + 2 * fs) * bps], 'FAT mirrors differ')
    free = sum(struct.unpack_from('<H', table, cluster * 2)[0] == 0 for cluster in range(2, clusters + 2))
    return dict(fat_bytes=len(data), retained_firmware_limit_bytes=FAT_LIMIT, cluster_bytes=bps * spc,
                data_clusters=clusters, free_clusters=free, free_bytes=free * bps * spc)


def capacity_failure(work, kind, details):
    value = dict(details)
    value.update(passed=False, capacity_failure=kind, device_operations=False,
        safe_options=['Use an explicitly reviewed larger FAT no greater than134217728 bytes if only FAT allocation fails.',
                      'If compressed96MiB capacity fails, qualify a lossless runtime/compression change against the unchanged firmware and retry.',
                      'Changing the retained firmware/transport or partition layout is a separate material change; do not do it implicitly.'],
        features_or_safety_checks_removed=False, production_image_created=False)
    save(work / ('capacity-failure-' + kind + '.json'), value)
    raise ValueError(kind + ' capacity exceeded: ' + json.dumps(details, sort_keys=True))


def build_fat(original, replacements, work, fat_mib=None):
    fat = work / 'payload.fat'
    with fat.open('xb') as stream:
        stream.write(original.fat)
    before = inventory(fat)
    old_capacity = fat_capacity(fat)
    if fat_mib is not None and fat_mib * 1024**2 != len(original.fat):
        require(len(original.fat) < fat_mib * 1024**2 <= FAT_LIMIT, 'Explicit FAT growth must fit unchanged firmware128MiB bound')
        with fat.open('wb') as stream:
            stream.truncate(fat_mib * 1024**2)
        run(['mformat', '-i', fat, '-v', 'PDX234XNU', '-N', '0x534F4E59', '-T', str(fat_mib * 2048), '::'], work / 'mformat.log')
        run(['mmd', '-i', fat, '::/EFI', '::/EFI/UniXNU', '::/EFI/UniXNU/Payloads'])
        for name, row in before.items():
            if name in replacements:
                continue
            target = work / 'retained-files' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(original.get(name))
            os.utime(target, (315532800, 315532800))
            run(['mcopy', '-m', '-i', fat, target, '::/' + name])
    else:
        # Free every replaced file before inserting any larger replacement.
        for name in replacements:
            if name in before:
                run(['mdel', '-i', fat, '::/' + name])
    available = fat_capacity(fat)
    cluster = available['cluster_bytes']
    needed = sum((path.stat().st_size + cluster - 1) // cluster * cluster for path in replacements.values())
    details = dict(baseline=old_capacity, available_after_replacement_deletion=available,
        replacement_file_bytes=sum(path.stat().st_size for path in replacements.values()),
        replacement_cluster_bytes=needed, minimum_shortfall_bytes=max(0, needed - available['free_bytes']),
        explicit_fat_mib=fat_mib, replacement_sizes={name: path.stat().st_size for name, path in replacements.items()})
    save(work / 'fat-capacity-preflight.json', details)
    if needed > available['free_bytes']:
        capacity_failure(work, 'fat', details)
    for i, (name, source) in enumerate(replacements.items()):
        # Never alter timestamps on another owner's qualified source artifact.
        staged = work / 'fat-inputs' / name
        staged.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, staged)
        os.utime(staged, (315532800, 315532800))
        run(['mcopy', '-m', '-i', fat, staged, '::/' + name], work / f'mcopy-{i:02}.log')
    run(['fsck.fat', '-v', '-n', fat], work / 'fat-fsck.log')
    after = inventory(fat)
    expected = dict(before)
    for name, source in replacements.items():
        expected[name] = dict(bytes=source.stat().st_size, sha256=sha(source))
    require(after == expected, 'Unexpected full FAT file content/inventory delta')
    changed = sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name))
    report = dict(passed=True, before=before, after=after, changed=changed, final_capacity=fat_capacity(fat),
        unchanged_files_preserved=True, full_root_inventory=True, fsck_read_only=True,
        fat_resized=len(original.fat) != fat.stat().st_size)
    save(work / 'payload-files.json', report)
    return fat, report


def request_check(fat, arguments, work, name):
    stage = work / name
    stage.mkdir()
    config_bytes = run(['mtype', '-i', fat, '::/' + PREFIX + 'unixnu.toml'])
    config = stage / 'unixnu.toml'
    config.write_bytes(config_bytes)
    choices = validate_choices(tomllib.loads(config_bytes.decode()), arguments)
    expected = {}
    for entry in tomllib.loads(config_bytes.decode())['entry']:
        if entry.get('type') != 'xnu':
            continue
        data = run(['mtype', '-i', fat, '::/' + PREFIX + entry['initrd']])
        require(data[:8] == b'DBRDISK1' and struct.unpack_from('<Q', data, 16)[0] == 2 * 1024**3,
                'Actual selected seed is not a packed2GiB image')
        target = stage / entry['initrd']
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        expected[entry['id']] = digest(data)
    run([sys.executable, '-B', ROOT / 'scripts/ci/check-darwinboot-request.py', '--out', stage / 'request',
         '--config', config, '--payload-root', stage], stage / 'request.log', timeout=90)
    record = json.loads((stage / 'request/result.json').read_text())
    entries = {entry['id']: entry for entry in record['entries']}
    require(record['passed'] is True and entries.keys() == expected.keys() and
            record['config']['sha256'] == digest(config_bytes), 'Missing or wrong actual menu request checks')
    for key, expected_sha in expected.items():
        row = entries[key]
        require(row['seed_sha256'] == expected_sha and row['logical_bytes'] == 2 * 1024**3 and row['packed'] is True and
                row['validation'] == choices[key] and row['copied_command_line_sha256'] == choices[key]['sha256'] and
                row['arguments_and_selected_seed_tested_together'] is True,
                'Actual configuration/seed request receipt differs: ' + key)
    require({Path(path).name: value for path, value in record['production_source'].items()} == LOADER_SOURCES,
            'Request fixture did not execute the retained loader sources')
    return dict(receipt=str(stage / 'request/result.json'), sha256=sha(stage / 'request/result.json'), entries=entries)


def compressed_capacity(original, fat, work):
    # Same exact compression/header/footer/alignment as pack_transport, without
    # constructing or naming a production boot image in probe mode.
    data = fat.read_bytes()
    packed = bytearray(lzma.compress(data, format=lzma.FORMAT_ALONE, preset=6))
    packed[5:13] = struct.pack('<Q', len(data))
    blob = struct.pack('<8s4IQ', b'PDXFAT02', 32, len(packed), len(data), zlib.crc32(data), 0) + packed
    (work / 'capacity-probe.bundle').write_bytes(blob)
    prop = packed[0]
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[dict(id=lzma.FILTER_LZMA1,
        dict_size=struct.unpack_from('<I', packed, 1)[0], lc=prop % 9, lp=(prop // 9) % 5, pb=prop // 45)])
    decoded = decoder.decompress(packed[13:], max_length=len(data) + 1)
    require(decoded == data and decoder.eof and not decoder.unused_data and
            zlib.crc32(decoded) == struct.unpack_from('<I', blob, 20)[0], 'Raw LZMA/CRC probe roundtrip differs')
    old = struct.unpack('<8sIIQQQIIQQQQ', original.combo[-80:])
    bundle_at = old[-2]
    combo_bytes = bundle_at + ((len(blob) + 7) & -8) + 80
    final_bytes = 4096 + ((combo_bytes + 4095) & -4096)
    report = dict(passed=final_bytes <= BOOT_BYTES, fat_bytes=len(data), bundle_bytes=len(blob),
        bundle_sha256=digest(blob), combo_bytes=combo_bytes, final_image_bytes=final_bytes,
        boot_partition_bytes=BOOT_BYTES, free_bytes=BOOT_BYTES - final_bytes,
        shortfall_bytes=max(0, final_bytes - BOOT_BYTES), firmware_bytes=len(original.fd),
        android_bytes=len(original.android), retained_transport_bundle_offset=bundle_at,
        compression='FORMAT_ALONE preset6 with exact logical-size field; PDXFAT02 CRC32',
        raw_lzma_crc_roundtrip_verified=True, no_production_image_created=True)
    save(work / 'compressed-capacity.json', report)
    if final_bytes > BOOT_BYTES:
        capacity_failure(work, 'boot96mib', report)
    return report


def pack_transport_bounded(original, fat, work):
    """Reuse 068's wrapper recipe with a deadline for each external tool."""
    transport = load('package069_transport', 'package-d27-metal-refresh.py')
    helpers = load('package069_helpers', 'package-d27-reviewed-native.py')

    def run_tool(command, *, check):
        require(check is True, 'BootShim tool must be checked')
        run(command, work / f'combo-{command[0]}.log', timeout=60)

    # Override only this private import's runner, never the subprocess module.
    transport.subprocess = SimpleNamespace(run=run_tool)
    image, blob, commands = transport.pack_transport(original.baseline_dict(), fat.read_bytes(), work, helpers)
    combo_end = 4096 + struct.unpack_from('<I', image, 8)[0]
    require(len(image) % 4096 == 0 and 0 <= len(image) - combo_end < 4096 and not any(image[combo_end:]),
            'BootShim final image alignment/padding differs')
    return image, blob, commands


def kernel_payload(strict_dir, arguments, work, expected_probe_sha=None):
    run([sys.executable, '-B', ROOT / 'scripts/ci/verify-d27-sdt.py', '--strict', strict_dir,
         '--out', work / 'sdt-verified.json'], work / 'sdt.log', timeout=180)
    kernel = work / 'kernel.macho'
    shutil.copyfile(strict_dir / 'kernel.macho', kernel)
    mainline = BASE / 'sources/UniXNU'
    if expected_probe_sha is not None:
        require(sha(mainline / 'scripts/patch-xnu-entry-probe.py') == expected_probe_sha,
                'Original error-screen renderer changed')
    run([sys.executable, '-B', ROOT / 'scripts/patch-panic-screen.py', '--kernel', kernel,
         '--mainline', mainline, '--uefi', ROOT.parent / 'uefi-pdx234', '--preserve-auth'],
        work / 'panic.log', timeout=180)
    panic = json.loads((work / 'kernel.panic-screen.json').read_text())
    require(panic['source_kernel_sha256'] == sha(strict_dir / 'kernel.macho') and
            panic['patched_kernel_sha256'] == sha(kernel) and panic['panic_screen'] is True and
            panic['auth_instructions_preserved'] is True and panic['no_reset'] is True and
            len(panic['panic_hooks']) == 2 and panic['diagnostic_padding']['original_bytes_zero'] is True,
            'Auth-preserving original error-screen fallback required')
    if expected_probe_sha is not None:
        require(panic['official_probe_sha256'] == expected_probe_sha, 'Original error-screen renderer changed')
    before = kernel.read_bytes()
    seal_script = mainline / 'scripts/seal-source-crypto-kernel.py'
    require(sha(seal_script) == 'b8f304c8d88ffa3f49277f407d1aa72734944cacd59c58d010609744af24c0a3' and
            sha(seal_script.with_name('kernel_target.py')) == 'f2351aebc029a69673ead76e1a0b49845fd940e285da82cd693a89084991c4bf',
            'Normal qualified XNU crypto seal tooling changed')
    env = dict(os.environ, UNIXNU_XNU_ARCH='arm64e', UNIXNU_IOS_VERSION='27.0', PYTHONDONTWRITEBYTECODE='1')
    with (work / 'seal.log').open('xb') as stream:
        subprocess.run([sys.executable, '-B', str(seal_script),
            str(kernel), '--kernel-args', arguments], env=env, stdout=stream, stderr=subprocess.STDOUT,
            check=True, timeout=120)
    seal = json.loads((work / 'kernel.macho.crypto-hmac.json').read_text())
    after = kernel.read_bytes()
    require(seal['kernel_sha256'] == digest(after) and seal['static_if_sites_prepatched'] == 0 and len(before) == len(after),
            'Normal XNU crypto seal identity/static_if contract differs')
    at = int(seal['hmac_file_offset'], 16)
    code = int(seal['code_file_offset'], 16)
    size = seal['code_bytes']
    require(0 <= at <= len(after) - 32 and 0 <= code < code + size <= len(after) and
            before[:at] == after[:at] and before[at + 32:] == after[at + 32:] and
            after[at:at + 32] == hmac.digest(b'\0', after[code:code + size], 'sha256') and
            after[at:at + 32].hex() == seal['hmac_sha256'], 'Sealing changed anything outside the normal POST HMAC field')
    run([sys.executable, '-B', ROOT / 'scripts/ci/audit-darwinboot-parser.py',
         '--darwinboot', ROOT / '.cache/firmware-components/DarwinBoot', '--kernel', kernel,
         '--report', work / 'darwinboot-parser.json'], work / 'parser.log', timeout=120)
    parser = json.loads((work / 'darwinboot-parser.json').read_text())
    require(parser['accepted'] is True and parser['kernel_sha256'] == digest(after), 'Production Mach-O parser rejected final kernel')
    return kernel, panic, seal


def make_record(prior, original, args, native, strict, verification, linked, skip, runtime, adt, policy,
                arguments, text, kernel, panic, seal, target, image, fat, blob, files, requests):
    record = copy.deepcopy(prior)
    # Keep older facts as inherited history, not claims about the new candidate.
    history = {key: record.pop(key) for key in list(record) if key.startswith('historical') or key.startswith('platform067_') or
               key in ('darwinboot_args_fix', 'metadata_normalization_history067', 'menu_qemu_receipt', 'menu_qemu_receipt_sha256')}
    record.update(historical068_metadata=history)
    record.update(image=str(target), bytes=len(image), sha256=digest(image), label=f'PAC-ABI-{args.version}',
        source_image_sha256=BASELINE_IMAGE_SHA, source_release=str(args.release.resolve()),
        native_sha256=native['native_sha256'], strict_kernel_sha256=strict['candidate_sha256'],
        payload_kernel_sha256=sha(kernel), payload_sha256=sha(fat), bundle_sha256=digest(blob),
        kernel_args=arguments, screen_build_tag=f'PDX{args.version}', menu_title=tomllib.loads(text)['ui']['title'],
        arguments_removed=sorted(set(prior['kernel_args'].split()) - set(arguments.split())),
        arguments_added=sorted(set(arguments.split()) - set(prior['kernel_args'].split())),
        baseline_arguments_unchanged=False, firmware_only_correction=False,
        cpufreq_mode=int(next(token.split('=', 1)[1] for token in arguments.split() if token.startswith('cpufreq='))),
        software_vsync_hz=int(next(token.split('=', 1)[1] for token in arguments.split() if token.startswith('vsync='))),
        menu_default='xnu', darwinboot_command_line=validate_arguments(arguments),
        darwinboot_requests=requests, platform069=native['platform069'], platform069_policy=policy,
        platform069_feature_status=policy['feature_status'], platform069_abi=linked['abi'],
        platform069_original_kmod_sites=strict['original_kmod_fields_verified'],
        platform069_linked_verification=linked, platform069_linked_verification_receipt=str(args.platform_verification.resolve()),
        platform069_linked_verification_sha256=sha(args.platform_verification),
        handset_instruction_verification=verification, handset_instruction_verification_receipt=str(args.verification.resolve()),
        handset_instruction_verification_sha256=sha(args.verification),
        block_descriptor_abi=verification['block_descriptor_abi'], sony_touch=native['sony_touch'],
        sony_touch_verification=verification['sony_touch'], sony_touch_hid_abi=linked['abi']['touch'],
        expanded_native_data=strict['expanded_native_data'], selected_profile=strict['selected_profile'],
        native_review_receipt=str(args.strict.resolve() / 'result.json'), strict_result_sha256=sha(args.strict / 'result.json'),
        native_result_receipt=str(args.native.resolve() / 'result.json'), native_result_sha256=sha(args.native / 'result.json'),
        display_source=native['display_source'], gpu_source=native['gpu_source'], boot_screen=native['boot_screen'],
        panic_screen=panic, crypto_seal=seal, entry_bars=True, loader_parser_accepted=True,
        auth_instruction_patches=False, pac_metadata_adapters=False,
        firmware_sha256=digest(original.fd), original_android_sha256=digest(original.android),
        baseline_firmware_byte_identity=True, baseline_kernel_byte_identity=False, baseline_adt_unchanged=False,
        adt_sha256=adt['output_sha256'], platform069_adt=adt, metal_runtime=runtime,
        metal_runtime_receipt=str(receipt(args.runtime)[0]), metal_runtime_receipt_sha256=sha(receipt(args.runtime)[0]),
        volatile_seed=prior['volatile_seed'], skip_setup=skip, physical_068_derived=True,
        gpu_enabled=True, cdc_disabled=True, xnu_cdc_enabled=False, uefi_cdc_frontend=False,
        config_fat_roundtrip_verified=True, linux_full_fat_inventory=files,
        first_frame_diagnostics=False, temporary_probe_cleanup=True, device_writes=False,
        image_delivered=False, staging_only=True, ready_for_manual_test=False,
        hardware_boot_verified=False, touch_runtime_verified=False, home_screen_verified=False,
        desktop_verified=False, springboard_verified=False, root_mount_verified=False, gpu_rendering_verified=False,
        platform069_features_hardware_verified=False, windows_independent_verification_pending=True,
        physical_refresh_verified=False, all_requested_features_complete=False,
        correction=f'Host-qualified{args.version} candidate; delivery requires separate main-owned Windows readback',
        firmware_extent=[4096 + 0x200000 + struct.unpack_from('<Q', original.android, 16)[0],
                         4096 + 0x200000 + struct.unpack_from('<Q', original.android, 16)[0] + len(original.fd)])
    for key, value in native.items():
        if key.startswith('platform069_') and key not in record:
            record[key] = value
    record['platform069_receipts'] = {
        key: dict(path=str(path), sha256=sha(path))
        for key, path in [('policy', args.policy), ('runtime', args.runtime), ('adt', args.adt_receipt),
                          ('normal_seed_tests', args.seed_tests), ('skip_seed_tests', args.skip_seed_tests),
                          ('skip_setup', args.skip_setup)]}
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', type=Path, default=ROOT / 'out/d27-pac-abi-release-20261118-068')
    parser.add_argument('--version', choices=('069', '070', '071'), default='069')
    parser.add_argument('--work', type=Path, required=True, help='New private Linux/F artifact directory')
    parser.add_argument('--out', type=Path, help='New final staging directory; forbidden in probe mode')
    parser.add_argument('--capacity-probe', action='store_true', help='068 kernel fixture; no final boot IMG')
    parser.add_argument('--probe-runtime', type=Path, help='Optional final/additive runtime receipt for capacity-only probing; still uses exact068 kernel')
    parser.add_argument('--fat-mib', type=int, choices=(112, 120, 128), help='Explicit reviewed FAT growth only; default preserves068 geometry')
    parser.add_argument('--deadline-seconds', type=int, default=900, choices=range(60, 1801), metavar='60..1800')
    parser.add_argument('--adt-receipt', type=Path, help='Explicit source-qualified radio ADT result.json (required for production)')
    parser.add_argument('--adt', type=Path, help='Optional ADT binary path; must equal the receipt output')
    for key in ('native', 'strict', 'verification', 'platform-verification', 'policy', 'runtime',
                'skip-setup', 'seed-tests', 'skip-seed-tests'):
        parser.add_argument('--' + key, type=Path, required=key == 'skip-setup')
    args = parser.parse_args()
    if args.capacity_probe:
        if args.out or any((args.native, args.strict, args.verification, args.platform_verification,
                            args.seed_tests, args.skip_seed_tests)):
            parser.error('Probe forbids output/native/strict inputs; only delivered068 kernel may be used')
        if args.runtime and args.probe_runtime:
            parser.error('Supply one runtime receipt')
    else:
        if args.probe_runtime:
            parser.error('--probe-runtime is only valid with --capacity-probe; production uses --runtime')
        missing = [key for key in ('out', 'native', 'strict', 'verification', 'platform_verification', 'policy',
                                   'runtime', 'seed_tests', 'skip_seed_tests') if getattr(args, key) is None]
        if args.adt_receipt is None:
            missing.append('adt_receipt')
        if missing:
            parser.error('Production requires: ' + ', '.join('--' + key.replace('_', '-') for key in missing))
    if args.adt is not None and args.adt_receipt is None:
        parser.error('--adt requires --adt-receipt')
    for name in ('verification', 'platform_verification', 'policy', 'runtime', 'probe_runtime',
                 'skip_setup', 'seed_tests', 'skip_seed_tests', 'adt_receipt'):
        path = getattr(args, name)
        if path is not None:
            setattr(args, name, receipt(path)[0])
    require(sys.platform == 'linux', 'Run under WSL UniXNU-Build')
    require(not args.work.exists() and not args.work.is_symlink() and
            (args.out is None or (not args.out.exists() and not args.out.is_symlink())), 'Use new work/output paths')
    if args.out is not None:
        require(not args.out.resolve().is_relative_to(args.work.resolve()) and
                not args.work.resolve().is_relative_to(args.out.resolve()), 'Work/output directories must be disjoint')
    require(args.work.resolve().is_relative_to(ARTIFACTS),
            'Use a new private F:/UniXNU-Port-artifacts/platform069-20261118 work directory')
    if args.out is not None:
        require(args.out.resolve().is_relative_to(ARTIFACTS),
                'All069 package outputs must stay in the authorized F artifact directory')
    check_space(args.work)
    args.work.mkdir(parents=True)
    work = args.work.resolve()
    started = time.monotonic()
    def expired(signum, frame):
        raise TimeoutError('Bounded069 package deadline exceeded')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(args.deadline_seconds)
    try:
        watched = {str(Path(__file__).resolve()): sha(__file__)}
        # Bound mutable orchestration helpers and the final verifier as well as
        # their input receipts. Do not accept another owner's mid-run update.
        paths = ['ci/pdx_boot_transport.py', 'ci/darwin_boot_args.py', 'ci/sony_menu068.py',
                 'ci/platform069/menu.py', 'ci/platform069/skip_setup.py', 'ci/platform069/radio_adt.py',
                 'ci/platform069/addon.py', 'ci/platform069/codesign.py', 'ci/platform069/launchd_cache.py',
                 'scripts/check-firmware-services.py', 'scripts/ci/check-darwinboot-request.py']
        if not args.capacity_probe:
            paths.extend(['ci/platform069/integration.py', 'ci/platform069/overlays.py', 'ci/XnuPrelink/kc_image.py',
                          'scripts/patch-panic-screen.py', 'scripts/ci/verify-delivered-platform069.py',
                          'scripts/ci/verify-d27-sdt.py', 'scripts/ci/audit-darwinboot-parser.py',
                          'scripts/ci/package-d27-reviewed-native.py', 'scripts/ci/package-d27-metal-refresh.py'])
        for filename in paths:
            path = ROOT / filename
            watched[str(path.resolve())] = sha(path)
        for path in (args.release / 'release.json', args.policy, args.runtime, args.probe_runtime, args.adt, args.adt_receipt, args.skip_setup,
                     args.seed_tests, args.skip_seed_tests, args.verification, args.platform_verification):
            if path:
                actual = path / 'result.json' if path.is_dir() else path
                watched[str(actual.resolve())] = sha(actual)
        for folder in (args.native, args.strict):
            if folder:
                for name in ('native.macho', 'native-link.command.json', 'result.json', 'kernel.json', 'kernel.macho'):
                    path = folder / name
                    if path.is_file():
                        watched[str(path.resolve())] = sha(path)
        original, prior, actual_loader = baseline(args.release)
        policy = validate_policy(args.policy, args.capacity_probe, prior['kernel_args'])
        watched.update(policy.get('inputs', {}))
        arguments = updated_arguments(prior['kernel_args'], policy['argument_changes'])
        if args.version != '069':
            arguments = arguments.replace('build-tag=PDX069', f'build-tag=PDX{args.version}', 1)
        text, choices = render(original.get(PREFIX + 'unixnu.toml').decode(), arguments)
        if args.version != '069':
            require(text.count('PAC-ABI-069') == 1, 'Expected exactly one versioned menu title')
            text = text.replace('PAC-ABI-069', f'PAC-ABI-{args.version}', 1)
        skip = validate_skip(args.skip_setup, original, prior)
        native = strict = verification = linked = panic = seal = None
        if not args.capacity_probe:
            native, strict, verification, linked = validate_native(args.native, args.strict,
                args.verification, args.platform_verification, prior)
            version = '071' if native.get('platform069_followup071') else '070' if native.get('platform069_followup070') else '069'
            require(version == args.version, 'Build version and selected follow-up plan disagree')
            require(watched[str((args.native / 'native.macho').resolve())] == native['native_sha256'],
                    'Native changed after snapshot')
            require(watched[str((args.strict / 'kernel.macho').resolve())] == strict['candidate_sha256'],
                    'Strict kernel changed after snapshot')
            validate_seed_tests(args.seed_tests, PRISTINE_SEED_SHA, native)
            skip_test = validate_seed_tests(args.skip_seed_tests, skip['sha256'], native)
            for path, expected in skip_test['sources'].items():
                watched[str(Path(path).resolve())] = expected
            inputs = native['platform069'].get('inputs', {})
            watched.update(inputs)
            requirements = json.loads(Path(linked['requirements']).read_text())
            watched.update(requirements['inputs'])
            kernel, panic, seal = kernel_payload(args.strict, arguments, work, prior['panic_screen']['official_probe_sha256'])
        else:
            kernel = work / 'fixture-delivered068-kernel.macho'
            kernel.write_bytes(original.get(PREFIX + 'Payloads/kernel.macho'))
        config = work / 'unixnu.toml'
        config.write_text(text)
        replacements = {PREFIX + 'unixnu.toml': config, PREFIX + 'Payloads/kernel.macho': kernel,
                        PREFIX + 'Payloads/scratch-data-skip-setup.img': Path(skip['seed'])}
        expected_payload_hashes = {PREFIX + 'unixnu.toml': digest(text.encode()),
            PREFIX + 'Payloads/kernel.macho': KERNEL_SHA if args.capacity_probe else seal['kernel_sha256'],
            PREFIX + 'Payloads/scratch-data-skip-setup.img': skip['sha256']}
        runtime = adt = None
        runtime_path = args.runtime or args.probe_runtime
        if runtime_path:
            runtime = validate_runtime(runtime_path, original, prior, work)
            for field, suffix in (('addon', 'gpuaddon'), ('trust', 'trustcache')):
                name = PREFIX + 'Payloads/kernel.macho.' + suffix
                replacements[name] = Path(runtime[field])
                expected_payload_hashes[name] = runtime[field + '_sha256']
        if args.adt_receipt:
            adt = validate_adt(args.adt_receipt, original, args.adt)
            replacements[PREFIX + 'Payloads/kernel.macho.adt'] = Path(adt['output'])
            expected_payload_hashes[PREFIX + 'Payloads/kernel.macho.adt'] = adt['output_sha256']
        if runtime is not None and runtime.get('plan'):
            watched[str(Path(runtime['plan']).resolve())] = runtime['plan_sha256']
            watched.update(json.loads(Path(runtime['plan']).read_text())['inputs'])
        for name, path in replacements.items():
            watched[str(path.resolve())] = expected_payload_hashes[name]
        fat, files = build_fat(original, replacements, work, args.fat_mib)
        for name, expected in expected_payload_hashes.items():
            require(files['after'][name]['sha256'] == expected, 'FAT did not contain the validated artifact: ' + name)
        staged_requests = request_check(fat, arguments, work, 'fat-readback-requests')
        if args.capacity_probe:
            capacities = compressed_capacity(original, fat, work)
            for path, expected in watched.items():
                require(sha(path) == expected, 'Probe input/helper changed during validation: ' + path)
            report = dict(passed=True, capacity_probe=True, production_image_created=False,
                scope='Delivered068 kernel fixture plus validated final/additive runtime when supplied and actual two069 menu/seed requests; final069 native remains separate',
                baseline_image_sha256=BASELINE_IMAGE_SHA, fixture_kernel_sha256=KERNEL_SHA,
                selected_runtime_sha256=None if runtime is None else runtime['addon_sha256'],
                selected_adt_sha256=None if adt is None else adt['output_sha256'],
                final069_native_verified=False, actual_loader_guard=actual_loader,
                fat=files['final_capacity'], compressed_capacity=capacities, requests=staged_requests,
                kernel_arguments=choices, elapsed_seconds=time.monotonic() - started,
                packager_sha256=sha(__file__), device_operations=False, hardware_verified=False)
            save(work / 'report.json', report)
            print(json.dumps(report, indent=2))
            return
        predicted_capacity = compressed_capacity(original, fat, work)
        image, blob, commands = pack_transport_bounded(original, fat, work)
        capacities = dict(final_image_bytes=len(image), boot_partition_bytes=BOOT_BYTES,
                          free_bytes=BOOT_BYTES - len(image), shortfall_bytes=max(0, len(image) - BOOT_BYTES),
                          bundle_bytes=len(blob), fat=files['final_capacity'])
        save(work / 'final-capacity.json', capacities)
        if len(image) > BOOT_BYTES:
            capacity_failure(work, 'boot96mib', capacities)
        require(len(image) == predicted_capacity['final_image_bytes'] and digest(blob) == predicted_capacity['bundle_sha256'],
                'Bounded BootShim output differs from final compressed size probe')
        require(fat.stat().st_size <= FAT_LIMIT, 'Retained firmware128MiB FAT bound exceeded')
        for path, expected in watched.items():
            require(sha(path) == expected, 'Input/receipt changed during packaging: ' + path)
        check_space(work)
        candidate_dir = work / 'linux-candidate'
        candidate_dir.mkdir()
        target = candidate_dir / f'boot-pdx234-pac-abi-{args.version}.img'
        with target.open('xb') as stream:
            stream.write(image)
        delivered = BootTransport(target, digest(image))
        require(delivered.android == original.android and delivered.fd == original.fd and delivered.fat == fat.read_bytes(),
                'Independent final transport/FAT/Android/FD readback differs')
        expected_header = bytearray(original.raw[:4096])
        struct.pack_into('<II', expected_header, 8, len(delivered.combo), 0)
        struct.pack_into('<I', expected_header, 1580, 0)
        require(delivered.raw[:4096] == expected_header, 'Android header changed beyond combo size/checksum')
        original_footer = struct.unpack('<8sIIQQQIIQQQQ', original.combo[-80:])
        final_footer = struct.unpack('<8sIIQQQIIQQQQ', delivered.combo[-80:])
        require(final_footer[:-1] == original_footer[:-1] and final_footer[-1] == len(blob) and delivered.blob == blob,
                'Final BootShim footer changed outside its compressed bundle extent')
        for name, row in files['after'].items():
            data = delivered.get(name)
            require((len(data), digest(data)) == (row['bytes'], row['sha256']), 'Final IMG full file identity differs: ' + name)
        final_fat = work / 'final-readback.fat'
        final_fat.write_bytes(delivered.fat)
        require(inventory(final_fat) == files['after'], 'Independent final full FAT root inventory differs')
        final_requests = request_check(final_fat, arguments, work, 'final-image-requests')
        require(final_requests['entries'] == staged_requests['entries'], 'Final loaded menu requests changed')
        requests = dict(staged_fat=staged_requests, final_image=final_requests)
        record = make_record(prior, original, args, native, strict, verification, linked, skip, runtime, adt, policy,
            arguments, text, kernel, panic, seal, target, image, fat, blob, files, requests)
        # Main owns the Windows verifier and may still be updating it. Bind the
        # exact source seen above and execute this host check without importing
        # user-provided report/config fields as code.
        verifier_path = ROOT / 'scripts/ci/verify-delivered-platform069.py'
        require(sha(verifier_path) == watched[str(verifier_path.resolve())], 'Final verifier changed before use')
        save(candidate_dir / 'release.json', record)
        run([sys.executable, '-B', verifier_path, '--release', candidate_dir,
             '--baseline', args.release, '--version', args.version, '--out', work / 'independent-linux-verification.json'],
            work / 'independent-linux-verification.log', timeout=240)
        verified = json.loads((work / 'independent-linux-verification.json').read_text())
        require(verified['passed'] is True and verified['image_sha256'] == record['sha256'] and
                verified['bytes'] == record['bytes'] and verified['actual_loader_guard'] == actual_loader,
                'Independent069 Linux readback failed')
        # The source, receipt, runtime and sealed payload must remain stable
        # through *final* request execution and the independent readback.
        for path, expected in watched.items():
            require(sha(path) == expected, 'Input/helper changed before final acceptance: ' + path)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        staging = work / 'delivery-staging'
        staging.mkdir()
        final_target = staging / target.name
        with final_target.open('xb') as stream:
            stream.write(target.read_bytes())
        require(sha(final_target) == record['sha256'] and final_target.stat().st_size == record['bytes'],
                'Final output staging copy differs from independently verified private candidate')
        published_target = args.out.resolve() / target.name
        record['image'] = str(published_target)
        record['linux_verification'] = dict(path=str(work / 'independent-linux-verification.json'),
            sha256=sha(work / 'independent-linux-verification.json'), independently_verified=True)
        save(staging / 'release.json', record)
        (staging / 'SHA256SUMS').write_text(record['sha256'] + '  ' + target.name + '\n')
        require(not args.out.exists(), 'Final output path appeared during packaging')
        os.replace(staging, args.out)
        final_target = published_target
        save(work / 'report.json', dict(passed=True, image=str(final_target), sha256=record['sha256'], bytes=len(image),
            inputs=watched, capacity=capacities, requests=requests, actual_loader_guard=actual_loader,
            firmware_android_identical=True, original_trust_modules_preserved=True, normal_seed_unchanged=True,
            panic_auth_preserved=True, normal_crypto_seal_applied=True, full_fat_inventory_verified=True,
            linux_verification=str(work / 'independent-linux-verification.json'),
            linux_verification_sha256=sha(work / 'independent-linux-verification.json'),
            windows_independent_verification_pending=True, staging_only=True, image_delivered=False,
            commands=commands, elapsed_seconds=time.monotonic() - started, packager_sha256=sha(__file__),
            device_operations=False, hardware_verified=False))
        print(json.dumps(dict(passed=True, image=str(final_target), sha256=record['sha256'], bytes=len(image),
            report=str(work / 'report.json'), windows_independent_verification_pending=True), indent=2))
    except BaseException as error:
        failure = work / 'failure.json'
        if not failure.exists():
            save(failure, dict(passed=False, error_type=type(error).__name__, error=str(error),
                elapsed_seconds=time.monotonic() - started, production_image_accepted=False,
                device_operations=False, hardware_verified=False))
        raise
    finally:
        signal.alarm(0)


if __name__ == '__main__':
    main()
