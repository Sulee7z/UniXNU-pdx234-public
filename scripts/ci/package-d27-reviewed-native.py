#!/usr/bin/env python3
"""Stage053 over052 or055 over054 with explicit screen and Metal receipts."""
import argparse
import contextlib
import copy
import hashlib
import importlib.util
import json
import lzma
import os
from pathlib import Path
import runpy
import shutil
import struct
import subprocess
import sys
import tomllib
import zlib

ROOT = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
BASELINE_SHA = '2f861b5229a10202c160473e2c71b8b2292707207661b34ec4c68e54d2e24263'
BASELINE_054_SHA = '776163aa703020a0188bf879cc53f76e7e79f0c6b42fad5e3b1ab344af7427f1'


def require_space():
    free = shutil.disk_usage(ROOT).free
    if free < 8 * 1024**3:
        raise ValueError(f'Stop: workspace free space below8GiB ({free} bytes)')


def receipt(path):
    path = path / 'result.json' if path.is_dir() else path
    return path.resolve(), json.loads(path.read_text())


def selected_arguments(record, label):
    expected = BASELINE_054_SHA if label == '055' else BASELINE_SHA
    if record['sha256'] != expected or not record.get('gpu_enabled'):
        raise ValueError('Unexpected baseline release identity or GPU policy')
    if label == '055':
        if record.get('cdc_disabled') is not True or record.get('xnu_cdc_enabled') is not False:
            raise ValueError('055 requires CDC disabled in054')
    elif not record.get('usb_core_errors_fixed'):
        raise ValueError('053 requires052 USB core error correction')
    tokens = record['kernel_args'].split()
    for key, value in [('qcom-usb-debug', '0' if label == '055' else '1'),
                       ('gpu-power', '9'), ('gpu-metal', '1'), ('sheng-gpu-addon', '1'),
                       ('fb-gpu', '1'), ('dpu-scanout', '0'),
                       ('build-tag', 'PDX054' if label == '055' else 'PDX051')]:
        if [t for t in tokens if t.startswith(key + '=')] != [key + '=' + value]:
            raise ValueError('Unexpected baseline argument: ' + key)
    old_tag = 'build-tag=PDX054' if label == '055' else 'build-tag=PDX051'
    return ' '.join('build-tag=PDX' + label if t == old_tag else t for t in tokens), old_tag


def trust_modules(data):
    count = struct.unpack_from('<I', data)[0]
    if not 0 < count <= (len(data) - 4) // 4:
        raise ValueError('Invalid trust module count')
    starts = list(struct.unpack_from('<' + str(count) + 'I', data, 4)) + [len(data)]
    if starts[0] < 4 + 4 * count or any(a >= b for a, b in zip(starts, starts[1:])):
        raise ValueError('Invalid trust module offsets')
    modules = [data[a:b] for a, b in zip(starts, starts[1:])]
    for module in modules:
        if len(module) < 24 or struct.unpack_from('<I', module)[0] != 2 or len(module) != 24 + 24 * struct.unpack_from('<I', module, 20)[0]:
            raise ValueError('Invalid version2 trust module')
    return modules


def validate_metal(runtime, baseline_trust):
    if (runtime.get('target') != 'arm64e-apple-ios27.0' or
            runtime.get('original_trust_modules_unchanged') is not True or
            runtime.get('signature_pages_verified') is not True):
        raise ValueError('Metal package lacks signature/original-trust validation')
    for key in ('addon', 'trust'):
        if sha(Path(runtime[key]).read_bytes()) != runtime[key + '_sha256']:
            raise ValueError('Metal package identity changed: ' + key)
    before = trust_modules(baseline_trust)
    after = trust_modules(Path(runtime['trust']).read_bytes())
    # Both packages append one owner module to the original D27 modules.
    if len(before) < 2 or after[:-1] != before[:-1]:
        raise ValueError('Original D27 trust modules changed')
    entries = {after[-1][i:i + 20].hex() for i in range(24, len(after[-1]), 24)}
    for key in ('plugin', 'turnip'):
        check = runtime['signature_checks'][key]
        if check.get('verified_code_pages', 0) <= 0 or check['cdhash'] not in entries:
            raise ValueError('Signed Metal identity absent from appended trust: ' + key)


def fat_inventory(fatfile):
    listing = subprocess.check_output(['mdir', '-/', '-b', '-i', str(fatfile), '::/EFI'], text=True)
    result = {}
    for name in listing.splitlines():
        name = name.strip()
        if not name or name.endswith('/'):
            continue
        data = subprocess.check_output(['mtype', '-i', str(fatfile), name])
        result[name.removeprefix('::/')] = sha(data)
    if 'EFI/UniXNU/unixnu.toml' not in result:
        raise ValueError('Incomplete FAT inventory')
    return result


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def readback(release, log):
    previous = sys.argv
    try:
        sys.argv = ['verify', '--release', str(release)]
        with log.open('x') as stream, contextlib.redirect_stdout(stream):
            return runpy.run_path(str(ROOT / 'scripts/ci/verify-delivered-high-memory.py'))
    finally:
        sys.argv = previous


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', type=Path, required=True)
    parser.add_argument('--strict', type=Path, required=True)
    parser.add_argument('--label', choices=('053', '055'), default='053')
    parser.add_argument('--label055', action='store_const', const='055', dest='label')
    parser.add_argument('--metal-runtime', type=Path, help='Signed package result.json or directory')
    parser.add_argument('--boot-screen', type=Path, help='Updated screen result.json or directory')
    parser.add_argument('--display-source', type=Path, required=True)
    parser.add_argument('--display-tests', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.label == '055' and (not args.metal_runtime or not args.boot_screen):
        parser.error('055 requires --metal-runtime and --boot-screen receipts')
    if args.label == '053' and (args.metal_runtime or args.boot_screen):
        parser.error('Use055 for updated Metal or screen inputs')
    require_space()
    for path in (args.work, args.out):
        if path.exists():
            parser.error('Use a new directory: ' + str(path))
    args.work.mkdir(parents=True)
    work = args.work.resolve()
    baseline = readback(args.release, work / 'baseline-readback.log')
    record = baseline['j']
    new_args, old_tag = selected_arguments(record, args.label)
    baseline_sha = record['sha256']
    strict = json.loads((args.strict / 'kernel.json').read_text())
    provenance = json.loads((args.strict / 'result.json').read_text())
    kernel_bytes = (args.strict / 'kernel.macho').read_bytes()
    if (sha(kernel_bytes) != strict['candidate_sha256'] or sha(kernel_bytes) != provenance['candidate_sha256'] or
            strict['missing'] or strict['stubbed'] or strict['allow_missing'] or not strict['candidate_written'] or
            not provenance['pac_enabled'] or provenance['pac_metadata_adapters'] or provenance['auth_instruction_patches']):
        raise ValueError('Require a complete strict collection preserving PAC')
    display = json.loads((args.display_source / 'result.json').read_text())
    display_verification = json.loads((args.display_source / 'sony-verification.json').read_text())
    display_tests = json.loads((args.display_tests / 'result.json').read_text())
    if (display['archive'] != str((args.display_source / 'build/native-legacy-display/libNativeLegacyDisplay.late.a').resolve()) or
            sha(Path(display['archive']).read_bytes()) != display['sha256'] or
            display['sha256'] != '91d475b07225320a8fd27335a74947b71c5e524137e560a77611512b3c714840' or
            display.get('pac_flag') != '-fptrauth-function-pointer-type-discrimination' or
            display_verification.get('archive_sha256') != display['sha256'] or
            not display_verification.get('dependency_and_object_hashes_valid') or
            not display_verification.get('arm64e_pac_flags_valid') or
            display_tests.get('adapted_gop_sha256') != display['source_overlay']['staged_gop_sha256'] or
            display_tests.get('helper_sha256') != display['source_overlay']['helper_sha256'] or
            display_tests.get('diagnostic_fields') != display['source_overlay']['diagnostic_fields'] or
            display_tests.get('sanitizers') != ['address', 'undefined'] or
            display_tests.get('device_operations') is not False):
        raise ValueError('Unqualified display-source-009 provenance')
    if provenance['display_source'] != display:
        raise ValueError('Strict build did not link the supplied display-source-009 receipt')
    for key in ('gpu_source', 'selected_profile'):
        if provenance[key] != record[key]:
            raise ValueError('Baseline integration input changed: ' + key)
    screen_path = runtime_path = None
    runtime = None
    if args.boot_screen:
        screen_path, screen = receipt(args.boot_screen)
        if (screen != provenance['boot_screen'] or
                sha(Path(screen['archive']).read_bytes()) != screen['sha256'] or
                screen.get('pac_flag') != '-fptrauth-function-pointer-type-discrimination' or
                not screen.get('cached_boot_diagnostics') or not screen.get('sources') or
                not screen.get('diagnostic_headers') or screen.get('device_operations') is not False):
            raise ValueError('Updated boot screen is not the qualified linked archive')
        for source in screen['sources']:
            if sha(Path(source['source']).read_bytes()) != source['sha256']:
                raise ValueError('Screen source changed: ' + source['source'])
        for name, digest in screen.get('diagnostic_headers', {}).items():
            if sha((screen_path.parent / name).read_bytes()) != digest:
                raise ValueError('Screen diagnostic header changed: ' + name)
        screen_verification_path = screen_path.parent / 'verification.json'
        screen_verification = json.loads(screen_verification_path.read_text())
        if (screen['sha256'] != '034aad481f5ff83a08c2b1bad9e4ef0905d38cafbe8d043e2367827b13f04063' or
                screen_verification['build']['sha256'] != screen['sha256'] or
                not screen_verification['build']['headers_verified'] or
                screen_verification['helper_sha256'] != screen['diagnostic_headers']['PdxBootCachedDiagnostics.h'] or
                screen_verification['display_probe_sha256'] != display['staged_probe_sha256']):
            raise ValueError('055 requires tested screen007 with the display009 diagnostic layout')
    elif provenance['boot_screen'] != record['boot_screen']:
        raise ValueError('053 boot-screen input changed')
    if args.metal_runtime:
        runtime_path, runtime = receipt(args.metal_runtime)
        validate_metal(runtime, baseline['get']('EFI/UniXNU/Payloads/kernel.macho.trustcache'))
        plugin_path = BASE / 'metal-d27-startup-003/result.json'
        plugin = json.loads(plugin_path.read_text())
        metal_evidence_path = ROOT / 'evidence/d27-metal-startup-003.json'
        metal_evidence = json.loads(metal_evidence_path.read_text())
        if (runtime['addon_sha256'] != '732133caada59afafa52e304768786385a50fe89606ed9cb0845b08219c06286' or
                runtime['trust_sha256'] != '8d93a6a5e30413043ef014dd32a40e951a4b25c12b9b9f8774afb9a2f9ce2f1f' or
                runtime.get('source_adapter') != plugin or not plugin.get('build_verified') or
                metal_evidence['addon_sha256'] != runtime['addon_sha256'] or
                metal_evidence['trust_sha256'] != runtime['trust_sha256']):
            raise ValueError('055 requires the completed Metal startup003 package')
    for path, digest in provenance['usb_sources'].items():
        if sha(Path(path).read_bytes()) != digest:
            raise ValueError('Compiled USB source identity changed: ' + path)
    if not provenance['expanded_native_data']['rw_nx'] or not provenance['expanded_native_data']['zero_fill_verified']:
        raise ValueError('Expanded native data validation missing')

    original = baseline['get']('EFI/UniXNU/unixnu.toml').decode()
    old_args = record['kernel_args']
    release = load('reviewed_release_helpers', ROOT / 'scripts/ci/release-d27-pac-abi.py')
    release.run([sys.executable, '-B', ROOT / 'scripts/ci/verify-d27-sdt.py',
                 '--strict', args.strict, '--out', work / 'sdt-verified.json'], work / 'sdt.log')
    corrected = release.replace_config_arguments(original, old_args, new_args)
    title = 'Sony PDX234 iOS 27 D27 XNU PAC-ABI-' + args.label + ' PANIC SCREEN'
    old_title = record['menu_title']
    if corrected.count(json.dumps(old_title)) != 1:
        raise ValueError('Unexpected052 menu title')
    corrected = corrected.replace(json.dumps(old_title), json.dumps(title), 1)
    before_config, after_config = tomllib.loads(original), tomllib.loads(corrected)
    check_config = copy.deepcopy(after_config)
    check_config['ui']['title'] = before_config['ui']['title']
    next(e for e in check_config['entry'] if e['id'] == 'xnu')['args'] = old_args
    if check_config != before_config or after_config['boot']['default'] != 'xnu':
        raise ValueError('Unexpected configuration delta')

    kernel = work / 'kernel.macho'
    require_space()
    kernel.write_bytes(kernel_bytes)
    # Same official adapter, sequencing and arm64e sealing environment as
    # release-d27-pac-abi.py. The adapter checks every changed byte and PACIBSP.
    release.run([sys.executable, '-B', ROOT / 'scripts/patch-panic-screen.py',
                 '--kernel', kernel, '--mainline', BASE / 'sources/UniXNU',
                 '--uefi', ROOT.parent / 'uefi-pdx234', '--preserve-auth'], work / 'panic-patch.log')
    panic = json.loads((work / 'kernel.panic-screen.json').read_text())
    if not panic['auth_instructions_preserved'] or panic['source_kernel_sha256'] != sha(kernel_bytes):
        raise ValueError('Panic patch identity/authentication differs')
    diagnostic_bytes = kernel.read_bytes()
    env = dict(os.environ, UNIXNU_XNU_ARCH='arm64e', UNIXNU_IOS_VERSION='27.0')
    release.run([sys.executable, '-B', BASE / 'sources/UniXNU/scripts/seal-source-crypto-kernel.py',
                 kernel, '--kernel-args', new_args], work / 'seal.log', env)
    seal = json.loads((work / 'kernel.macho.crypto-hmac.json').read_text())
    if seal['kernel_sha256'] != sha(kernel.read_bytes()):
        raise ValueError('Sealed payload identity differs')
    sys.path.insert(0, str(args.strict / 'XnuPrelink'))
    from kc_image import Image
    before, after = Image(diagnostic_bytes), Image(kernel.read_bytes())
    for _, offset in before.entries.values():
        member = Image(before.data, offset)
        for segment in member.segments:
            if segment['name'] in ('__TEXT_EXEC', '__KLD') and segment['filesize']:
                at, size = segment['fileoff'], segment['filesize']
                if before.data[at:at + size] != after.data[at:at + size]:
                    raise ValueError('Sealing changed executable bytes')
    release.run([sys.executable, '-B', ROOT / 'scripts/ci/audit-darwinboot-parser.py',
                 '--darwinboot', ROOT / '.cache/firmware-components/DarwinBoot', '--kernel', kernel,
                 '--report', work / 'darwinboot-parser.json'], work / 'parser.log')
    if not json.loads((work / 'darwinboot-parser.json').read_text())['accepted']:
        raise ValueError('DarwinBoot rejected the sealed collection')

    config = work / 'unixnu.toml'
    config.write_text(corrected)
    fatfile = work / 'payload.fat'
    fatfile.write_bytes(baseline['fat'])
    old_files = fat_inventory(fatfile)
    replacements = [(kernel, 'Payloads/kernel.macho'), (config, 'unixnu.toml')]
    if runtime:
        replacements += [(Path(runtime['addon']), 'Payloads/kernel.macho.gpuaddon'),
                         (Path(runtime['trust']), 'Payloads/kernel.macho.trustcache')]
    for local, remote in replacements:
        if local in (kernel, config):
            os.utime(local, (315532800, 315532800))
        subprocess.run(['mcopy', '-o', '-m', '-i', str(fatfile), str(local), '::/EFI/UniXNU/' + remote], check=True)
    new_files = fat_inventory(fatfile)
    changed = {name for name in old_files.keys() | new_files.keys() if old_files.get(name) != new_files.get(name)}
    expected = {'EFI/UniXNU/' + remote for local, remote in replacements
                if old_files.get('EFI/UniXNU/' + remote) != sha(local.read_bytes())}
    if changed != expected or old_files.keys() != new_files.keys():
        raise ValueError('Unexpected payload file delta: ' + repr(changed))
    for local, remote in replacements:
        if new_files['EFI/UniXNU/' + remote] != sha(local.read_bytes()):
            raise ValueError('FAT replacement differs: ' + remote)
    write_json(work / 'payload-files.json', {'before': old_files, 'after': new_files, 'changed': sorted(changed)})

    # Transport packing follows correct-sony-menu.py. Copy the verified baseline
    # Android/header/FD bytes and rebuild only the bundle-dependent wrapper.
    fat = fatfile.read_bytes()
    require_space()
    compressed = bytearray(lzma.compress(fat, format=lzma.FORMAT_ALONE, preset=6))
    compressed[5:13] = struct.pack('<Q', len(fat))
    bundle = work / 'payload.bundle'
    bundle.write_bytes(struct.pack('<8s4IQ', b'PDXFAT02', 32, len(compressed), len(fat), zlib.crc32(fat), 0) + compressed)
    android, fd = work / 'Android.Image', work / 'firmware.fd'
    android.write_bytes(baseline['android'])
    fd.write_bytes(baseline['fd'])
    memory, flags = struct.unpack_from('<QQ', baseline['android'], 16)
    (work / 'Pdx234ComboInputs.h').write_text('\n'.join([
        f'#define ANDROID_INPUT_PATH "{android}"', f'#define UEFI_FD_INPUT_PATH "{fd}"',
        f'#define XNU_BUNDLE_INPUT_PATH "{bundle}"', f'#define ANDROID_MEMORY_BYTES {memory}',
        f'#define ANDROID_IMAGE_FLAGS {flags}', f'#define ANDROID_IMAGE_BYTES {len(baseline["android"])}',
        f'#define ANDROID_IMAGE_CRC32 {zlib.crc32(baseline["android"])}',
        '#define ANDROID_PAYLOAD_OFFSET 0x200000', '#define SPMI_CORE_BASE 0xc400000',
        '#define SPMI_OBSERVER_BASE 0xc440000', '#define FD_BASE 0xa7100000', '#define FD_SIZE 0x300000']) + '\n')
    source = ROOT.parent / 'uefi-pdx234/BootShim/Pdx234Combo.S'
    commands = [
        ['clang', '--target=aarch64-none-elf', '-I', str(work), '-c', str(source), '-o', str(work / 'combo.o')],
        ['ld.lld', '--image-base=0', '-Ttext=0', '-e', '_Head', str(work / 'combo.o'), '-o', str(work / 'combo.elf')],
        ['llvm-objcopy', '-O', 'binary', str(work / 'combo.elf'), str(work / 'combo.Image')]]
    for command in commands:
        subprocess.run(command, check=True)
    combo = (work / 'combo.Image').read_bytes()
    fd_offset = 0x200000 + memory
    if (combo[0x200000:0x200000 + len(baseline['android'])] != baseline['android'] or
            combo[fd_offset:fd_offset + len(baseline['fd'])] != baseline['fd']):
        raise ValueError('Android or firmware changed')
    metadata = struct.unpack('<8sIIQQQIIQQQQ', combo[-80:])
    if metadata[:3] != (b'PXCBHOF1', 2, 80) or combo[metadata[-2]:metadata[-2] + metadata[-1]] != bundle.read_bytes():
        raise ValueError('Wrapper metadata/bundle differs')
    header = bytearray(baseline['raw'][:4096])
    struct.pack_into('<II', header, 8, len(combo), 0)
    struct.pack_into('<I', header, 1580, 0)
    image = header + combo + bytes(-len(combo) % 4096)
    if len(image) > 128 * 1024 * 1024:
        raise ValueError('Image exceeds boot capacity')
    args.out.mkdir(parents=True)
    require_space()
    final_release = args.label == '055'
    target = args.out.resolve() / ('boot-pdx234-pac-abi-' + args.label + ('' if final_release else '-native') + '.img')
    target.write_bytes(image)
    record = copy.deepcopy(record)
    for key in ('recount_sparse_kind_span', 'native_jop_policy', 'single_cluster_qos',
                'vfs_shutdown_diagnostic', 'usb_console', 'upstream_startup', 'launchd_trace',
                'launchd_transport', 'launchd_shutdown', 'display_source', 'gpu_source',
                'selected_profile', 'boot_screen', 'expanded_native_data', 'audit_source_repairs'):
        record[key] = provenance[key]
    record.update(image=str(target), bytes=len(image), sha256=sha(image), label='PAC-ABI-' + args.label + ('' if final_release else '-NATIVE'),
        staging_only=not final_release, native_sha256=provenance['native_sha256'], strict_kernel_sha256=sha(kernel_bytes),
        payload_kernel_sha256=sha(kernel.read_bytes()), payload_sha256=sha(fat), bundle_sha256=sha(bundle.read_bytes()),
        source_image_sha256=baseline_sha, source_release=str(args.release.resolve()),
        kernel_args=new_args, screen_build_tag='PDX' + args.label, menu_title=title, menu_default='xnu',
        arguments_removed=[old_tag], arguments_added=['build-tag=PDX' + args.label],
        baseline_arguments_unchanged=False, firmware_only_correction=False, baseline_adt_unchanged=True,
        comparison_release=None, comparison_image_sha256=None, comparison_kernel_byte_identity=False,
        panic_screen=panic, crypto_seal=seal, entry_bars=True, auth_instruction_patches=False,
        pac_metadata_adapters=False, gpu_runtime_enabled=True, software_rendering_control=False,
        loader_parser_accepted=True, config_fat_roundtrip_verified=True, usb_sources=provenance['usb_sources'],
        native_review_receipt=str((args.strict / 'result.json').resolve()),
        strict_result_sha256=sha((args.strict / 'result.json').read_bytes()),
        firmware_extent=[4096 + fd_offset, 4096 + fd_offset + len(baseline['fd'])],
        correction='Stage reviewed native and display009 with retained baseline firmware/GPU/CDC policy',
        display_source_receipt=str((args.display_source / 'result.json').resolve()),
        display_verification_receipt=str((args.display_source / 'sony-verification.json').resolve()),
        display_tests_receipt=str((args.display_tests / 'result.json').resolve()),
        cdc_poweroff_fixed=False, poweroff_root_cause_verified=False, hardware_boot_verified=False,
        usb_hardware_verified=False, desktop_verified=False, device_writes=False)
    if runtime:
        record.update(metal_runtime=runtime, metal_userspace_packaged=True,
            metal_runtime_receipt=str(runtime_path), metal_runtime_receipt_sha256=sha(runtime_path.read_bytes()),
            metal_plugin_receipt=str(plugin_path), metal_plugin_receipt_sha256=sha(plugin_path.read_bytes()),
            metal_startup_evidence=str(metal_evidence_path), metal_startup_evidence_sha256=sha(metal_evidence_path.read_bytes()),
            boot_screen_receipt=str(screen_path), boot_screen_receipt_sha256=sha(screen_path.read_bytes()),
            boot_screen_verification_receipt=str(screen_verification_path),
            boot_screen_verification_sha256=sha(screen_verification_path.read_bytes()),
            cdc_disabled=True, xnu_cdc_enabled=False, uefi_cdc_frontend=False,
            correction='055: updated cached boot diagnostics and signed Metal addon; retain054 CDC-off/GPU-on policy')
    write_json(args.out / 'release.json', record)
    (args.out / 'SHA256SUMS').write_text(sha(image) + '  ' + target.name + '\n')
    final = readback(args.out, work / 'final-readback.log')
    if final['fat'] != fat or final['fd'] != baseline['fd'] or final['android'] != baseline['android']:
        raise ValueError('Final independent transport readback differs')
    write_json(work / 'report.json', {'image': str(target), 'image_sha256': sha(image),
        'native_sha256': provenance['native_sha256'], 'strict_sha256': sha(kernel_bytes),
        'payload_kernel_sha256': record['payload_kernel_sha256'], 'panic_auth_preserved': True,
        'seal_executable_bytes_unchanged': True, 'payload_files_changed': sorted(changed),
        'firmware_preserved': True, 'android_preserved': True, 'commands': commands,
        'packager_sha256': sha(Path(__file__).read_bytes()), 'hardware_verified': False})
    print(json.dumps({key: record[key] for key in ('image', 'sha256', 'native_sha256',
        'strict_kernel_sha256', 'payload_kernel_sha256', 'firmware_sha256', 'staging_only')}, indent=2))


if __name__ == '__main__':
    main()
