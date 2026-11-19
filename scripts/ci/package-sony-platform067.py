#!/usr/bin/env python3
"""Package the reviewed physical066-derived platform update and 2GiB RAM seed."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
BASELINE_SHA = '4f5984cce75fbf59f22628cb3025739bc05fa52fe7b613d121fe724e4462e456'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def save(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n')


def updated_arguments(before, changes):
    tokens = before.split()
    if (tokens.count('build-tag=PDX066') != 1 or
            len(tokens) != len({token.split('=')[0] for token in tokens})):
        raise ValueError('Unexpected066 baseline arguments')
    if any(key in changes for key in ('build-tag', 'data-persist', 'qcom-usb-debug', 'smp', 'sony-touch', 'touch-hid')):
        raise ValueError('Protected argument override')
    allowed = {'cpufreq', 'cpufreq-cap', 'vsync', 'first-frame-diag', 'gpu-trace', 'sheng-gpu-trace',
               'gpu-dcvs', 'sony-platform-performance', 'sony-buttons', 'sony-buttons-read-qualified',
               'gpu-dcvs-min', 'gpu-fence-wake', 'gpu-pause-us', 'sony-display-timing', 'sony-perf-samples',
               'sony-buttons-pon-apid', 'sony-buttons-gpio-apid', 'sony-wcn', 'sony-wifi', 'sony-bluetooth',
               'sony-backlight', 'sony-oled-backlight', 'backlight', 'wifi', 'bluetooth'}
    allowed.add('storage-probe')
    for key, value in changes.items():
        if key not in allowed or not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError('Unreviewed boot argument: ' + key)
        previous = [i for i, token in enumerate(tokens) if token.split('=')[0] == key]
        if len(previous) > 1:
            raise ValueError('Ambiguous baseline argument: ' + key)
        if previous:
            tokens[previous[0]] = key + '=' + str(value)
        else:
            tokens.append(key + '=' + str(value))
    tokens[tokens.index('build-tag=PDX066')] = 'build-tag=PDX067'
    result=' '.join(tokens)
    sys.path.insert(0,str(ROOT/'ci'))
    from darwin_boot_args import validate
    validate(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('release', 'native', 'strict', 'verification', 'platform-verification', 'seed', 'policy', 'work', 'out'):
        parser.add_argument('--' + key, type=Path, required=True)
    args = parser.parse_args()
    if args.work.exists() or args.out.exists():
        raise ValueError('Preserve existing packages')
    helpers = load('platform067_helpers', 'package-d27-reviewed-native.py')
    release = load('platform067_release', 'release-d27-pac-abi.py')
    transport = load('platform067_transport', 'package-d27-metal-refresh.py')
    helpers.require_space()
    args.work.mkdir(parents=True)
    work = args.work.resolve()
    baseline = helpers.readback(args.release, work / 'baseline-readback.log')
    prior = baseline['j']
    if prior['sha256'] != BASELINE_SHA or not prior['gpu_enabled'] or not prior['cdc_disabled']:
        raise ValueError('Exact tested066 physical payload required')
    native = json.loads((args.native / 'result.json').read_text())
    strict = json.loads((args.strict / 'result.json').read_text())
    kernel_record = json.loads((args.strict / 'kernel.json').read_text())
    verification = json.loads(args.verification.read_text())
    platform_verification = json.loads(args.platform_verification.read_text())
    if (sha(args.native / 'native.macho') != native['native_sha256'] or
            native['native_sha256'] != strict['native_sha256'] or
            sha(args.strict / 'kernel.macho') != strict['candidate_sha256'] or
            kernel_record['candidate_sha256'] != strict['candidate_sha256'] or
            kernel_record['missing'] or kernel_record['stubbed'] or kernel_record['allow_missing'] or
            not kernel_record['candidate_written'] or not strict['pac_enabled'] or
            strict['pac_metadata_adapters'] or strict['auth_instruction_patches'] or
            not verification['passed'] or verification['native_sha256'] != native['native_sha256'] or
            verification['strict_sha256'] != strict['candidate_sha256']):
        raise ValueError('Exact strict source and instruction receipts required')
    if (not platform_verification['passed'] or
            platform_verification['native_sha256'] != native['native_sha256'] or
            platform_verification['strict_sha256'] != strict['candidate_sha256'] or
            platform_verification['actual_signed_blocks_inputs_verified'] != 66):
        raise ValueError('Actual selected platform archives/functions/PAC verification required')
    if not verification['block_descriptor_abi']['passed'] or not native['sony_touch']['temporary_probes_removed']:
        raise ValueError('Signed Blocks ABI and completed touch-probe cleanup required')
    if (verification['full_profile_roots'], verification['closure_entries'],
            verification['matching_personalities'], verification['original_kmod_pac_fields']) != (19, 38, 32, 36):
        raise ValueError('Complete platform/Apple security closure required')
    sys.path.insert(0, str(ROOT / 'ci'))
    from native_source_overlays import validate_overlays
    validate_overlays(native, sha)
    for key in ('display_source', 'gpu_source', 'boot_screen'):
        if native[key] != strict[key] or sha(native[key]['archive']) != native[key]['sha256']:
            raise ValueError('Physical archive changed: ' + key)
    if strict['selected_profile']['roots'] != prior['selected_profile']['roots']:
        raise ValueError('Retained D27 profile roots differ')
    seed = json.loads(args.seed.read_text())
    if (not seed['passed'] or seed['logical_bytes'] != 2 * 1024**3 or seed['persistence_mode'] != 0 or
            not seed['nodes_bytes_uid_gid_modes_mtime_symlinks_xattrs_verified'] or not seed['apfsck_passed'] or
            sha(seed['seed']) != seed['seed_sha256']):
        raise ValueError('Complete matching 2GiB volatile seed qualification required')
    policy = json.loads(args.policy.read_text())
    if not isinstance(policy.get('feature_status'), dict):
        raise ValueError('Explicit per-feature implementation/hardware status required')
    for key in ('heat', 'refresh', 'app_exits', 'wifi', 'bluetooth', 'brightness', 'power_key', 'touch'):
        status = policy['feature_status'].get(key)
        if (not isinstance(status, dict) or not isinstance(status.get('implemented'), bool) or
                not isinstance(status.get('hardware_verified'), bool) or not status.get('limits')):
            raise ValueError('Missing honest implementation boundary: ' + key)
        if status['hardware_verified']:
            raise ValueError('New067 features have no handset observation yet: ' + key)
    sparse = json.loads(Path(policy['volatile_seed_test']).read_text())
    if (not sparse['passed'] or sparse['seed_sha256'] != seed['seed_sha256'] or
            sparse['persistence_required'] or sparse['device_operations']):
        raise ValueError('Actually linked RAM sparse2GiB boundary regression required')
    for path, expected in policy['inputs'].items():
        if sha(path) != expected:
            raise ValueError('Policy qualification input differs: ' + path)
    arguments = updated_arguments(prior['kernel_args'], policy['argument_changes'])
    for required in ('data-persist=0', 'banner=0', 'boot-diag-resume=0', 'sony-touch=1', 'touch-hid=1',
                     'first-frame-diag=0', 'gpu-trace=0', 'sheng-gpu-trace=0'):
        if arguments.split().count(required) != 1:
            raise ValueError('Protected run policy differs: ' + required)
    original = baseline['get']('EFI/UniXNU/unixnu.toml').decode()
    text = release.replace_config_arguments(original, prior['kernel_args'], arguments)
    title = prior['menu_title'].replace('PAC-ABI-066', 'PAC-ABI-067')
    if text.count(json.dumps(prior['menu_title'])) != 1:
        raise ValueError('Ambiguous menu identity')
    text = text.replace(json.dumps(prior['menu_title']), json.dumps(title))
    expected = copy.deepcopy(tomllib.loads(original))
    expected['ui']['title'] = title
    next(entry for entry in expected['entry'] if entry['id'] == 'xnu')['args'] = arguments
    if tomllib.loads(text) != expected:
        raise ValueError('Unexpected menu/configuration change')
    menu = work / 'menu'
    esp = menu / 'esp'
    (esp / 'EFI/BOOT').mkdir(parents=True)
    (esp / 'EFI/UniXNU').mkdir(parents=True)
    app = BASE / 'tmp/first-frame-menu058/esp/EFI/BOOT/BOOTAA64.EFI'
    if sha(app) != '3327e1b7a84fc0e6cd796c54acf63620d9d2add99e78b6a4032d99c9dd9d25c3':
        raise ValueError('Qualified UniXNU menu binary differs')
    (esp / 'EFI/BOOT/BOOTAA64.EFI').write_bytes(app.read_bytes())
    (esp / 'EFI/UniXNU/unixnu.toml').write_text(text)
    menu_command = ['python3', '-B', '/root/unixnu-build/pdx234-unixnu-package/Scripts/qemu-run.py', str(esp),
        '--log', str(menu / 'serial.log'), '--screenshot', str(menu / 'menu.png'), '--expect', "default 0 'xnu'",
        '--reject', 'UNIXNU: config: default entry needs confirmation', '--timeout', '30', '--finish-on-expect']
    with (menu / 'runner.log').open('x') as log:
        subprocess.run(menu_command, stdout=log, stderr=subprocess.STDOUT, timeout=45, check=True)
    save(menu / 'result.json', dict(passed=True, command=menu_command, application_sha256=sha(app),
         config_sha256=hashlib.sha256(text.encode()).hexdigest(), scope='Menu only, never boots XNU'))
    release.run([sys.executable, '-B', ROOT / 'scripts/ci/verify-d27-sdt.py', '--strict', args.strict,
                 '--out', work / 'sdt-verified.json'], work / 'sdt.log')
    kernel = work / 'kernel.macho'
    kernel.write_bytes((args.strict / 'kernel.macho').read_bytes())
    release.run([sys.executable, '-B', ROOT / 'scripts/patch-panic-screen.py', '--kernel', kernel,
        '--mainline', BASE / 'sources/UniXNU', '--uefi', ROOT.parent / 'uefi-pdx234', '--preserve-auth'], work / 'panic.log')
    panic = json.loads((work / 'kernel.panic-screen.json').read_text())
    if not panic['auth_instructions_preserved'] or panic['source_kernel_sha256'] != strict['candidate_sha256']:
        raise ValueError('Panic renderer altered authentication')
    unsealed = kernel.read_bytes()
    release.run([sys.executable, '-B', BASE / 'sources/UniXNU/scripts/seal-source-crypto-kernel.py', kernel,
        '--kernel-args', arguments], work / 'seal.log', dict(os.environ, UNIXNU_XNU_ARCH='arm64e', UNIXNU_IOS_VERSION='27.0'))
    seal = json.loads((work / 'kernel.macho.crypto-hmac.json').read_text())
    if seal['kernel_sha256'] != sha(kernel):
        raise ValueError('Final seal hash differs')
    sys.path.insert(0, str(args.strict / 'XnuPrelink'))
    from kc_image import Image
    collection = Image(unsealed)
    sealed = kernel.read_bytes()
    for _, offset in collection.entries.values():
        member = Image(unsealed, offset)
        for segment in member.segments:
            if segment['name'] in ('__TEXT_EXEC', '__KLD'):
                at, size = segment['fileoff'], segment['filesize']
                if unsealed[at:at+size] != sealed[at:at+size]:
                    raise ValueError('Crypto seal modified executable code')
    release.run([sys.executable, '-B', ROOT / 'scripts/ci/audit-darwinboot-parser.py',
        '--darwinboot', ROOT / '.cache/firmware-components/DarwinBoot', '--kernel', kernel,
        '--report', work / 'darwinboot-parser.json'], work / 'parser.log')
    if not json.loads((work / 'darwinboot-parser.json').read_text())['accepted']:
        raise ValueError('Production DarwinBoot parser rejected kernel')
    config = work / 'unixnu.toml'
    config.write_text(text)
    staged_seed = work / 'scratch-data.img'
    staged_seed.write_bytes(Path(seed['seed']).read_bytes())
    fat = work / 'payload.fat'
    fat.write_bytes(baseline['fat'])
    old_files = helpers.fat_inventory(fat)
    for local, remote in ((kernel, 'Payloads/kernel.macho'), (config, 'unixnu.toml'), (staged_seed, 'Payloads/scratch-data.img')):
        os.utime(local, (315532800, 315532800))
        subprocess.run(['mcopy', '-o', '-m', '-i', str(fat), str(local), '::/EFI/UniXNU/' + remote], check=True)
    new_files = helpers.fat_inventory(fat)
    changed = {name for name in old_files if old_files[name] != new_files.get(name)}
    allowed = {'EFI/UniXNU/Payloads/kernel.macho', 'EFI/UniXNU/unixnu.toml', 'EFI/UniXNU/Payloads/scratch-data.img'}
    if old_files.keys() != new_files.keys() or changed != allowed:
        raise ValueError('Unexpected066 payload change')
    image, blob, commands = transport.pack_transport(baseline, fat.read_bytes(), work, helpers)
    if len(image) > 96 * 1024**2:
        raise ValueError('Sony boot partition capacity exceeded')
    args.out.mkdir(parents=True)
    target = args.out.resolve() / 'boot-pdx234-pac-abi-067.img'
    target.write_bytes(image)
    record = copy.deepcopy(prior)
    platform_abi={}
    if native.get('platform067_buttons'):
        path=Path(native['platform067_buttons']['archive']).with_name('buttons-hid-abi.json')
        if sha(path)!=native['platform067_buttons']['hid_abi_sha256']:
            raise ValueError('Final buttons ABI input changed')
        platform_abi['buttons']=json.loads(path.read_text())
    if native.get('platform067_oled'):
        path=Path(native['platform067_oled']['archive']).with_name('abi.json')
        if sha(path)!=native['platform067_oled']['abi_sha256']:
            raise ValueError('Final OLED ABI input changed')
        platform_abi['oled']=json.loads(path.read_text())
    record.update(image=str(target), bytes=len(image), sha256=helpers.sha(image), label='PAC-ABI-067',
        source_image_sha256=BASELINE_SHA, source_release=str(args.release.resolve()),
        native_sha256=native['native_sha256'], strict_kernel_sha256=strict['candidate_sha256'],
        payload_kernel_sha256=sha(kernel), payload_sha256=sha(fat), bundle_sha256=helpers.sha(blob),
        kernel_args=arguments, screen_build_tag='PDX067', menu_title=title, panic_screen=panic, crypto_seal=seal,
        expanded_native_data=strict['expanded_native_data'], selected_profile=strict['selected_profile'],
        display_source=native['display_source'], gpu_source=native['gpu_source'], boot_screen=native['boot_screen'],
        native_review_receipt=str(args.strict / 'result.json'), strict_result_sha256=sha(args.strict / 'result.json'),
        handset_instruction_verification=verification, handset_instruction_verification_receipt=str(args.verification),
        handset_instruction_verification_sha256=sha(args.verification), block_descriptor_abi=verification['block_descriptor_abi'],
        sony_touch=native['sony_touch'], sony_touch_verification=verification['sony_touch'],
        sony_touch_hid_abi=json.loads(Path(native['sony_touch']['archive']).with_name('hid-abi.json').read_text()),
        platform067=native['platform067'], platform067_policy=policy, volatile_seed=seed,
        platform067_abi=platform_abi,
        platform067_feature_status=policy['feature_status'],
        platform067_linked_verification=platform_verification,
        platform067_linked_verification_receipt=str(args.platform_verification),
        platform067_linked_verification_sha256=sha(args.platform_verification),
        platform067_performance=native.get('platform067_performance'),
        platform067_buttons=native.get('platform067_buttons'), platform067_oled=native.get('platform067_oled'),
        platform067_radio=native.get('platform067_radio'), platform067_logging=native.get('platform067_logging'),
        physical_066_derived=True, official_upstream_parity=native['official_upstream_parity'],
        menu_qemu_receipt=str(menu / 'result.json'), menu_qemu_receipt_sha256=sha(menu / 'result.json'),
        cpu_runtime_recording_enabled=False, touch_runtime_verified=False, hardware_boot_verified=False,
        first_frame_diagnostics=False, temporary_probe_cleanup=True,
        home_screen_verified=False, desktop_verified=False, device_writes=False,
        staging_only=not policy.get('image_for_user_delivery',False), image_delivered=False,
        ready_for_manual_test=policy.get('image_for_user_delivery',False),
        platform067_features_hardware_verified=False)
    save(args.out / 'release.json', record)
    (args.out / 'SHA256SUMS').write_text(record['sha256'] + '  ' + target.name + '\n')
    final = helpers.readback(args.out, work / 'final-readback.log')
    if (final['android'] != baseline['android'] or final['fd'] != baseline['fd'] or
            final['get']('EFI/UniXNU/Payloads/kernel.macho') != sealed or
            final['get']('EFI/UniXNU/Payloads/scratch-data.img') != staged_seed.read_bytes()):
        raise ValueError('Independent final readback differs')
    save(work / 'report.json', dict(passed=True, image=str(target), sha256=record['sha256'],
        changed_files=sorted(changed), all_other_payload_files_identical=True, firmware_android_unchanged=True,
        commands=commands, packager_sha256=sha(__file__), device_operations=False, hardware_verified=False))
    print(json.dumps(dict(image=str(target), sha256=record['sha256'], bytes=len(image),
        cdc_disabled=True, gpu_enabled=True, volatile_data_mib=2048, hardware_verified=False), indent=2))


if __name__ == '__main__':
    main()
