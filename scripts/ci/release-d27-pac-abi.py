#!/usr/bin/env python3
"""Package the PAC build, optionally with the official auth-preserving panic screen."""
import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tomllib
import zlib

DEVICE = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(command, log, env=None):
    with log.open('x') as stream:
        result = subprocess.run(list(map(str, command)), env=env, stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(log.read_text()[-6000:])


def without_autoreset(arguments):
    """Remove only the known diagnostic deadline, not other reset policies."""
    tokens = arguments.split()
    deadlines = [token for token in tokens if token == 'autoreset' or token.startswith('autoreset=')]
    if deadlines != ['autoreset=180'] or arguments != ' '.join(tokens):
        raise ValueError('Require exactly one baseline autoreset=180 and canonical spacing')
    return ' '.join(token for token in tokens if token != 'autoreset=180')


def replace_config_arguments(text, before, after):
    entries = [entry for entry in tomllib.loads(text)['entry'] if entry.get('id') == 'xnu']
    if len(entries) != 1 or entries[0]['args'] != before or text.count(json.dumps(before)) != 1:
        raise ValueError('Unexpected baseline XNU arguments')
    sys.path.insert(0, str(DEVICE / 'ci'))
    from darwin_boot_args import validate
    validate(after)
    result = text.replace(json.dumps(before), json.dumps(after), 1)
    if next(entry for entry in tomllib.loads(result)['entry'] if entry.get('id') == 'xnu')['args'] != after:
        raise ValueError('XNU argument replacement failed')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('strict', 'payload', 'boot', 'out'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--panic-screen', action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument('--label', default='PAC-ABI-012', choices=tuple(f'PAC-ABI-{n:03d}' for n in range(6, 31))+('PAC-ABI-032','PAC-ABI-033','PAC-ABI-034'))
    parser.add_argument('--smp-adt', type=Path, help='Verified Sony eight-core ADT directory')
    parser.add_argument('--metal-runtime', type=Path, help='Verified signed GPU addon and augmented trust bundle')
    parser.add_argument('--fd', type=Path, default=BASE / 'firmware-retained-010.fd')
    parser.add_argument('--without-autoreset', action='store_true', help='Only remove autoreset=180; keep log and panic diagnostics')
    parser.add_argument('--compare-release', type=Path, help='Prior release.json requiring byte-identical kernel for the A/B test')
    args = parser.parse_args()
    release_label = args.label
    # 034 uses the same payload policy as033; its new behavior is compiled
    # into the USB archive. Retain the final label for menu/build identity.
    usb_reset_release = release_label == 'PAC-ABI-034'
    if usb_reset_release:
        release_label = args.label = 'PAC-ABI-033'
    # 027 retains the complete026 payload recipe and enables its already-linked
    # AppleKeyStore service. Keep026 reproducible for the observed comparison.
    if args.label in ('PAC-ABI-027', 'PAC-ABI-028', 'PAC-ABI-029', 'PAC-ABI-030', 'PAC-ABI-032','PAC-ABI-033'):
        args.label = 'PAC-ABI-026'
    if release_label in ('PAC-ABI-030','PAC-ABI-032','PAC-ABI-033'):
        firmware_build='firmware-high-memory-001' if release_label=='PAC-ABI-030' else 'firmware-high-memory-002'
        fw=json.loads((BASE/firmware_build/'retained-result.json').read_text())
        if sha(args.fd)!=fw['sha256'] or fw['entry_base']!=0x980000000 or not fw['retained_other_modules']:
            raise ValueError('030 requires paired high-bank firmware')
    if args.without_autoreset and ((not args.compare_release and args.label not in tuple(f'PAC-ABI-{n:03d}' for n in range(14, 27))) or not args.panic_screen):
        parser.error('--without-autoreset requires --compare-release and the panic screen')
    for path in (args.payload, args.boot, args.out):
        if path.exists():
            parser.error('Use new output directories: ' + str(path))
    strict = json.loads((args.strict / 'kernel.json').read_text())
    provenance = json.loads((args.strict / 'result.json').read_text())
    if usb_reset_release:
        sources=provenance.get('usb_sources',{})
        required=[DEVICE/'ci/usb/Pdx234.h',DEVICE/'drivers/QcomXnuUsbDebug/soc/QcomUsbReset.h',
                  DEVICE/'drivers/QcomXnuUsbDebug/kernel/QcomXnuUsbDebug.c',
                  DEVICE/'drivers/QcomXnuUsbDebug/usb/Dwc3.c']
        if any(sources.get(str(path))!=sha(path) for path in required):
            raise ValueError('034 requires compiled reset-clock source identities')
    if release_label=='PAC-ABI-033' and not provenance.get('boot_screen',{}).get('usb_status'):
        raise ValueError('033 requires persistent USB screen status')
    if release_label in ('PAC-ABI-032','PAC-ABI-033'):
        if not (provenance.get('audit_source_repairs') and
                provenance.get('display_source',{}).get('matching_report') and
                provenance.get('display_source',{}).get('cpufreq_inputs') and
                provenance.get('boot_screen',{}).get('cpufreq')):
            raise ValueError('032 requires audit repairs, matching diagnostics and CPUfreq integration')
        sdt=json.loads((args.strict/'sdt-verified.json').read_text())['summary']
        if sdt['kernel_sha256']!=provenance['candidate_sha256'] or not sdt['mac_records']:
            raise ValueError('032 requires final readonly SDT verification')
    if args.label == 'PAC-ABI-014' and (not args.without_autoreset or not provenance.get('vfs_shutdown_diagnostic')):
        raise ValueError('014 requires VFS source diagnostics and no autoreset')
    if args.label in tuple(f'PAC-ABI-{n:03d}' for n in range(15, 27)) and (not args.without_autoreset or not provenance.get('usb_console')):
        raise ValueError('USB release requires USB console source integration and no autoreset')
    if args.label == 'PAC-ABI-019' and not provenance.get('upstream_startup'):
        raise ValueError('019 requires the pinned upstream startup fixes')
    if args.label == 'PAC-ABI-020' and (not provenance.get('upstream_startup') or not provenance.get('launchd_trace')):
        raise ValueError('020 requires upstream startup fixes and PID1 trace')
    if args.label in ('PAC-ABI-021', 'PAC-ABI-022', 'PAC-ABI-023') and not all(provenance.get(k) for k in ('upstream_startup', 'launchd_trace', 'launchd_transport')):
        raise ValueError('021 requires upstream startup fixes and PID1 transport trace')
    if args.label == 'PAC-ABI-023' and not provenance.get('launchd_shutdown'):
        raise ValueError('023 requires the pre-shutdown snapshot')
    if args.label in ('PAC-ABI-024', 'PAC-ABI-025', 'PAC-ABI-026'):
        if not all(provenance.get(k) for k in ('display_source', 'gpu_source', 'selected_profile', 'launchd_shutdown')):
            raise ValueError('024 requires real display/GPU archives, graphics roots and retained PID1 evidence')
        for key in ('display_source', 'gpu_source'):
            source = provenance[key]
            if sha(source['archive']) != source['sha256']:
                raise ValueError('Linked driver archive changed: ' + key)
    if (sha(args.strict / 'kernel.macho') != strict['candidate_sha256'] or
            strict['missing'] or strict['stubbed'] or strict['allow_missing'] or
            provenance['pac_metadata_adapters'] or provenance['auth_instruction_patches']):
        raise ValueError('Require the strict flag-only collection with original PAC metadata')
    baseline = BASE / 'payload-root-004'
    info = json.loads((baseline / 'report.json').read_text())
    if sha(baseline / 'kernel.macho.adt') != info['adt_sha256'] or sha(baseline / 'payload.fat') != info['payload_sha256']:
        raise ValueError('Baseline ADT/FAT changed')
    original_arguments = info['kernel_args']
    removed_arguments = ['autoreset=180'] if args.without_autoreset else []
    if args.without_autoreset:
        info['kernel_args'] = without_autoreset(original_arguments)
    added_arguments = ['qcom-usb-debug=1'] if args.label in tuple(f'PAC-ABI-{n:03d}' for n in range(15, 27)) else []
    if args.label in ('PAC-ABI-022', 'PAC-ABI-023', 'PAC-ABI-024', 'PAC-ABI-025', 'PAC-ABI-026'):
        added_arguments += ['disable-watchdogd=1', 'lite=1', 'no-lc=1', 'sheng-no-lc=1']
    if args.label in ('PAC-ABI-024', 'PAC-ABI-025', 'PAC-ABI-026'):
        added_arguments += ['offline-mobile-graphics-load=1', 'offline-mobile-graphics-client=1',
                            'offline-legacy-register=1', 'offline-legacy-gop=1', 'offline-legacy-unit-scale=2',
                            'offline-legacy-pm=1', 'offline-legacy-validate=1', 'offline-legacy-transfer=1',
                            'offline-legacy-cpu-present=1', 'offline-legacy-phase=4',
                            'aks=1', 'aks-sls=3', 'gpu-power=9', 'gpu-metal=1']
    smp = None
    if args.label in ('PAC-ABI-025', 'PAC-ABI-026'):
        if not args.smp_adt:
            raise ValueError('025 requires the verified eight-core ADT')
        smp = json.loads((args.smp_adt / 'result.json').read_text())
        if (smp['baseline_sha256'] != info['adt_sha256'] or smp['cpu_count'] != 8 or
                not smp['non_cpu_adt_unchanged'] or sha(args.smp_adt / 'kernel.macho.adt') != smp['adt_sha256']):
            raise ValueError('Unexpected SMP ADT provenance')
        added_arguments += ['smp=1', 'sheng-smp=1', 'armcpu-spi-ipi=1', 'armcpu-self-ipi=1', 'armcpu-diagnostics=1']
    elif args.smp_adt:
        raise ValueError('SMP ADT is selected only by025')
    runtime = None
    if args.label == 'PAC-ABI-026':
        if not args.metal_runtime or not provenance.get('boot_screen') or not provenance.get('expanded_native_data'):
            raise ValueError('026 requires real screen, expanded native data and signed Metal runtime')
        runtime = json.loads((args.metal_runtime / 'result.json').read_text())
        for key in ('addon','trust'):
            if sha(runtime[key]) != runtime[key+'_sha256']:raise ValueError('Runtime input changed: '+key)
        if not runtime['original_trust_modules_unchanged'] or not runtime['signature_pages_verified']:
            raise ValueError('Runtime trust/signature verification missing')
        if release_label in ('PAC-ABI-032','PAC-ABI-033') and not (runtime.get('source_adapter') or {}).get('j820_private_accesses_removed'):
            raise ValueError('032 requires the D27 Metal source adapter')
        # Replace an inherited disabled progress option rather than add a
        # duplicate boot argument with parser-dependent precedence.
        info['kernel_args'] = ' '.join(t for t in info['kernel_args'].split() if not t.startswith('boot-progress='))
        added_arguments += ['boot-progress=2','build-tag=PDX'+('034' if usb_reset_release else release_label[-3:]),'boot-diag-resume=10','sheng-gpu-addon=1']
        if release_label in ('PAC-ABI-027', 'PAC-ABI-028', 'PAC-ABI-029', 'PAC-ABI-030', 'PAC-ABI-032','PAC-ABI-033'):
            added_arguments += ['offline-key-events=1']
        if release_label in ('PAC-ABI-028', 'PAC-ABI-029', 'PAC-ABI-030', 'PAC-ABI-032','PAC-ABI-033'):
            added_arguments = [t for t in added_arguments if t not in
                               ('gpu-power=9','gpu-metal=1','sheng-gpu-addon=1')]
            added_arguments += ['gpu-power=0','gpu-metal=0','sheng-gpu-addon=0','fb-gpu=0']
        if release_label in ('PAC-ABI-032','PAC-ABI-033'):
            added_arguments += ['cpufreq=1','vsync=60']
    elif args.metal_runtime:
        raise ValueError('Metal runtime selected only by026')
    if added_arguments:
        info['kernel_args'] += ' ' + ' '.join(added_arguments)
    args.label = release_label
    comparison = {}
    if args.compare_release:
        comparison = json.loads(args.compare_release.read_text())
        if (comparison['native_sha256'] != provenance['native_sha256'] or
                comparison['strict_kernel_sha256'] != strict['candidate_sha256'] or
                comparison['adt_sha256'] != info['adt_sha256'] or
                comparison['kernel_args'] != original_arguments or
                sha(comparison['image']) != comparison['sha256']):
            raise ValueError('A/B baseline identity changed')
    payload = args.payload
    payload.mkdir(parents=True)
    shutil.copytree(baseline / 'stage', payload / 'stage')
    for name in ('Android.original.Image', 'kernel.macho.adt', 'platform-seed', 'payload.fat'):
        shutil.copyfile(baseline / name, payload / name)
    if smp:
        shutil.copyfile(args.smp_adt / 'kernel.macho.adt', payload / 'kernel.macho.adt')
        shutil.copyfile(payload / 'kernel.macho.adt', payload / 'stage/EFI/UniXNU/Payloads/kernel.macho.adt')
        info['adt_sha256'] = smp['adt_sha256']
    resource_limits = None
    if runtime:
        sys.path.insert(0,str(DEVICE / 'scripts/ci'))
        import importlib.util
        spec=importlib.util.spec_from_file_location('adt_codec',DEVICE/'scripts/apple-device-tree.py')
        codec=importlib.util.module_from_spec(spec);spec.loader.exec_module(codec)
        spec=importlib.util.spec_from_file_location('smp_codec',DEVICE/'scripts/ci/prepare-d27-smp-adt.py')
        smp_codec=importlib.util.module_from_spec(spec);spec.loader.exec_module(smp_codec)
        adt=codec.parse((payload/'kernel.macho.adt').read_bytes())
        memory=adt['children']['chosen']['children']['memory-map']['properties']
        if 'GpuAddon' in memory:raise ValueError('Unexpected preexisting GPU mapping')
        memory['GpuAddon']=bytes(16)
        if args.label in ('PAC-ABI-029','PAC-ABI-030','PAC-ABI-032','PAC-ABI-033'):
            sys.path.insert(0, str(DEVICE / 'ci'))
            from resource_limits import apply
            resource_limits = apply(adt, high_memory=args.label in ('PAC-ABI-030','PAC-ABI-032','PAC-ABI-033'))
        encoded=smp_codec.serialize(adt)
        if codec.parse(encoded)!=adt:raise ValueError('GPU ADT roundtrip differs')
        (payload/'kernel.macho.adt').write_bytes(encoded)
        shutil.copyfile(payload/'kernel.macho.adt',payload/'stage/EFI/UniXNU/Payloads/kernel.macho.adt')
        info['adt_sha256']=sha(payload/'kernel.macho.adt')
        for key,name in [('addon','kernel.macho.gpuaddon'),('trust','kernel.macho.trustcache')]:
            shutil.copyfile(runtime[key],payload/'stage/EFI/UniXNU/Payloads'/name)
    shutil.copyfile(args.strict / 'kernel.macho', payload / 'kernel.macho')
    panic = {}
    if args.panic_screen:
        run([sys.executable, '-B', DEVICE / 'scripts/patch-panic-screen.py',
             '--kernel', payload / 'kernel.macho', '--mainline', BASE / 'sources/UniXNU',
             '--uefi', DEVICE.parent / 'uefi-pdx234', '--preserve-auth'], payload / 'panic-patch.log')
        panic = json.loads((payload / 'kernel.panic-screen.json').read_text())
        if not panic['auth_instructions_preserved']:
            raise ValueError('Panic diagnostic must preserve authentication instructions')
    diagnostic_bytes = (payload / 'kernel.macho').read_bytes()
    env = dict(os.environ, UNIXNU_XNU_ARCH='arm64e', UNIXNU_IOS_VERSION='27.0')
    run([sys.executable, '-B', BASE / 'sources/UniXNU/scripts/seal-source-crypto-kernel.py',
         payload / 'kernel.macho', '--kernel-args', info['kernel_args']], payload / 'seal.log', env)
    seal = json.loads((payload / 'kernel.macho.crypto-hmac.json').read_text())
    if comparison and sha(payload / 'kernel.macho') != comparison['payload_kernel_sha256']:
        raise ValueError('A/B test must retain the exact sealed baseline kernel')
    sys.path.insert(0, str(args.strict / 'XnuPrelink'))
    from kc_image import Image
    before = Image(diagnostic_bytes)
    after = Image((payload / 'kernel.macho').read_bytes())
    for _, offset in before.entries.values():
        member = Image(before.data, offset)
        for segment in member.segments:
            if segment['name'] not in ('__TEXT_EXEC', '__KLD') or not segment['filesize']:
                continue
            at, size = segment['fileoff'], segment['filesize']
            if before.data[at:at + size] != after.data[at:at + size]:
                raise ValueError('Sealing changed executable bytes')
    shutil.copyfile(payload / 'kernel.macho', payload / 'stage/EFI/UniXNU/Payloads/kernel.macho')
    config = payload / 'stage/EFI/UniXNU/unixnu.toml'
    text = replace_config_arguments(config.read_text(), original_arguments, info['kernel_args'])
    sys.path.insert(0,str(DEVICE/'ci'))
    from sony_menu_identity import select_ios_default
    text = select_ios_default(text)
    if text.count('DIAG-004') != 1:
        raise ValueError('Unexpected baseline menu label')
    delivery_label='PAC-ABI-034' if usb_reset_release else args.label
    config.write_text(text.replace('DIAG-004', delivery_label + (' PANIC SCREEN' if args.panic_screen else ' NATIVE PANIC')))
    for path in (config, payload / 'kernel.macho'):
        os.utime(path, (315532800, 315532800))
    fat = payload / 'payload.fat'
    for local, remote in ((payload / 'kernel.macho', 'Payloads/kernel.macho'), (config, 'unixnu.toml')):
        subprocess.run(['mcopy', '-o', '-m', '-i', str(fat), str(local), '::/EFI/UniXNU/' + remote], check=True)
    if smp:
        subprocess.run(['mcopy', '-o', '-m', '-i', str(fat), str(payload / 'kernel.macho.adt'),
                         '::/EFI/UniXNU/Payloads/kernel.macho.adt'], check=True)
    if runtime:
        for name in ('kernel.macho.gpuaddon','kernel.macho.trustcache'):
            subprocess.run(['mcopy','-o','-m','-i',str(fat),str(payload/'stage/EFI/UniXNU/Payloads'/name),
                            '::/EFI/UniXNU/Payloads/'+name],check=True)
    config_roundtrip = payload / 'unixnu.roundtrip.toml'
    subprocess.run(['mcopy', '-i', str(fat), '::/EFI/UniXNU/unixnu.toml', str(config_roundtrip)], check=True)
    if config_roundtrip.read_bytes() != config.read_bytes():
        raise ValueError('FAT configuration differs')
    embedded_args = next(entry for entry in tomllib.loads(config_roundtrip.read_text())['entry'] if entry.get('id') == 'xnu')['args']
    if embedded_args != info['kernel_args'] or (args.without_autoreset and 'autoreset' in embedded_args):
        raise ValueError('FAT arguments do not match the A/B plan')
    for path in (payload / 'stage/EFI/UniXNU/Payloads').iterdir():
        temp = payload / 'roundtrip'
        subprocess.run(['mcopy', '-i', str(fat), '::/EFI/UniXNU/Payloads/' + path.name, str(temp)], check=True)
        if temp.read_bytes() != path.read_bytes():
            raise ValueError('FAT file differs: ' + path.name)
        temp.unlink()
    raw = fat.read_bytes()
    compressed = bytearray(lzma.compress(raw, format=lzma.FORMAT_ALONE, preset=6))
    compressed[5:13] = struct.pack('<Q', len(raw))
    if lzma.decompress(compressed, format=lzma.FORMAT_ALONE) != raw:
        raise ValueError('FAT compression roundtrip differs')
    bundle = struct.pack('<8s4IQ', b'PDXFAT02', 32, len(compressed), len(raw), zlib.crc32(raw), 0) + compressed
    (payload / 'payload.bundle').write_bytes(bundle)
    info.update(kernel_sha256=sha(payload / 'kernel.macho'), strict_source_kernel_sha256=strict['candidate_sha256'],
                strict_report=strict, entry_probe=panic, crypto_seal=seal, payload_sha256=sha(fat),
                bundle_sha256=sha(payload / 'payload.bundle'), bundle_bytes=len(bundle),
                pac_abi_build=provenance, diagnostic_instruction_patches=args.panic_screen,
                 baseline_adt_byte_identity=not smp, smp=smp, baseline_arguments_unchanged=not removed_arguments and not added_arguments,
                arguments_removed=removed_arguments, arguments_added=added_arguments, config_fat_roundtrip_verified=True,
                comparison_release=str(args.compare_release) if args.compare_release else None,
                comparison_image_sha256=comparison.get('sha256'),
                comparison_kernel_byte_identity=bool(comparison))
    (payload / 'report.json').write_text(json.dumps(info, indent=2) + '\n')
    run([sys.executable, '-B', DEVICE / 'scripts/ci/audit-darwinboot-parser.py',
         '--darwinboot', DEVICE / '.cache/firmware-components/DarwinBoot', '--kernel', payload / 'kernel.macho',
         '--report', payload / 'darwinboot-parser.json'], payload / 'parser.log')
    if not json.loads((payload / 'darwinboot-parser.json').read_text())['accepted']:
        raise ValueError('DarwinBoot refused the sealed collection')
    run([sys.executable, '-B', BASE / 'pack-sony-strict-boot.py', '--payload', payload,
          '--fd', args.fd, '--out', args.boot], payload / 'pack.log')
    boot = json.loads((args.boot / 'report.json').read_text())
    args.out.mkdir(parents=True)
    image = args.out / ('boot-pdx234-' + delivery_label.lower() + '.img')
    shutil.copyfile(args.boot / 'boot-pdx234-dual-xnu-entry-CANDIDATE.img', image)
    if sha(image) != boot['image_sha256'] or image.stat().st_size != boot['image_bytes']:
        raise ValueError('Delivered boot image differs')
    release = dict(image=str(image), bytes=image.stat().st_size, sha256=sha(image), label=delivery_label,
                   usb_reset_clock_preparation=usb_reset_release,
                   native_sha256=provenance['native_sha256'], strict_kernel_sha256=strict['candidate_sha256'],
                   payload_kernel_sha256=info['kernel_sha256'], original_android_sha256=boot['android_kernel_sha256'],
                   adt_sha256=info['adt_sha256'], baseline_adt_unchanged=not smp, smp=smp, kernel_args=info['kernel_args'],
                   baseline_arguments_unchanged=not removed_arguments, arguments_removed=removed_arguments,
                   arguments_added=added_arguments,
                   autoreset_removed=args.without_autoreset, config_fat_roundtrip_verified=True,
                   comparison_release=str(args.compare_release) if args.compare_release else None,
                   comparison_image_sha256=comparison.get('sha256'), comparison_kernel_byte_identity=bool(comparison),
                   auth_instruction_patches=False, pac_metadata_adapters=False,
                   recount_sparse_kind_span=provenance.get('recount_sparse_kind_span', False),
                   native_jop_policy=provenance.get('native_jop_policy', False),
                   single_cluster_qos=provenance.get('single_cluster_qos', False),
                   vfs_shutdown_diagnostic=provenance.get('vfs_shutdown_diagnostic', False),
                   usb_console=provenance.get('usb_console', False),
                   upstream_startup=provenance.get('upstream_startup', False),
                   launchd_trace=provenance.get('launchd_trace', False),
                   launchd_transport=provenance.get('launchd_transport', False),
                   launchd_shutdown=provenance.get('launchd_shutdown', False),
                   display_source=provenance.get('display_source'),
                   gpu_source=provenance.get('gpu_source'),
                   selected_profile=provenance.get('selected_profile'),
                    boot_screen=provenance.get('boot_screen'),
                    expanded_native_data=provenance.get('expanded_native_data'),
                    metal_userspace_packaged=bool(runtime), metal_runtime=runtime,
                    software_rendering_control=args.label in ('PAC-ABI-028','PAC-ABI-029','PAC-ABI-030','PAC-ABI-032','PAC-ABI-033'),
                    gpu_runtime_enabled=bool(runtime) and args.label not in ('PAC-ABI-028','PAC-ABI-029','PAC-ABI-030','PAC-ABI-032','PAC-ABI-033'),
                    audit_source_repairs=provenance.get('audit_source_repairs',False),
                    cpufreq_mode=1 if args.label in ('PAC-ABI-032','PAC-ABI-033') else 0,
                    software_vsync_hz=60 if args.label in ('PAC-ABI-032','PAC-ABI-033') else 0,
                    physical_refresh_verified=False,
                    firmware_sha256=sha(args.fd),
                    resource_limits=resource_limits,
                   usb_serial='PDX234XnuLog' if provenance.get('usb_console') else None,
                   usb_hardware_verified=False,
                   panic_path='official framebuffer renderer after preserved PACIBSP' if args.panic_screen else 'unmodified native XNU',
                   panic_screen=panic, entry_bars=args.panic_screen,
                   loader_parser_accepted=True, strict_missing={},
                   strict_stubbed={}, allow_missing=False, device_writes=False, root_mount_verified=False,
                   springboard_verified=False, hardware_boot_verified=False)
    (args.out / 'release.json').write_text(json.dumps(release, indent=2) + '\n')
    (args.out / 'SHA256SUMS').write_text(release['sha256'] + '  ' + image.name + '\n')
    print(json.dumps(release, indent=2), flush=True)


if __name__ == '__main__':
    main()
