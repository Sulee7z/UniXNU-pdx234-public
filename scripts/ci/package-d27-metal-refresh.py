#!/usr/bin/env python3
"""Refresh055's signed Metal payload for056 without changing its sealed kernel."""
import argparse
import copy
import importlib.util
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import struct
import subprocess
import zlib

ROOT = Path(__file__).resolve().parents[2]
BASELINE_SHA = 'b9496dbe680d38d02b3655d7a4f3c8eecaeaf45a3453414d25d690a1e0d945da'
KERNEL_SHA = 'cc37586ceccd762e0158cc4f1ca1705fd62c7a6523bea2713c0833c28a0010c2'
FIRMWARE_SHA = '30777cf8cafcb51e09d48a7ec5437575fcae816fe41575dfed6ede1734abe3ea'
TURNIP_SHA = '540cef9e278693dc8562f36e596ae4632214671ad3a0e57a95ed4ee48d4b360f'
ADDON_SHA = 'e62e13ad9a68e741bd0e94f208b17c8b6f533a23689d729d8b466889b14a2763'
TRUST_SHA = 'c2775c912d29e7808b1d5f85b3937d747a5d6e5ec7990010e54df58951b9f4c3'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def config_update(record, original):
    import tomllib
    if (record['sha256'] != BASELINE_SHA or record['payload_kernel_sha256'] != KERNEL_SHA or
            record['firmware_sha256'] != FIRMWARE_SHA or not record.get('cdc_disabled') or
            record.get('xnu_cdc_enabled') is not False or not record.get('gpu_enabled')):
        raise ValueError('Require exact055 CDC-off/GPU-on baseline')
    tokens = record['kernel_args'].split()
    for key, value in [('build-tag', 'PDX055'), ('qcom-usb-debug', '0'), ('gpu-power', '9'),
                       ('gpu-metal', '1'), ('sheng-gpu-addon', '1'), ('fb-gpu', '1'), ('dpu-scanout', '0')]:
        if [t for t in tokens if t.startswith(key + '=')] != [key + '=' + value]:
            raise ValueError('Unexpected055 argument: ' + key)
    arguments = ' '.join('build-tag=PDX056' if t == 'build-tag=PDX055' else t for t in tokens)
    title = 'Sony PDX234 iOS 27 D27 XNU PAC-ABI-056 PANIC SCREEN'
    corrected = original
    for before, after in [(record['kernel_args'], arguments), (record['menu_title'], title)]:
        if corrected.count(json.dumps(before)) != 1:
            raise ValueError('Ambiguous baseline configuration')
        corrected = corrected.replace(json.dumps(before), json.dumps(after), 1)
    parsed = tomllib.loads(corrected)
    if parsed['boot']['default'] != 'xnu':
        raise ValueError('Unexpected menu default')
    parsed['ui']['title'] = record['menu_title']
    next(e for e in parsed['entry'] if e['id'] == 'xnu')['args'] = record['kernel_args']
    if parsed != tomllib.loads(original):
        raise ValueError('Unexpected configuration delta')
    return corrected, arguments, title


def validate_addon(runtime, work, helpers):
    raw = Path(runtime['addon']).read_bytes()
    if len(raw) < 24 or raw[:8] != b'NGPUADD2' or len(raw) > 128 * 1024**2:
        raise ValueError('Invalid addon header/size')
    count, _, size = struct.unpack_from('<IIQ', raw, 8)
    expected = {f['path']: f for f in runtime['files']}
    if not 0 < count <= 64 or count != len(expected) or count != len(runtime['files']) or size != len(raw):
        raise ValueError('Invalid addon member count')
    offset, total, seen = 24, 0, set()
    stage = work / 'signature-check'
    for _ in range(count):
        plen, mode, length, packed = struct.unpack_from('<IIQQ', raw, offset)
        offset += 24
        if not 1 < plen <= 4096 or length > 64 * 1024**2 or offset + plen > len(raw):
            raise ValueError('Invalid addon member bounds')
        encoded = raw[offset:offset + plen]
        if encoded[-1] or b'\0' in encoded[:-1]:
            raise ValueError('Invalid addon member name')
        name = encoded[:-1].decode()
        path = PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or '\\' in name or name in seen or name not in expected:
            raise ValueError('Unsafe/duplicate/unrecorded addon member')
        offset += (plen + 7) & -8
        if offset + packed > len(raw):
            raise ValueError('Truncated addon stream')
        decoder = zlib.decompressobj()
        data = decoder.decompress(raw[offset:offset + packed], length + 1)
        if len(data) != length or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ValueError('Addon decompression bounds differ')
        total += length
        if total > 128 * 1024**2:
            raise ValueError('Addon expanded size exceeds bound')
        offset += (packed + 7) & -8
        entry = expected[name]
        if (helpers.sha(data), length, mode) != (entry['sha256'], entry['bytes'], entry['mode']):
            raise ValueError('Addon member identity differs: ' + name)
        target = stage / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        seen.add(name)
    if offset != len(raw) or seen != expected.keys():
        raise ValueError('Addon trailing bytes or missing members')
    bundle = stage / 'addons/NativeAdrenoMetal.bundle'
    if helpers.sha((bundle / 'libvulkan_freedreno.dylib').read_bytes()) != TURNIP_SHA:
        raise ValueError('Require the actual QEMU-tested legacy Turnip bytes')
    signer = load('refresh_codesign', 'd27-codesign.py')
    checks = {}
    for key, path in [('plugin', bundle), ('turnip', bundle / 'libvulkan_freedreno.dylib')]:
        actual = signer.inspect(path)
        actual.pop('entitlements')
        if actual != runtime['signature_checks'][key]:
            raise ValueError('Actual signature pages differ from receipt: ' + key)
        checks[key] = actual
    return {'members_verified': len(seen), 'signature_checks': checks, 'turnip_sha256': TURNIP_SHA}


def pack_transport(baseline, fat, work, helpers):
    # Same bounded PDXFAT02/BootShim transport as the native packager. No kernel
    # patch, crypto seal or native link is needed for this userspace-only update.
    helpers.require_space()
    compressed = bytearray(lzma.compress(fat, format=lzma.FORMAT_ALONE, preset=6))
    compressed[5:13] = struct.pack('<Q', len(fat))
    bundle = work / 'payload.bundle'
    blob = struct.pack('<8s4IQ', b'PDXFAT02', 32, len(compressed), len(fat), zlib.crc32(fat), 0) + compressed
    bundle.write_bytes(blob)
    android, fd = work / 'Android.Image', work / 'firmware.fd'
    android.write_bytes(baseline['android']); fd.write_bytes(baseline['fd'])
    memory, flags = struct.unpack_from('<QQ', baseline['android'], 16)
    (work / 'Pdx234ComboInputs.h').write_text('\n'.join([
        f'#define ANDROID_INPUT_PATH "{android}"', f'#define UEFI_FD_INPUT_PATH "{fd}"',
        f'#define XNU_BUNDLE_INPUT_PATH "{bundle}"', f'#define ANDROID_MEMORY_BYTES {memory}',
        f'#define ANDROID_IMAGE_FLAGS {flags}', f'#define ANDROID_IMAGE_BYTES {len(baseline["android"])}',
        f'#define ANDROID_IMAGE_CRC32 {zlib.crc32(baseline["android"])}',
        '#define ANDROID_PAYLOAD_OFFSET 0x200000', '#define SPMI_CORE_BASE 0xc400000',
        '#define SPMI_OBSERVER_BASE 0xc440000', '#define FD_BASE 0xa7100000', '#define FD_SIZE 0x300000']) + '\n')
    commands = [
        ['clang', '--target=aarch64-none-elf', '-I', str(work), '-c', str(ROOT.parent / 'uefi-pdx234/BootShim/Pdx234Combo.S'), '-o', str(work / 'combo.o')],
        ['ld.lld', '--image-base=0', '-Ttext=0', '-e', '_Head', str(work / 'combo.o'), '-o', str(work / 'combo.elf')],
        ['llvm-objcopy', '-O', 'binary', str(work / 'combo.elf'), str(work / 'combo.Image')]]
    for command in commands:
        subprocess.run(command, check=True)
    combo = (work / 'combo.Image').read_bytes()
    fd_at = 0x200000 + memory
    metadata = struct.unpack('<8sIIQQQIIQQQQ', combo[-80:])
    if (metadata[:3] != (b'PXCBHOF1', 2, 80) or
            combo[metadata[-2]:metadata[-2] + metadata[-1]] != blob or
            combo[0x200000:0x200000 + len(baseline['android'])] != baseline['android'] or
            combo[fd_at:fd_at + len(baseline['fd'])] != baseline['fd']):
        raise ValueError('Transport/Android/firmware identity differs')
    header = bytearray(baseline['raw'][:4096])
    struct.pack_into('<II', header, 8, len(combo), 0); struct.pack_into('<I', header, 1580, 0)
    image = header + combo + bytes(-len(combo) % 4096)
    if len(image) > 128 * 1024**2:
        raise ValueError('Boot capacity exceeded')
    return image, blob, commands


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', '--release055', dest='release', type=Path, required=True)
    parser.add_argument('--metal-runtime', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    helpers = load('refresh_helpers', 'package-d27-reviewed-native.py')
    helpers.require_space()
    if args.out.exists() or args.work.exists():
        parser.error('Use new work and output directories')
    work = args.work.resolve(); work.mkdir(parents=True)
    baseline = helpers.readback(args.release, work / 'baseline-readback.log')
    record = baseline['j']
    config, arguments, title = config_update(record, baseline['get']('EFI/UniXNU/unixnu.toml').decode())
    runtime_path, runtime = helpers.receipt(args.metal_runtime)
    if runtime['addon_sha256'] != ADDON_SHA or runtime['trust_sha256'] != TRUST_SHA:
        raise ValueError('056 requires the supplied strip-fixed-addon-001 package')
    helpers.validate_metal(runtime, baseline['get']('EFI/UniXNU/Payloads/kernel.macho.trustcache'))
    plugin_path = Path(runtime['plugin_source']).parent / 'result.json'
    plugin = json.loads(plugin_path.read_text())
    if (runtime.get('source_adapter') != plugin or not plugin.get('build_verified') or
            not plugin.get('dlopen_diagnostic') or not plugin.get('macho_strip_validator_sha256')):
        raise ValueError('Require built dlopen diagnostics and checked stripper provenance')
    if helpers.sha((ROOT / 'scripts/ci/strip-d27-macho.py').read_bytes()) != plugin['macho_strip_validator_sha256']:
        raise ValueError('Strip validator source identity changed')
    addon_checks = validate_addon(runtime, work, helpers)
    fatfile = work / 'payload.fat'; fatfile.write_bytes(baseline['fat'])
    before = helpers.fat_inventory(fatfile)
    config_path = work / 'unixnu.toml'; config_path.write_text(config)
    os.utime(config_path, (315532800, 315532800))
    replacements = [(config_path, 'EFI/UniXNU/unixnu.toml'),
                    (Path(runtime['addon']), 'EFI/UniXNU/Payloads/kernel.macho.gpuaddon'),
                    (Path(runtime['trust']), 'EFI/UniXNU/Payloads/kernel.macho.trustcache')]
    for local, remote in replacements:
        subprocess.run(['mcopy', '-o', '-m', '-i', str(fatfile), str(local), '::/' + remote], check=True)
    after = helpers.fat_inventory(fatfile)
    changed = {key for key in before.keys() | after.keys() if before.get(key) != after.get(key)}
    if before.keys() != after.keys() or changed != {remote for _, remote in replacements}:
        raise ValueError('Unexpected FAT delta: ' + repr(changed))
    for local, remote in replacements:
        if after[remote] != helpers.sha(local.read_bytes()):
            raise ValueError('FAT replacement differs: ' + remote)
    if after['EFI/UniXNU/Payloads/kernel.macho'] != KERNEL_SHA:
        raise ValueError('055 sealed kernel changed')
    helpers.write_json(work / 'payload-files.json', {'before': before, 'after': after, 'changed': sorted(changed)})
    fat = fatfile.read_bytes()
    image, blob, commands = pack_transport(baseline, fat, work, helpers)
    helpers.require_space(); args.out.mkdir(parents=True)
    target = args.out.resolve() / 'boot-pdx234-pac-abi-056.img'; target.write_bytes(image)
    record = copy.deepcopy(record)
    # Replace runtime provenance wholesale; keep all native/PAC/screen/seal data.
    for key in ('metal_startup_evidence', 'metal_startup_evidence_sha256'):
        record.pop(key, None)
    record.update(image=str(target), bytes=len(image), sha256=helpers.sha(image), label='PAC-ABI-056', staging_only=False,
        source_image_sha256=BASELINE_SHA, source_release=str(args.release.resolve()),
        kernel_args=arguments, screen_build_tag='PDX056', menu_title=title,
        arguments_removed=['build-tag=PDX055'], arguments_added=['build-tag=PDX056'],
        baseline_arguments_unchanged=False, payload_sha256=helpers.sha(fat), bundle_sha256=helpers.sha(blob),
        metal_runtime=runtime, metal_runtime_receipt=str(runtime_path), metal_runtime_receipt_sha256=helpers.sha(runtime_path.read_bytes()),
        metal_plugin_receipt=str(plugin_path), metal_plugin_receipt_sha256=helpers.sha(plugin_path.read_bytes()),
        metal_refresh_checks=addon_checks, comparison_release=str(args.release.resolve()),
        runtime_qemu_evidence=dict(run='004', source='parent session reported actual D27 overlay execution',
            tested_turnip_sha256=TURNIP_SHA, variant='legacy with LLVM23 strip',
            dlopen_succeeded=True, dlsym_succeeded=True, dlclose_succeeded=True,
            vulkan_initialization_verified=False, metal_rendering_verified=False, handset_verified=False,
            packaged_plugin_guest_execution_verified=False),
        comparison_image_sha256=BASELINE_SHA, comparison_kernel_byte_identity=True,
        correction='056: checked LLVM23 strip and dlopen diagnostics; retain055 kernel/firmware/CDC-off/GPU-on',
        hardware_boot_verified=False, desktop_verified=False, usb_hardware_verified=False, device_writes=False)
    helpers.write_json(args.out / 'release.json', record)
    (args.out / 'SHA256SUMS').write_text(record['sha256'] + '  ' + target.name + '\n')
    final = helpers.readback(args.out, work / 'final-readback.log')
    if final['fat'] != fat or final['fd'] != baseline['fd'] or final['android'] != baseline['android']:
        raise ValueError('Final independent readback differs')
    helpers.write_json(work / 'report.json', {'image_sha256': record['sha256'], 'kernel_sha256': KERNEL_SHA,
        'firmware_sha256': FIRMWARE_SHA, 'payload_files_changed': sorted(changed), 'commands': commands,
        'addon_checks': addon_checks, 'native_rebuilt': False, 'kernel_resealed': False,
        'packager_sha256': helpers.sha(Path(__file__).read_bytes()), 'device_operations': False})
    print(json.dumps({k: record[k] for k in ('image', 'sha256', 'payload_kernel_sha256', 'firmware_sha256')}, indent=2))


if __name__ == '__main__':
    main()
