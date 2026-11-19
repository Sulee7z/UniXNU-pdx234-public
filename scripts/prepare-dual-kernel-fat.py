#!/usr/bin/env python3
"""Prepare a standard FAT16 XNU probe payload and a Mu LZMA transport bundle."""
import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import secrets
import shutil
import struct
import subprocess
import sys
import tomllib
import zlib

DEVICE = Path(__file__).resolve().parents[1]
PROJECT = DEVICE.parents[1]
KERNEL_SHA = '098469d880049ad9f1811c3e893874fa56cba72957200fcb4dad756627af0efe'
ANDROID_SHA = '92321cba44b4d5f32355e694ed918125b8e56810ff2580b7a904cef0f719549f'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(*command):
    subprocess.run(list(map(str, command)), check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', required=True, type=Path)
    parser.add_argument('--kernel', required=True, type=Path)
    parser.add_argument('--mainline', required=True, type=Path)
    parser.add_argument('--soc', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--strict-report', type=Path, help='Explicit new strict report')
    parser.add_argument('--diagnostic-report', type=Path, help='Traced diagnostic derivative report')
    parser.add_argument('--ufs-test', action='store_true', help='Sony-only diagnostic menu')
    parser.add_argument('--ufs-complete', action='store_true', help='One controller/GPT diagnostic entry')
    args = parser.parse_args()
    if args.ufs_complete and not args.ufs_test:
        parser.error('--ufs-complete requires --ufs-test')
    args.out.mkdir(parents=True, exist_ok=False)
    manifest = json.loads((args.capture / 'manifest.json').read_text())
    if manifest['serial'] != 'PDX_DEVICE_SERIAL' or manifest['slot'] not in ('_a', '_b'):
        raise ValueError('Require verified Sony capture')
    for part in manifest['partitions']:
        p = args.capture / (part['label'].removesuffix(manifest['slot']) + '.img')
        if not part['matched'] or sha(p.read_bytes()) != part['sha256']:
            raise ValueError(f'Capture mismatch: {p}')
    stock = (args.capture / 'boot.img').read_bytes()
    n = struct.unpack_from('<I', stock, 8)[0]
    field = stock[4096:4096+n]
    if sha(field) == ANDROID_SHA:
        android = field
    else:
        if len(field) < 0x200000 + 50964992 or field[-64:-56] != b'PXCBHOF1':
            raise ValueError('Current boot is neither pinned Android nor recognized v1 wrapper')
        android = field[0x200000:0x200000+50964992]
    if sha(android) != ANDROID_SHA:
        raise ValueError('Embedded current Android kernel changed')
    original_boot_path = PROJECT / 'evidence/Xperia-XQ-DQ72/20261107T092807Z/boot.img'
    original_boot = original_boot_path.read_bytes()
    if sha(original_boot) != '8594665ff61aa8c8c2be5772fa9af845ee70f636cd0c46e6d59967c5f0400a45':
        raise ValueError('Original Android boot backup changed')
    original_bytes = struct.unpack_from('<I', original_boot, 8)[0]
    original_android = original_boot[4096:4096+original_bytes]
    if sha(original_android) != ANDROID_SHA or android != original_android:
        raise ValueError('Installed wrapper Android differs from original boot kernel')
    # Actual input comes from the original boot. The active wrapper is comparison evidence only.
    android = original_android
    (args.out / 'Android.original.Image').write_bytes(android)
    kernel = args.kernel.read_bytes()
    report = json.loads((args.strict_report or args.kernel.with_suffix('.json')).read_text())
    expected = report['candidate_sha256'] if args.strict_report else KERNEL_SHA
    diagnostic = json.loads(args.diagnostic_report.read_text()) if args.diagnostic_report else None
    if diagnostic:
        if diagnostic['source_kernel_sha256'] != expected or diagnostic['patched_kernel_sha256'] != sha(kernel):
            raise ValueError('Diagnostic derivative identity differs')
        expected = diagnostic['patched_kernel_sha256']
    if (sha(kernel) != expected or report['missing'] or report['stubbed'] or report['allow_missing'] or
            report['inputs']['kernelcache_sha256'] != 'c28f4fc9b83cde00087e81f890c82d566b9e98b5ac228dfecd83afdf34070445'):
        raise ValueError('Require exact strict D27 native kernel')
    (args.out / 'kernel.macho').write_bytes(kernel)
    sys.path.insert(0, str(args.mainline / 'scripts'))
    from unixnu.devicetree import read_fdt, registers, generate
    from unixnu.profiles import merge
    live_path = args.capture / 'live.dtb'
    live = live_path.read_bytes()
    if sha(live) != manifest['live_fdt']['sha256']:
        raise ValueError('Live FDT changed')
    root = read_fdt(live)
    banks = [pair for node in root.walk() if node.strings('device_type') == ['memory']
             for pair in registers(node) if pair[1]]
    # Early-entry probe exposes one actual bank, not a fabricated span over sparse DRAM.
    bank = (0x880000000, 0x39d00000)
    if bank not in banks:
        raise ValueError('Selected real high DRAM bank is no longer present')
    dts = (DEVICE / 'dts/pdx234.dts').read_text()
    dts, count = re.subn(r'(memory@80000000\s*\{.*?reg\s*=).*?;',
                         r'\1 <8 0x80000000 0 0x39d00000>;', dts, count=1, flags=re.S)
    if count != 1:
        raise ValueError('Sony DTS memory declaration changed')
    source = args.out / 'pdx234-entry-window.dts'
    source.write_text(dts)
    dtb = args.out / 'pdx234-entry-window.dtb'
    run('dtc', '-I', 'dts', '-O', 'dtb', '-i', args.soc / 'dts', '-o', dtb, source)
    config = merge(tomllib.loads((DEVICE / 'profiles/ios-27.0.1-24A446-iphone14/profile.toml').read_text()),
                   tomllib.loads((DEVICE / 'board.toml').read_text()))
    # Sheng 27 reports a virtual platform on real SM8550 boards without Apple
    # PMGR/SEP. Preserve the board value; do not replace it with a QEMU guess.
    vmm_present = config['adt']['defaults']['u32']['vmm-present']
    if vmm_present != 1:
        raise ValueError('Sony SM8550/27 requires board vmm-present=1 (no Apple PMGR/SEP)')
    config['payload']['adt']['owned_memory_size'] = '0x10000000'
    # Local random platform seed, not an Apple hardware ECID; retained only in ignored build output.
    seed = f'{secrets.randbits(64) or 1:016x}'
    (args.out / 'platform-seed').write_text(seed + '\n')
    adt = generate(dtb, config, unique_chip_id=seed)
    import importlib.util
    spec = importlib.util.spec_from_file_location('apple_device_tree', DEVICE / 'scripts/apple-device-tree.py')
    codec = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(codec)
    if codec.u32(codec.parse(adt), '/defaults', 'vmm-present') != vmm_present:
        raise ValueError('Generated ADT lost the board vmm-present value')
    (args.out / 'kernel.macho.adt').write_bytes(adt)
    stage = args.out / 'stage/EFI/UniXNU'
    (stage / 'Payloads').mkdir(parents=True)
    shutil.copyfile(args.out / 'kernel.macho', stage / 'Payloads/kernel.macho')
    shutil.copyfile(args.out / 'kernel.macho.adt', stage / 'Payloads/kernel.macho.adt')
    command_line = ' '.join(config['payload']['kernel_args'])
    (stage / 'unixnu.toml').write_text(
        'version = 1\n[boot]\ntimeout = -1\nconnect_all = true\n'
        '[ui]\ntitle = "Sony PDX234 XNU entry probe"\n[kits]\nautoload = false\n'
        '[[entry]]\nid = "xnu"\ntitle = "D27 strict XNU - entry test"\ntype = "xnu"\n'
        f'path = "Payloads/kernel.macho"\nargs = "{command_line}"\n'
        'confirm = "Start the XNU entry test?"\n'
        '[[entry]]\nid = "restart"\ntitle = "Restart"\ntype = "action"\naction = "reset"\n'
         '[[entry]]\nid = "shutdown"\ntitle = "Power off"\ntype = "action"\naction = "shutdown"\n')
    if args.ufs_test:
        if not diagnostic:
            raise ValueError('UFS test requires traced panic renderer and entry diagnostics')
        command_line += ' sony-ufs-test=1 native-ufs-diagnostics=1 sheng-log=0'
        entries = ['version=1\n[boot]\ntimeout=-1\nconnect_all=true\n'
                   '[ui]\ntitle="PDX234 D27 UFS diagnostic"\n[kits]\nautoload=false\n']
        modes = ((10, 'Sony UFS - complete read-only check'),) if args.ufs_complete else (
            (2, 'UFS 1 - read controller state'), (10, 'UFS 2 - read GPT, no disk writes'))
        for mode, title in modes:
            entries.append(f'[[entry]]\nid="ufs{mode}"\ntitle="{title}"\ntype="xnu"\n'
                           'path="Payloads/kernel.macho"\n'
                           f'args="{command_line} native-ufs-probe={mode}"\n')
        entries.append('[[entry]]\nid="restart"\ntitle="Restart"\ntype="action"\naction="reset"\n'
                       '[[entry]]\nid="shutdown"\ntitle="Power off"\ntype="action"\naction="shutdown"\n')
        (stage / 'unixnu.toml').write_text(''.join(entries))
    # Seal the exact payload copy after all diagnostic patches and argument selection.
    env = dict(os.environ, UNIXNU_XNU_ARCH='arm64e', UNIXNU_IOS_VERSION='27.0')
    subprocess.run(['python3', '-B', str(args.mainline / 'scripts/seal-source-crypto-kernel.py'),
                    str(args.out / 'kernel.macho'), '--kernel-args', command_line], env=env, check=True)
    kernel = (args.out / 'kernel.macho').read_bytes()
    shutil.copyfile(args.out / 'kernel.macho', stage / 'Payloads/kernel.macho')
    for p in (args.out / 'stage').rglob('*'):
        os.utime(p, (315532800, 315532800))
    image = args.out / 'payload.fat'
    # FAT16, explicitly not mformat -F (FAT32). 88 MiB leaves 10+ MiB spare for files.
    run('mformat', '-C', '-T', 88 * 2048, '-h', 64, '-s', 32, '-N', '534f4e59',
        '-v', 'PDX234XNU', '-i', image, '::')
    run('mcopy', '-i', image, '-s', '-m', args.out / 'stage/EFI', '::/')
    run('mcopy', '-i', image, '::/EFI/UniXNU/Payloads/kernel.macho', args.out / 'fat-kernel-roundtrip')
    if sha((args.out / 'fat-kernel-roundtrip').read_bytes()) != sha(kernel):
        raise ValueError('FAT kernel roundtrip failed')
    (args.out / 'fat-kernel-roundtrip').unlink()
    adt_roundtrip = args.out / 'fat-adt-roundtrip'
    run('mcopy', '-i', image, '::/EFI/UniXNU/Payloads/kernel.macho.adt', adt_roundtrip)
    if adt_roundtrip.read_bytes() != adt:
        raise ValueError('FAT ADT roundtrip failed')
    adt_roundtrip.unlink()
    raw = image.read_bytes()
    compressed = bytearray(lzma.compress(raw, format=lzma.FORMAT_ALONE, preset=6))
    compressed[5:13] = struct.pack('<Q', len(raw))  # Mu decoder requires an explicit decoded size.
    if lzma.decompress(compressed, format=lzma.FORMAT_ALONE) != raw:
        raise ValueError('LZMA transport roundtrip failed')
    header = struct.pack('<8s4IQ', b'PDXFAT02', 32, len(compressed), len(raw), zlib.crc32(raw), 0)
    (args.out / 'payload.bundle').write_bytes(header + compressed)
    result = dict(capture=str(args.capture), current_boot_sha256=sha(stock),
                  android_source_boot=str(original_boot_path),
                  android_source_boot_sha256=sha(original_boot),
                  active_wrapper_embedded_android_matches_original=True,
                   android_sha256=sha(android), kernel_sha256=sha(kernel), adt_sha256=sha(adt),
                   adt_vmm_present=vmm_present, adt_vmm_present_verified_after_generation=True,
                   fat_adt_byte_identity=True,
                  original_live_dram_banks=[[hex(a), hex(s)] for a,s in banks],
                  probe_dram_subset=[hex(v) for v in bank], darwinboot_window_bytes=0x10000000,
                  note='Only one real bank exposed for entry probe; allocation chosen by unmodified DarwinBoot.',
                  payload_bytes=len(raw), payload_sha256=sha(raw), bundle_bytes=len(header+compressed),
                  bundle_sha256=sha(header+compressed), kernel_args=command_line,
                   source_prelink_loadable_field=report.get('loadable'),
                   strict_source_kernel_sha256=report['candidate_sha256'], strict_report=report,
                   diagnostic_derivative=diagnostic,
                   crypto_seal=json.loads((args.out / 'kernel.macho.crypto-hmac.json').read_text()),
                   ufs_diagnostic_only=args.ufs_test,
                  device_writes=False, hardware_boot_verified=False, springboard_verified=False)
    (args.out / 'report.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
