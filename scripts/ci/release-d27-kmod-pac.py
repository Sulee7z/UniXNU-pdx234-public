#!/usr/bin/env python3
"""Package the kmod PAC adaptation while preserving the tested DIAG-004 ADT.

No source/kernel rebuild, new platform seed, argument change or device write.
Only the audited kmod fixups and menu label differ from DIAG-004.
"""
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
import zlib

DEVICE = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(command, log, env=None):
    with log.open('x') as stream:
        done = subprocess.run(list(map(str, command)), env=env, stdout=stream, stderr=subprocess.STDOUT)
    if done.returncode:
        raise RuntimeError(log.read_text()[-6000:])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--strict', required=True, type=Path)
    parser.add_argument('--payload', required=True, type=Path)
    parser.add_argument('--boot', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    for path in (args.payload, args.boot, args.out):
        if path.exists():
            parser.error('Use new output directories: ' + str(path))
    baseline = BASE / 'payload-root-004'
    info = json.loads((baseline / 'report.json').read_text())
    for name, expected in (('kernel.macho', info['kernel_sha256']),
                           ('kernel.macho.adt', info['adt_sha256']),
                           ('payload.fat', info['payload_sha256'])):
        if sha(baseline / name) != expected:
            raise ValueError('Baseline input changed: ' + name)
    strict = json.loads((args.strict / 'kernel.json').read_text())
    adaptation = json.loads((args.strict / 'result.json').read_text())
    if (sha(args.strict / 'kernel.macho') != strict['candidate_sha256'] or
            strict['missing'] or strict['stubbed'] or strict['allow_missing'] or
            adaptation['only_kmod_diversifiers_changed'] is not True):
        raise ValueError('Need the verified strict kmod-PAC adaptation')
    payload = args.payload
    payload.mkdir(parents=True)
    shutil.copytree(baseline / 'stage', payload / 'stage')
    for name in ('Android.original.Image', 'kernel.macho.adt', 'platform-seed', 'payload.fat'):
        shutil.copyfile(baseline / name, payload / name)
    shutil.copyfile(args.strict / 'kernel.macho', payload / 'kernel.macho')
    run([sys.executable, '-B', DEVICE / 'scripts/patch-panic-screen.py',
         '--kernel', payload / 'kernel.macho', '--mainline', BASE / 'sources/UniXNU',
         '--uefi', DEVICE.parent / 'uefi-pdx234'], payload / 'panic-patch.log')
    env = dict(os.environ, UNIXNU_XNU_ARCH='arm64e', UNIXNU_IOS_VERSION='27.0')
    run([sys.executable, '-B', BASE / 'sources/UniXNU/scripts/seal-source-crypto-kernel.py',
         payload / 'kernel.macho', '--kernel-args', info['kernel_args']], payload / 'seal.log', env)
    panic = json.loads((payload / 'kernel.panic-screen.json').read_text())
    seal = json.loads((payload / 'kernel.macho.crypto-hmac.json').read_text())
    new = (payload / 'kernel.macho').read_bytes()
    old = (baseline / 'kernel.macho').read_bytes()
    # Panic code/HMAC must be identical to DIAG-004; only the ABI fields differ.
    if len(new) != len(old) or sum(a != b for a, b in zip(new, old)) != adaptation['changed_bytes']:
        raise ValueError('Unexpected difference from the tested diagnostic kernel')
    if seal['kernel_sha256'] != sha(payload / 'kernel.macho'):
        raise ValueError('Crypto seal identity differs')
    shutil.copyfile(payload / 'kernel.macho', payload / 'stage/EFI/UniXNU/Payloads/kernel.macho')
    config = payload / 'stage/EFI/UniXNU/unixnu.toml'
    text = config.read_text()
    if text.count('DIAG-004') != 1:
        raise ValueError('Unexpected baseline menu label')
    config.write_text(text.replace('DIAG-004', 'DIAG-005 KMOD-PAC'))
    for file in (config, payload / 'kernel.macho'):
        os.utime(file, (315532800, 315532800))
    fat = payload / 'payload.fat'
    for local, remote in ((payload / 'kernel.macho', 'Payloads/kernel.macho'), (config, 'unixnu.toml')):
        subprocess.run(['mcopy', '-o', '-m', '-i', str(fat), str(local), '::/EFI/UniXNU/' + remote], check=True)
    # Every payload file is independently extracted and compared.
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
        raise ValueError('Compressed FAT roundtrip differs')
    bundle = struct.pack('<8s4IQ', b'PDXFAT02', 32, len(compressed), len(raw), zlib.crc32(raw), 0) + compressed
    (payload / 'payload.bundle').write_bytes(bundle)
    info.update(kernel_sha256=sha(payload / 'kernel.macho'), strict_source_kernel_sha256=strict['candidate_sha256'],
                strict_report=strict, entry_probe=panic, crypto_seal=seal,
                payload_sha256=sha(fat), bundle_sha256=sha(payload / 'payload.bundle'),
                bundle_bytes=len(bundle), kmod_pac_adaptation=adaptation,
                baseline_adt_byte_identity=True, baseline_arguments_unchanged=True)
    (payload / 'report.json').write_text(json.dumps(info, indent=2) + '\n')
    run([sys.executable, '-B', DEVICE / 'scripts/ci/audit-darwinboot-parser.py',
         '--darwinboot', DEVICE / '.cache/firmware-components/DarwinBoot',
         '--kernel', payload / 'kernel.macho', '--report', payload / 'darwinboot-parser.json'],
        payload / 'parser.log')
    run([sys.executable, '-B', BASE / 'pack-sony-strict-boot.py', '--payload', payload,
         '--fd', DEVICE / 'out/firmware-fat013/SILICIUM_UEFI.fd', '--out', args.boot],
        payload / 'pack.log')
    boot = json.loads((args.boot / 'report.json').read_text())
    args.out.mkdir(parents=True)
    image = args.out / 'boot-pdx234-sheng27-root-diag005.img'
    shutil.copyfile(args.boot / 'boot-pdx234-dual-xnu-entry-CANDIDATE.img', image)
    if sha(image) != boot['image_sha256'] or image.stat().st_size != boot['image_bytes']:
        raise ValueError('Delivered image differs')
    release = dict(image=str(image), bytes=image.stat().st_size, sha256=sha(image), label='DIAG-005 KMOD-PAC',
                   strict_kernel_sha256=strict['candidate_sha256'], patched_kernel_sha256=info['kernel_sha256'],
                   original_android_sha256=boot['android_kernel_sha256'], android_byte_identity=True,
                   adt_sha256=info['adt_sha256'], adt_byte_identical_to_diag004=True,
                   kernel_args=info['kernel_args'], kernel_arguments_unchanged=True,
                   kmod_pac_adaptation=adaptation, panic_screen=panic, crypto_seal=seal,
                   loader_parser_accepted=True, strict_missing={}, strict_stubbed={}, allow_missing=False,
                   default_boot='Android', menu_default='restart', xnu_explicit_confirmation=True,
                   device_writes=False, hardware_boot_verified=False, root_mount_verified=False,
                   springboard_verified=False, log_first_block=16769024, log_blocks=8192,
                   export_first_block=16703488, export_blocks=65536,
                   notes='Only the audited kmod PAC diversifiers and menu label change versus DIAG-004.')
    (args.out / 'release.json').write_text(json.dumps(release, indent=2) + '\n')
    (args.out / 'SHA256SUMS').write_text(release['sha256'] + '  ' + image.name + '\n')
    for name in ('darwinboot-parser.json', 'kernel.panic-screen.json'):
        shutil.copyfile(payload / name, args.out / name)
    print(json.dumps({k: release[k] for k in ('image', 'bytes', 'sha256', 'strict_kernel_sha256')}, indent=2), flush=True)


if __name__ == '__main__':
    main()
