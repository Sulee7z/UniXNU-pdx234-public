#!/usr/bin/env python3
"""Pack Sony's volume-up-gated iOS menu, preserving direct Android; never flash it."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import zlib

PROJECT = Path('/mnt/g/UniXNU-Port')
DEVICE = PROJECT / 'ports/UniXNU-pdx234'
UEFI = PROJECT / 'ports/uefi-pdx234'
CAPTURE = PROJECT / 'evidence/Xperia-XQ-DQ72/20261107T092807Z'
SHA = '92321cba44b4d5f32355e694ed918125b8e56810ff2580b7a904cef0f719549f'
ANDROID_OFFSET = 2 << 20


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fd', type=Path, required=True)
    parser.add_argument('--attempt', required=True)
    args = parser.parse_args()
    if not args.attempt.isalnum():
        raise RuntimeError('Use an alphanumeric fresh attempt label')
    out = DEVICE / 'out' / ('combo-probe-' + args.attempt)
    out.mkdir()
    stock = (CAPTURE / 'boot.img').read_bytes()
    if digest(stock) != '8594665ff61aa8c8c2be5772fa9af845ee70f636cd0c46e6d59967c5f0400a45':
        raise RuntimeError('Current Android capture changed')
    size, ramdisk_size = struct.unpack_from('<II', stock, 8)
    original = stock[4096:4096+size]
    if (digest(original) != SHA or original[56:60] != b'ARM\x64' or ramdisk_size or
            struct.unpack_from('<I', stock, 40)[0] != 4):
        raise RuntimeError('Android current kernel/header differs')
    text_offset, memory_size, flags = struct.unpack_from('<QQQ', original, 8)
    if text_offset or memory_size < len(original) or flags != 0xa:
        raise RuntimeError('Unexpected original ARM64 Image placement contract')
    fd = args.fd.read_bytes()
    if len(fd) != 0x300000:
        raise RuntimeError('Sony firmware is not the configured 3MiB FD')
    subprocess.run([sys.executable, str(DEVICE / 'scripts/check-firmware-services.py'), str(args.fd),
                    '--report', str(out / 'firmware-service-check.json')], check=True)
    source = UEFI / 'BootShim/Pdx234Combo.S'
    kernel_file = out / 'Android.original.Image'
    kernel_file.write_bytes(original)
    include = out / 'Pdx234ComboInputs.h'
    include.write_text('\n'.join([
        f'#define ANDROID_INPUT_PATH "{kernel_file}"', f'#define UEFI_FD_INPUT_PATH "{args.fd.resolve()}"',
        f'#define ANDROID_MEMORY_BYTES 0x{memory_size:x}', f'#define ANDROID_IMAGE_FLAGS 0x{flags:x}',
        f'#define ANDROID_IMAGE_BYTES {len(original)}', f'#define ANDROID_IMAGE_CRC32 0x{zlib.crc32(original):x}',
        f'#define ANDROID_PAYLOAD_OFFSET 0x{ANDROID_OFFSET:x}',
        '#define SPMI_CORE_BASE 0xc400000', '#define SPMI_OBSERVER_BASE 0xc440000',
        '#define FD_BASE 0xa7100000', '#define FD_SIZE 0x300000'])+'\n')
    obj = out / 'combo.o'
    subprocess.run(['clang', '--target=aarch64-none-elf', '-I', str(out), '-c', str(source), '-o', str(obj)], check=True)
    elf = out / 'combo.elf'
    subprocess.run(['ld.lld', '-Ttext=0', '-e', '_Head', str(obj), '-o', str(elf)], check=True)
    raw_path = out / 'combo.Image'
    subprocess.run(['llvm-objcopy', '-O', 'binary', str(elf), str(raw_path)], check=True)
    combined = raw_path.read_bytes()
    expected_size = ANDROID_OFFSET + memory_size + len(fd) + 64
    if (len(combined) != expected_size or combined[56:60] != b'ARM\x64' or
            struct.unpack_from('<QQQ', combined, 8) != (0, expected_size, flags) or
            combined[ANDROID_OFFSET:ANDROID_OFFSET+len(original)] != original or
            combined[ANDROID_OFFSET+memory_size:-64] != fd or combined[-64:-56] != b'PXCBHOF1'):
        raise RuntimeError('Composite byte/header/placement verification failed')
    # Keep the existing Android boot header and OS version. Do not attach stale AVB signatures.
    header = bytearray(stock[:4096])
    struct.pack_into('<I', header, 8, len(combined))
    struct.pack_into('<I', header, 12, 0)
    struct.pack_into('<I', header, 1580, 0)
    image = bytes(header)+combined+bytes(-len(combined)%4096)
    if len(image) > len(stock):
        raise RuntimeError('Probe exceeds the actual Sony boot partition capacity')
    image_file = out / 'boot-pdx234-menu-CANDIDATE.img'
    image_file.write_bytes(image)
    disassembly = subprocess.check_output(['llvm-objdump', '-d', str(elf)], text=True)
    (out / 'combo-disassembly.txt').write_text(disassembly)
    report = dict(result='volume-up-ios-menu-candidate-packaged', image=str(image_file), image_bytes=len(image),
                  image_sha256=digest(image), original_android_sha256=SHA, android_payload_offset=ANDROID_OFFSET,
                  original_android_code_unchanged=True, current_init_boot_vendor_boot_dtbo_unchanged=True,
                  header_version=4, outer_text_offset=0, fd_destination='0xa7100000',
                  source_sha256=digest(source.read_bytes()), fd_sha256=digest(fd),
                  selector='default original Android before UEFI; held Sony PON RESIN bit6 volume-up -> iOS boot menu; volume-down is not a selector',
                  menu_contains_android_entry=False,
                  device_operations=False, hardware_boot_verified=False, iphone_ios27_boot_ready=False,
                  avb_signed=False, approved_for_boot_partition_flash=False,
                  limitation='Local volume-up menu candidate. iOS payload remains unavailable/disabled. No automatic flash authorization; direct Android and hardware key selection require device verification')
    (out / 'probe.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
