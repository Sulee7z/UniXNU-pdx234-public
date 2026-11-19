#!/usr/bin/env python3
"""Pack and independently unpack the Sony Android+strict-XNU entry-test image."""
import argparse
import hashlib
import importlib.util
import json
import lzma
from pathlib import Path
import struct
import subprocess
import sys
import zlib

DEVICE = Path(__file__).resolve().parents[1]
PROJECT = DEVICE.parents[1]
ANDROID_SHA = '92321cba44b4d5f32355e694ed918125b8e56810ff2580b7a904cef0f719549f'
KERNEL_SHA = '098469d880049ad9f1811c3e893874fa56cba72957200fcb4dad756627af0efe'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--payload', required=True, type=Path)
    parser.add_argument('--fd', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    info = json.loads((args.payload / 'report.json').read_text())
    payload_kernel = (args.payload / 'kernel.macho').read_bytes()
    payload_kernel_sha = sha(payload_kernel)
    if payload_kernel_sha != info['kernel_sha256']:
        raise ValueError('Payload kernel identity changed')
    if payload_kernel_sha != KERNEL_SHA:
        strict = info.get('strict_report', {})
        diag = info.get('diagnostic_derivative', {})
        traced_new = (strict.get('candidate_written') is True and strict.get('missing') == {} and
                      strict.get('stubbed') == {} and strict.get('allow_missing') is False and
                      strict.get('inputs', {}).get('kernelcache_sha256') ==
                      'c28f4fc9b83cde00087e81f890c82d566b9e98b5ac228dfecd83afdf34070445' and
                      diag.get('source_kernel_sha256') == strict.get('candidate_sha256') and
                      info.get('crypto_seal', {}).get('kernel_sha256') == payload_kernel_sha)
        probe = info.get('entry_probe', {})
        seal = info.get('crypto_seal', {})
        reset = (probe.get('no_reset') is False and probe.get('reset_checkpoint') == 'post-MMU' and
                  probe.get('reset_delay') == 6 and probe.get('timebase_hz') == 19200000)
        call_reset = (probe.get('no_reset') is False and
                      probe.get('reset_checkpoint') == 'after _arm_vm_init in _arm_init' and
                      probe.get('reset_after') == '_arm_vm_init' and probe.get('reset_delay') == 6 and
                      probe.get('timebase_hz') == 19200000)
        if not traced_new and (info.get('source_kernel_sha256') != KERNEL_SHA or
                probe.get('source_kernel_sha256') != KERNEL_SHA or
                 not (probe.get('no_reset') is True or reset or call_reset) or
                probe.get('panic_screen') or seal.get('kernel_sha256') != payload_kernel_sha):
            raise ValueError('Require strict kernel or traced official entry-probe/resealed derivative')
    capture = Path(info['capture'])
    stock = (capture / 'boot.img').read_bytes()
    if sha(stock) != info['current_boot_sha256']:
        raise ValueError('Current capture identity changed')
    original_boot = (PROJECT / 'evidence/Xperia-XQ-DQ72/20261107T092807Z/boot.img').read_bytes()
    if sha(original_boot) != '8594665ff61aa8c8c2be5772fa9af845ee70f636cd0c46e6d59967c5f0400a45':
        raise ValueError('Original Android boot backup changed')
    original = original_boot[4096:4096+struct.unpack_from('<I',original_boot,8)[0]]
    if original != (args.payload / 'Android.original.Image').read_bytes():
        raise ValueError('Payload Android does not match original boot')
    if sha(original) != ANDROID_SHA:
        raise ValueError('Android kernel identity changed')
    memory_size, flags = struct.unpack_from('<QQ', original, 16)
    if original[56:60] != b'ARM\x64' or memory_size < len(original) or flags != 10:
        raise ValueError('Original ARM64 Image contract changed')
    fd = args.fd.read_bytes()
    subprocess.run([sys.executable, str(DEVICE / 'scripts/check-firmware-services.py'), str(args.fd),
                    '--report', str(args.out / 'firmware-check.json')], check=True)
    if len(fd) != 0x300000:
        raise ValueError('Sony FD extent changed')
    bundle = (args.payload / 'payload.bundle').read_bytes()
    magic, header, compressed, expanded, crc, reserved = struct.unpack_from('<8s4IQ', bundle)
    if (magic != b'PDXFAT02' or header != 32 or compressed != len(bundle)-32 or reserved or
            sha(bundle) != info['bundle_sha256']):
        raise ValueError('FAT bundle identity/header mismatch')
    fat = lzma.decompress(bundle[32:], format=lzma.FORMAT_ALONE)
    if len(fat) != expanded or zlib.crc32(fat) != crc or sha(fat) != info['payload_sha256']:
        raise ValueError('FAT transport roundtrip failed')
    source = PROJECT / 'ports/uefi-pdx234/BootShim/Pdx234Combo.S'
    include = args.out / 'Pdx234ComboInputs.h'
    include.write_text('\n'.join([
        f'#define ANDROID_INPUT_PATH "{(args.payload / "Android.original.Image").resolve()}"',
        f'#define UEFI_FD_INPUT_PATH "{args.fd.resolve()}"',
        f'#define XNU_BUNDLE_INPUT_PATH "{(args.payload / "payload.bundle").resolve()}"',
        f'#define ANDROID_MEMORY_BYTES {memory_size}', f'#define ANDROID_IMAGE_FLAGS {flags}',
        f'#define ANDROID_IMAGE_BYTES {len(original)}', f'#define ANDROID_IMAGE_CRC32 {zlib.crc32(original)}',
        '#define ANDROID_PAYLOAD_OFFSET 0x200000', '#define SPMI_CORE_BASE 0xc400000',
        '#define SPMI_OBSERVER_BASE 0xc440000', '#define FD_BASE 0xa7100000', '#define FD_SIZE 0x300000',
    ])+'\n')
    obj, elf, raw = [args.out / name for name in ('combo.o', 'combo.elf', 'combo.Image')]
    commands = [
        ['clang','--target=aarch64-none-elf','-I',str(args.out),'-c',str(source),'-o',str(obj)],
        ['ld.lld','-Ttext=0','-e','_Head',str(obj),'-o',str(elf)],
        ['llvm-objcopy','-O','binary',str(elf),str(raw)],
    ]
    for command in commands:
        subprocess.run(command, check=True)
    combined = raw.read_bytes()
    metadata = struct.unpack('<8sIIQQQIIQQQQ', combined[-80:])
    magic, version, size, android_ptr, android_bytes, fdt_ptr, android_crc, reserved, image_ptr, image_bytes, off, length = metadata
    if ((magic, version, size, android_bytes, android_crc) !=
            (b'PXCBHOF1',2,80,len(original),zlib.crc32(original)) or
            any((android_ptr,fdt_ptr,reserved,image_ptr,image_bytes))):
        raise ValueError('BootShim metadata ABI mismatch')
    fd_off = 0x200000 + memory_size
    if (combined[0x200000:0x200000+len(original)] != original or
            combined[fd_off:fd_off+len(fd)] != fd or combined[off:off+length] != bundle or
            off < fd_off+len(fd) or off+length > len(combined)-80 or
            struct.unpack_from('<QQQ',combined,8) != (0,len(combined),flags)):
        raise ValueError('Composite layout/byte identity mismatch')
    boot_header = bytearray(original_boot[:4096])
    if stock[:8] != b'ANDROID!' or struct.unpack_from('<I',stock,40)[0] != 4:
        raise ValueError('Require Sony boot v4 capture')
    struct.pack_into('<II',boot_header,8,len(combined),0)
    struct.pack_into('<I',boot_header,1580,0)
    image = boot_header + combined + bytes(-len(combined)%4096)
    if len(image) > len(stock):
        raise ValueError('Composite exceeds captured boot partition')
    output = args.out / 'boot-pdx234-dual-xnu-entry-CANDIDATE.img'
    output.write_bytes(image)
    unpacked = output.read_bytes()
    field = unpacked[4096:4096+struct.unpack_from('<I',unpacked,8)[0]]
    if field != combined or sha(field[0x200000:0x200000+len(original)]) != ANDROID_SHA:
        raise ValueError('Final boot unpack failed')
    result = dict(image=str(output),image_bytes=len(image),partition_capacity=len(stock),image_sha256=sha(image),
                  android_kernel_sha256=ANDROID_SHA,xnu_kernel_sha256=payload_kernel_sha,
                   strict_source_kernel_sha256=info.get('strict_source_kernel_sha256', KERNEL_SHA),entry_probe=info.get('entry_probe'),
                  android_source='Original 20261107 boot backup; active wrapper used only for byte comparison',
                  fd_sha256=sha(fd),bundle_sha256=sha(bundle),bundle_offset=off,bundle_bytes=length,
                  boot_source_version=version,boot_source_bytes=size,android_byte_identity=True,
                  xnu_fat_transport_roundtrip=True,boot_header_version=4,boot_ramdisk_bytes=0,
                  init_boot_vendor_boot_dtbo_unchanged=True,device_writes=False,
                  hardware_boot_verified=False,root_mount_verified=False,springboard_verified=False,
                  official_contract='FAT payload, shared UniXNURamDiskDxe/DiskIo/Fat and DarwinBoot',
                  sony_adapter='BootShim v2 compressed FAT transport; device-specific, not an upstream recipe',
                  commands=commands)
    (args.out/'report.json').write_text(json.dumps(result,indent=2)+'\n')
    (args.out/'SHA256SUMS').write_text(f'{sha(image)}  {output.name}\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    main()
