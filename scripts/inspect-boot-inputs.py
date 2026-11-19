#!/usr/bin/env python3
"""Inspect captured Android boot images and live FDT without changing them."""
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

PROJECT = Path(__file__).resolve().parents[3]
INPUT = PROJECT / 'evidence/Xperia-XQ-DQ72/20261107T092807Z'
OUT = PROJECT / 'diagnostics/xperia-boot-audit-20261107'
sys.path.insert(0, str(PROJECT / 'references/xperia-mainline-20261107/scripts'))
from unixnu.devicetree import read_fdt, registers


def align(value, page=4096):
    return (value + page - 1) // page * page


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def avb(raw):
    if raw[-64:-60] != b'AVBf':
        return None
    major, minor, original, offset, size = struct.unpack_from('>IIQQQ', raw, len(raw)-60)
    if offset + size > len(raw)-64:
        raise ValueError('AVB metadata outside image')
    return dict(version=[major, minor], original_image_bytes=original, vbmeta_offset=offset, vbmeta_bytes=size)


def boot(name):
    raw = (INPUT / (name + '.img')).read_bytes()
    if raw[:8] != b'ANDROID!':
        raise ValueError('Unexpected boot magic')
    version = struct.unpack_from('<I', raw, 40)[0]
    if version not in (3, 4):
        raise ValueError('This audit expects Xperia GKI v3/v4')
    kernel_size, ramdisk_size, os_version, header_size = struct.unpack_from('<4I', raw, 8)
    if header_size != (1580 if version == 3 else 1584):
        raise ValueError('Unexpected GKI header size')
    kernel_at, ramdisk_at = 4096, 4096 + align(kernel_size)
    if ramdisk_at + ramdisk_size > len(raw):
        raise ValueError('GKI sections exceed partition')
    kernel = raw[kernel_at:kernel_at + kernel_size]
    ramdisk = raw[ramdisk_at:ramdisk_at + ramdisk_size]
    result = dict(partition_bytes=len(raw), image_sha256=sha(raw), header_version=version,
                  kernel_bytes=kernel_size, kernel_sha256=sha(kernel),
                  ramdisk_bytes=ramdisk_size, ramdisk_sha256=sha(ramdisk),
                  kernel_offset=kernel_at, ramdisk_offset=ramdisk_at,
                  signature_bytes=struct.unpack_from('<I', raw, 1580)[0] if version == 4 else 0,
                  os_version_raw=hex(os_version), avb_footer=avb(raw))
    if kernel:
        (OUT / 'current-android-kernel.bin').write_bytes(kernel)
        result['compressed_magic_hex'] = kernel[:16].hex()
        decoded = gzip.decompress(kernel) if kernel[:2] == b'\x1f\x8b' else kernel
        if decoded != kernel:
            (OUT / 'current-android-kernel.decoded.bin').write_bytes(decoded)
        result['decoded_bytes'] = len(decoded)
        result['arm64_image_header'] = decoded[56:60] == b'ARM\x64'
        result['linux_version_strings'] = [s.decode('utf-8', 'replace') for s in
            re.findall(rb'Linux version [^\x00\r\n]{1,500}', decoded)[:5]]
    return result


def vendor():
    raw = (INPUT / 'vendor_boot.img').read_bytes()
    if raw[:8] != b'VNDRBOOT':
        raise ValueError('Unexpected vendor_boot magic')
    version, page, kernel_addr, ramdisk_addr, rd_size = struct.unpack_from('<5I', raw, 8)
    tags = struct.unpack_from('<I', raw, 2076)[0]
    header, dtb_size, dtb_addr = struct.unpack_from('<IIQ', raw, 2096)
    rd_at, dtb_at = align(header, page), align(header, page) + align(rd_size, page)
    if version not in (3, 4) or dtb_at + dtb_size > len(raw):
        raise ValueError('Invalid vendor_boot extent/version')
    dtb = raw[dtb_at:dtb_at+dtb_size]
    (OUT / 'vendor-boot.dtb').write_bytes(dtb)
    result = dict(partition_bytes=len(raw), header_version=version, page_bytes=page,
                  kernel_address=hex(kernel_addr), ramdisk_address=hex(ramdisk_addr), tags_address=hex(tags),
                  vendor_ramdisk_bytes=rd_size, vendor_ramdisk_sha256=sha(raw[rd_at:rd_at+rd_size]),
                  dtb_bytes=dtb_size, dtb_address=hex(dtb_addr), dtb_sha256=sha(dtb), avb_footer=avb(raw))
    if version == 4:
        table_size, count, entry_size, config_size = struct.unpack_from('<4I', raw, 2112)
        table_at = dtb_at + align(dtb_size, page)
        config_at = table_at + align(table_size, page)
        if table_size != count * entry_size or entry_size < 108 or config_at + config_size > len(raw):
            raise ValueError('Invalid vendor ramdisk table')
        entries = []
        for index in range(count):
            at = table_at + index * entry_size
            size, offset, kind = struct.unpack_from('<3I', raw, at)
            if offset + size > rd_size:
                raise ValueError('Vendor ramdisk entry outside ramdisk')
            entries.append(dict(bytes=size, offset=offset, type=kind,
                                name=raw[at+12:at+44].split(b'\0')[0].decode('utf-8', 'replace')))
        result.update(ramdisk_table=entries, bootconfig_bytes=config_size)
    return result


def pathname(node):
    return '/' if node.parent is None else pathname(node.parent).rstrip('/') + '/' + node.name


def props(node):
    result = {}
    for name, raw in node.properties.items():
        if name in ('phandle', 'linux,phandle'):
            continue
        string_property = (name in ('model', 'compatible', 'device_type', 'status', 'label', 'method',
                                   'enable-method', 'phy-names', 'reset-names', 'reg-names', 'clock-names',
                                   'interrupt-names', 'interconnect-names', 'power-domain-names') or
                           name.endswith(('-name', '-names')))
        if string_property and raw and raw.endswith(b'\0') and all(32 <= b < 127 or b == 0 for b in raw):
            result[name] = raw.rstrip(b'\0').decode().split('\0')
        elif len(raw) % 4 == 0:
            result[name] = [hex(n) for n in struct.unpack(f'>{len(raw)//4}I', raw)]
        else:
            result[name] = {'bytes': len(raw), 'hex': raw.hex()}
    return result


def main():
    if (OUT / 'audit.json').exists():
        raise RuntimeError('Preserve the completed input audit')
    OUT.mkdir(exist_ok=True)
    root = read_fdt((INPUT / 'live.dtb').read_bytes())
    selected = []
    for node in root.walk():
        path = pathname(node)
        compat = '\0'.join(node.strings('compatible'))
        if (path in ('/', '/memory', '/cpus', '/reserved-memory') or path.startswith('/cpus/') or
                path.startswith('/reserved-memory/') or
                re.search(r'ufs|gic|psci|timer|kgsl|gpu|dsi|panel|touch|lxs|lge|smmu|simple-framebuffer',
                          path + ' ' + compat, re.I)):
            item = dict(path=path, enabled=node.enabled(), properties=props(node))
            if 'reg' in node.properties:
                try:
                    item['register_ranges'] = [{'address': hex(a), 'bytes': hex(b)} for a, b in registers(node)]
                except Exception as error:
                    item['register_decode_error'] = str(error)
            selected.append(item)
    result = dict(boot=boot('boot'), init_boot=boot('init_boot'), vendor_boot=vendor(),
                  live_dtb_sha256=sha((INPUT / 'live.dtb').read_bytes()), hardware=selected,
                  phone_operations=False, kernel_source_role='reference only; preserve captured active Android kernel',
                  bootloader={'user_reports_unlocked': True, 'getprop_values_masked': True,
                              'proc_bootconfig_verifiedbootstate': 'orange',
                              'fastboot_unlock_status_not_queried': True})
    with (OUT / 'audit.json').open('x') as target:
        json.dump(result, target, indent=2)
    print(json.dumps({k:v for k,v in result.items() if k != 'hardware'}, indent=2))
    print('Hardware nodes:', len(selected), 'Output:', OUT)


if __name__ == '__main__':
    main()
