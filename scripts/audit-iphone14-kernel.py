#!/usr/bin/env python3
"""Decode original iPhone14 cache/ADT and inventory fileset identities; no rewriting."""
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

PROJECT = Path('/mnt/g/UniXNU-Port')
DEVICE = PROJECT / 'ports/UniXNU-pdx234'
INPUT = DEVICE / '.cache/iphone14-ios27/ipsw/24A446'
sys.path.insert(0, str(PROJECT / 'references/xperia-mainline-20261107/scripts'))
from unixnu.ipsw import im4p_payload


def decode_adt(raw):
    cursor = 0
    result = []

    def parse(parent):
        nonlocal cursor
        count, children = struct.unpack_from('<II', raw, cursor)
        cursor += 8
        if count > 4096 or children > 4096:
            raise ValueError('Invalid ADT count')
        props = {}
        for _ in range(count):
            name = raw[cursor:cursor+32].split(b'\0')[0].decode()
            size = struct.unpack_from('<I', raw, cursor+32)[0] & 0x7fffffff
            cursor += 36
            props[name] = raw[cursor:cursor+size]
            cursor += (size+3)&~3
            if cursor > len(raw):
                raise ValueError('Truncated ADT')
        name = props.get('name', b'').split(b'\0')[0].decode('utf-8', 'replace')
        path = parent.rstrip('/')+'/'+name
        if path in ('/device-tree', '/device-tree/product', '/device-tree/chosen'):
            fields = {}
            for key, value in props.items():
                if key in ('model', 'compatible', 'target-type', 'product-name', 'product-description',
                           'region-info', 'region-code', 'regulatory-model-number'):
                    fields[key] = value.rstrip(b'\0').decode('utf-8', 'replace')
            result.append({'path': path, 'fields': fields})
        for _ in range(children):
            parse(path)

    parse('')
    return result


def main():
    source = INPUT / 'kernelcache.release.iphone14b'
    packed = INPUT / 'original-kernel.audit.lzfse'
    output = INPUT / 'kernelcache.audit-verified'
    if output.exists():
        raise RuntimeError('Preserve the completed original-kernel inventory')
    packed.write_bytes(im4p_payload(source.read_bytes()))
    subprocess.run(['/root/unixnu-toolchain/bin/lzfse', '-decode', '-i', str(packed), '-o', str(output)], check=True)
    raw = output.read_bytes()
    if raw[:4] == b'\xca\xfe\xba\xbe':
        count = struct.unpack_from('>I', raw, 4)[0]
        slices = [struct.unpack_from('>5I', raw, 8+20*i) for i in range(count)]
        selected = [item for item in slices if item[0] == 0x100000c]
        if len(selected) != 1:
            raise ValueError('No unique ARM64 slice')
        _, _, start, size, _ = selected[0]
        raw = raw[start:start+size]
        output.write_bytes(raw)
    magic, cpu, subtype, filetype, commands, command_bytes = struct.unpack_from('<6I', raw)
    if magic != 0xfeedfacf or cpu != 0x100000c or filetype != 12:
        raise ValueError('Expected original ARM64 fileset')
    cursor, entries = 32, []
    for _ in range(commands):
        cmd, size = struct.unpack_from('<II', raw, cursor)
        if size < 8 or cursor+size > 32+command_bytes:
            raise ValueError('Invalid Mach-O commands')
        if cmd == 0x80000035:
            _, _, va, offset, nameoff, _ = struct.unpack_from('<IIQQII', raw, cursor)
            name = raw[cursor+nameoff:cursor+size].split(b'\0')[0].decode()
            if offset >= len(raw):
                raise ValueError('Fileset entry outside kernelcache')
            entries.append(dict(name=name, vmaddr=hex(va), fileoff=offset))
        cursor += size
    adt = im4p_payload((INPUT / 'DeviceTree.d27ap.im4p').read_bytes())
    if adt.startswith((b'bvx2', b'bvxn', b'bvx-')):
        packed_adt = INPUT / 'DeviceTree.original.lzfse'
        decoded_adt = INPUT / 'DeviceTree.decoded.adt'
        packed_adt.write_bytes(adt)
        subprocess.run(['/root/unixnu-toolchain/bin/lzfse', '-decode', '-i', str(packed_adt), '-o', str(decoded_adt)], check=True)
        adt = decoded_adt.read_bytes()
    else:
        (INPUT / 'DeviceTree.decoded.adt').write_bytes(adt)
    version = [s.decode('utf-8', 'replace') for s in re.findall(rb'Darwin Kernel Version[^\x00\r\n]{1,350}', raw)]
    report = dict(product='iPhone14,7', build='24A446', source='original Apple member',
                  kernelcache_sha256=hashlib.sha256(raw).hexdigest(), kernelcache_bytes=len(raw),
                  cpu_subtype=hex(subtype), filetype='MH_FILESET', fileset_entries=entries,
                  version_strings=version, original_adt_sha256=hashlib.sha256(adt).hexdigest(),
                  original_adt_identity=decode_adt(adt),
                  native_abi_or_runtime_compatibility_proven=False,
                  ipad_addresses_or_root_uuids_reused=False, phone_operations=False)
    (DEVICE / 'evidence/iphone14-ios27-kernel-inventory.json').write_text(json.dumps(report, indent=2))
    print(json.dumps({key: value for key,value in report.items() if key != 'fileset_entries'}, indent=2))
    print('Fileset entries:', len(entries))


if __name__ == '__main__':
    main()
