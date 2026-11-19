#!/usr/bin/env python3
"""Qualify live D27 storage metadata against the candidate and native DWARF."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

DEVICE = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--observation', required=True, type=Path)
    parser.add_argument('--kernel', required=True, type=Path)
    parser.add_argument('--dwarf', required=True, type=Path)
    parser.add_argument('--static-audit', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Preserve the existing report')
    raw = args.kernel.read_bytes()
    obs = json.loads(args.observation.read_text())
    static = json.loads(args.static_audit.read_text())
    if obs['kernel_sha256'] != hashlib.sha256(raw).hexdigest():
        raise ValueError('Live candidate identity differs')
    sys.path.insert(0, str(DEVICE / 'ci/XnuPrelink'))
    from kc_image import Image
    collection = Image(raw)
    native = Image(raw, collection.entries['com.apple.kernel'][1])
    symbols = {name: va for va, names in native.symbols().items() for name in names}
    if int(obs['pc'], 16) != symbols['_native_apfs_probe_checkpoint']:
        raise ValueError('Did not reach the post-load checkpoint')
    offsets = {}
    for member in args.dwarf.read_text().split('DW_TAG_member')[1:]:
        for name in ('superClassLink', 'className', 'classSize'):
            if f'("{name}")' in member:
                match = re.search(r'DW_AT_data_member_location\s+\((0x[0-9a-f]+)\)', member)
                if not match:
                    raise ValueError('Missing DWARF member location')
                offsets[name] = int(match[1], 16)
    if offsets != dict(superClassLink=0x10, className=0x18, classSize=0x20):
        raise ValueError('D27 native metaclass layout changed')

    def memory(address, length):
        value = bytes.fromhex(obs['memory'][f'{address:x}:{length:x}'])
        if len(value) != length:
            raise ValueError('Incomplete live memory')
        return value

    block_address = int(static['original_metaclass'], 16)
    service_address = symbols['__ZN9IOService10gMetaClassE']
    block, service = memory(block_address, 0x50), memory(service_address, 0x50)
    parent = struct.unpack_from('<Q', block, offsets['superClassLink'])[0]
    block_size = struct.unpack_from('<I', block, offsets['classSize'])[0]
    service_size = struct.unpack_from('<I', service, offsets['classSize'])[0]
    tcr = int(obs['system_registers']['TCR_EL1'], 16)
    if (parent != service_address or block_size != 0x90 or service_size != 0x88 or
            (tcr >> 14) & 3 != 0 or (tcr >> 30) & 3 != 2 or
            memory(symbols['_native_apfs_load_status'], 4) != bytes(4) or
            static['method_slots'] != 190 or not static['pac_layout_matches']):
        raise ValueError('Live metadata, translation granules or static PAC qualification differ')
    report = dict(target='iPhone14,7 / D27AP / 24A446',
                  candidate_sha256=obs['kernel_sha256'], live_native_4k=True,
                  original_metaclass=hex(block_address), original_superclass=hex(parent),
                  original_class_size=block_size, native_ioservice_size=service_size,
                  native_dwarf_offsets=offsets, method_slots=190, static_pac_layout_matches=True,
                  apfs_load_status=0,
                  apfs_registered=int.from_bytes(memory(symbols['_native_apfs_registered'], 4), 'little'),
                  inputs_sha256={str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in (args.observation, args.dwarf, args.static_audit)},
                  actual_io_qualified=False, root_mounted=False, device_operations=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
