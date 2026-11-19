#!/usr/bin/env python3
"""Generate Sony's UEFI memory map from its own firmware cfg and live FDT."""
import csv
import hashlib
import json
from pathlib import Path
import sys

DEVICE = Path(__file__).resolve().parents[1]
PROJECT = DEVICE.parents[1]
UEFI = PROJECT / 'ports/uefi-pdx234'
sys.path.insert(0, str(PROJECT / 'references/xperia-mainline-20261107/scripts'))
from unixnu.devicetree import read_fdt, registers


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    cfg = PROJECT / 'diagnostics/pdx234-vendor-uefiplat.cfg'
    dtb = PROJECT / 'evidence/Xperia-XQ-DQ72/20261107T092807Z/live.dtb'
    if sha(cfg) != 'd9cbf623af553aeeae2601290bc63c3231fae4a32a4c78a3cb057d1e5cf12955':
        raise RuntimeError('Sony OEM firmware configuration differs')
    if sha(dtb) != '63e127c3b7a5426d55a3726e73278c2853f70c5462e4683bf68cb6c2c89452ef':
        raise RuntimeError('Sony live FDT differs')
    rows, critical, section = [], [], ''
    critical_names = {'UEFI FD', 'UEFI FD Reserved', 'CPU Vectors', 'Info Blk', 'MMU PageTables',
                      'Log Buffer', 'UEFI Stack', 'SEC Heap', 'Sched Heap', 'FV Region', 'UEFI RESV',
                      'DXE Heap', 'Display Reserved'}
    for line in cfg.read_text().splitlines():
        line = line.split('#', 1)[0].strip()
        if line.startswith('['):
            section = line
        if section not in ('[MemoryMap]', '[RegisterMap]') or not line.startswith('0x'):
            continue
        fields = next(csv.reader([line], skipinitialspace=True))
        if len(fields) != 8:
            raise ValueError('Unexpected OEM cfg row')
        base, size, name = int(fields[0], 0), int(fields[1], 0), fields[2].strip()
        flags = [value.strip() for value in fields[3:]]
        if flags[0] in ('NoMap', 'AddDynamicMem'):
            flags[0] = 'HobOnlyNoCacheSetting'
        entry = dict(base=base, end=base+size, name=name, flags=flags,
                     priority=90 if name in critical_names else 40 if flags[0] == 'HobOnlyNoCacheSetting' else 20,
                     source='Sony uefiplat.cfg')
        if name == 'UEFI FD':
            if (base, size) != (0xa7000000, 0x400000):
                raise ValueError('Unexpected OEM FD reservation')
            rows.append(dict(entry, end=0xa7100000, name='FD Reserved'))
            entry['base'] = 0xa7100000
        rows.append(entry)
        if name in critical_names:
            critical.append(entry)
    root = read_fdt(dtb.read_bytes())
    banks, reservations = [], []
    for node in root.walk():
        if node.strings('device_type') == ['memory']:
            for base, size in registers(node):
                if size:
                    banks.append((base, base+size))
                    rows.append(dict(base=base, end=base+size, name=f'DRAM {base:x}',
                                     flags=['AddMem', 'SYS_MEM', 'SYS_MEM_CAP', 'Conv', 'WRITE_BACK_XN'],
                                     priority=1, source='Sony live FDT memory'))
        if node.parent and node.parent.name == 'reserved-memory' and 'reg' in node.properties:
            for base, size in registers(node):
                if not size:
                    continue
                if any(base < c['end'] and c['base'] < base+size and c['name'] != 'Display Reserved' for c in critical):
                    raise ValueError(f'Live reservation conflicts with UEFI working memory: {node.name}')
                reservations.append((base, base+size, node.name))
                rows.append(dict(base=base, end=base+size, name=node.name,
                                 flags=['AddMem', 'MEM_RES', 'UNCACHEABLE', 'Reserv', 'UNCACHED_UNBUFFERED_XN'],
                                 priority=30, source='Sony live FDT reserved-memory'))
    cuts = sorted({value for row in rows for value in (row['base'], row['end'])})
    resolved = []
    for base, end in zip(cuts, cuts[1:]):
        covering = [row for row in rows if row['base'] <= base and end <= row['end']]
        if not covering:
            continue
        winner = max(covering, key=lambda row: row['priority'])
        piece = dict(winner, base=base, end=end)
        if (resolved and resolved[-1]['end'] == base and
                all(resolved[-1][key] == piece[key] for key in ('name', 'flags', 'source'))):
            resolved[-1]['end'] = end
        else:
            resolved.append(piece)
    if len(resolved) >= 255:
        raise ValueError('Memory descriptor count exceeds firmware interface')
    allocations = [row for row in resolved if row['flags'][3] in ('Conv', 'BsData', 'BsCode', 'RtData')]
    for row in allocations:
        if row['name'] in critical_names or row['name'] == 'FD Reserved':
            continue
        if any(row['base'] < end and base < row['end'] for base, end, _ in reservations):
            raise ValueError('A reserved range was exposed to the allocator')
    output = UEFI / 'Platforms/Sony/pdx234Pkg/Library/MemoryMapLib/MemoryMapLib.c'
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise RuntimeError('Preserve generated memory-map source; compare rather than overwrite')
    lines = ['// SPDX-License-Identifier: BSD-3-Clause',
             '// Generated from hash-qualified Sony uefiplat.cfg and live FDT; not sheng RAM.',
             '#include <Library/MemoryMapLib.h>',
             'STATIC EFI_MEMORY_REGION_DESCRIPTOR gMemoryDescriptor[] = {']
    used = set()
    for row in resolved:
        name = row['name'][:31]
        if name in used:
            name = f'{name[:20]} {row["base"]:x}'[:31]
        used.add(name)
        row['c_name'] = name
        lines.append(f'  {{"{name}", 0x{row["base"]:X}ULL, 0x{row["end"]-row["base"]:X}ULL, ' + ', '.join(row['flags']) + '},')
    lines.extend(['};', 'VOID GetMemoryMap (OUT EFI_MEMORY_REGION_DESCRIPTOR **Map, OUT UINT8 *Count) {',
                  '  *Map = gMemoryDescriptor; *Count = ARRAY_SIZE(gMemoryDescriptor);', '}'])
    output.write_text('\n'.join(lines)+'\n')
    report = dict(cfg_sha256=sha(cfg), dtb_sha256=sha(dtb), descriptors=resolved,
                  allocator_reserved_overlap=False, descriptor_count=len(resolved),
                  generated_source_sha256=sha(output), firmware_fd_base='0xa7100000', firmware_fd_bytes=0x300000,
                  hardware_tested=False)
    (DEVICE / 'evidence/sony-uefi-memory-map.json').write_text(json.dumps(report, indent=2))
    print(json.dumps({key: report[key] for key in ('descriptor_count', 'allocator_reserved_overlap', 'generated_source_sha256')}, indent=2))


if __name__ == '__main__':
    main()
