#!/usr/bin/env python3
"""Compare pinned sheng/D27 graphics code and PAC metadata before binding reuse."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
FAMILIES = ('com.apple.iokit.IOMobileGraphicsFamily', 'com.apple.iokit.IOSurface',
            'com.apple.iokit.IOGPUFamily', 'com.apple.iokit.IOHIDFamily')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(BASE / 'strict-pac-abi-019/XnuPrelink'))
    from kc_image import Image, scan
    sys.path.insert(0, str(BASE / 'tmp/graphics-python'))
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG, ARM64_OP_MEM
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    decoder.detail = True
    paths = [Path('/root/unixnu-build/pdx234-j820-abi-reference-001/ipsw/24A446/kernelcache.decompressed'),
             Path('/mnt/g/UniXNU-Port/ports/UniXNU-pdx234/.cache/iphone14-ios27/ipsw/24A446/kernelcache.decompressed')]
    raws = [p.read_bytes() for p in paths]
    digests = [hashlib.sha256(r).hexdigest() for r in raws]
    if digests != ['38e6d9fa5f789b8228f4617ef4c6d2a3fd8ab564abdc9b62920f1db53fc1780a',
                   'c28f4fc9b83cde00087e81f890c82d566b9e98b5ac228dfecd83afdf34070445']:
        raise ValueError('Unexpected original kernel input')
    images = [Image(raw) for raw in raws]
    fixups = [im.fixups() for im in images]
    sections = []
    for family in FAMILIES:
        pair = [Image(raw, im.entries[family][1]) for raw, im in zip(raws, images)]
        left = {(s['segment'], s['name']): s for s in pair[0].sections}
        right = {(s['segment'], s['name']): s for s in pair[1].sections}
        if left.keys() != right.keys():
            raise ValueError('Different section set: ' + family)
        for key, old in left.items():
            new = right[key]
            if old['size'] != new['size']:
                raise ValueError('Different section size: ' + repr((family, key)))
            sections.append((family, key, old, new))

    def translate(address):
        found = [new['va'] + address - old['va'] for _, _, old, new in sections
                 if old['va'] <= address < old['va'] + old['size']]
        return found[0] if len(found) == 1 else None

    def page_uses(code, start):
        # Track callee-saved ADRP registers through calls. Register writes kill
        # provenance; this explains relocation operands the short scanner drops.
        pages, uses = {}, {}
        for ins in decoder.disasm(code, start):
            operands = ins.operands
            if ins.mnemonic == 'adrp' and len(operands) == 2:
                pages[operands[0].reg] = (operands[1].imm & ((1 << 64)-1), ins.address)
                continue
            for operand in operands:
                if operand.type == ARM64_OP_MEM and operand.mem.base in pages and not operand.mem.index:
                    page, origin = pages[operand.mem.base]
                    uses[ins.address] = (page + operand.mem.disp, origin)
            _, writes = ins.regs_access()
            for reg in writes:
                pages.pop(reg, None)
            if ins.mnemonic in ('bl', 'blr', 'blraa', 'blrab', 'blraaz', 'blrabz'):
                for reg in list(pages):
                    name = decoder.reg_name(reg)
                    if name.startswith('x') and name[1:].isdigit() and int(name[1:]) <= 18:
                        pages.pop(reg, None)
        return uses

    records = []
    for family in FAMILIES:
        pair = [Image(raw, im.entries[family][1]) for raw, im in zip(raws, images)]
        texts = [next(s for s in im.sections if s['name'] == '__text') for im in pair]
        starts = [im.function_starts() for im in pair]
        if [a-texts[0]['va'] for a in starts[0]] != [a-texts[1]['va'] for a in starts[1]]:
            raise ValueError('Different function layout: ' + family)
        unexplained, reference_mismatches, page_relocations = [], [], []
        checked = 0
        for index, (old_start, new_start) in enumerate(zip(*starts)):
            length = (starts[0][index+1] if index+1 < len(starts[0]) else texts[0]['va']+texts[0]['size']) - old_start
            old_bytes, new_bytes = pair[0].read(old_start, length), pair[1].read(new_start, length)
            old_calls, old_refs, old_shape = scan(old_bytes, old_start)
            new_calls, new_refs, new_shape = scan(new_bytes, new_start)
            if old_shape != new_shape:
                old_uses, new_uses = page_uses(old_bytes, old_start), page_uses(new_bytes, new_start)
                for i, (a, b) in enumerate(zip(old_shape, new_shape)):
                    if a != b:
                        site, new_site = old_start+i*4, new_start+i*4
                        first, second = old_uses.get(site), new_uses.get(new_site)
                        # Only the immediate of the same load/store may differ.
                        if (first and second and a & 0x3b000000 == 0x39000000 and
                                (a & ~0x3ffc00) == (b & ~0x3ffc00) and
                                first[1]-old_start == second[1]-new_start and
                                translate(first[0]) == second[0]):
                            page_relocations.append(dict(old=hex(site), new=hex(new_site),
                                                         old_target=hex(first[0]), new_target=hex(second[0]),
                                                         adrp=hex(first[1]), new_adrp=hex(second[1])))
                            continue
                        unexplained.append(dict(old=hex(old_start+i*4), new=hex(new_start+i*4),
                                                old_word=hex(struct.unpack_from('<I', old_bytes, i*4)[0]),
                                                new_word=hex(struct.unpack_from('<I', new_bytes, i*4)[0])))
            for old_list, new_list in [(old_calls, new_calls), (old_refs, new_refs)]:
                if len(old_list) != len(new_list):
                    reference_mismatches.append(dict(function=hex(old_start), reason='reference count'))
                    continue
                for a, b in zip(old_list, new_list):
                    target = translate(a[1])
                    if a[0]-old_start != b[0]-new_start or a[2] != b[2] or (target is not None and target != b[1]):
                        reference_mismatches.append(dict(old=list(a), new=list(b), expected=target))
            checked += length
        fixup_mismatches, internal_fixups, external_fixups = [], 0, 0
        for _, _, old, new in [s for s in sections if s[0] == family]:
            for site, pointer in fixups[0].items():
                if not old['va'] <= site < old['va']+old['size']:
                    continue
                new_site = new['va'] + site - old['va']
                other = fixups[1].get(new_site)
                target = translate(pointer[0])
                internal_fixups += target is not None
                external_fixups += target is None
                if not other or pointer[1:] != other[1:] or (target is not None and target != other[0]):
                    fixup_mismatches.append(dict(site=hex(site), new_site=hex(new_site), old=pointer, new=other))
        records.append(dict(family=family, function_count=len(starts[0]), checked_code_bytes=checked,
                            unexplained_instructions=unexplained, reference_mismatches=reference_mismatches,
                            explained_page_relocations=page_relocations,
                            fixup_mismatches=fixup_mismatches, internal_fixups=internal_fixups,
                            external_fixups_requiring_identity=external_fixups))
    report = dict(inputs=[dict(path=str(p), sha256=h) for p,h in zip(paths,digests)],
                  sections=[dict(family=f,segment=k[0],section=k[1],size=a['size'],
                                 sheng=hex(a['va']),d27=hex(b['va'])) for f,k,a,b in sections],
                  families=records, binding_reuse_qualified=False, device_operations=False)
    (args.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    for row in records:
        print(row['family'], 'unexplained',len(row['unexplained_instructions']),
              'reference mismatches',len(row['reference_mismatches']),
              'PAC/fixup mismatches',len(row['fixup_mismatches']), flush=True)


if __name__ == '__main__':
    main()
