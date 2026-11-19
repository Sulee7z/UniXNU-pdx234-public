#!/usr/bin/env python3
"""Translate source ABI fixtures through independently checked D27 family layouts."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--audit', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    audit = json.loads(args.audit.read_text())
    if len(audit['families']) != 4 or any(row[key] for row in audit['families']
            for key in ('unexplained_instructions', 'reference_mismatches', 'fixup_mismatches')):
        raise ValueError('Require the four checked graphics families')
    sys.path.insert(0, str(BASE/'strict-pac-abi-019/XnuPrelink'))
    from kc_image import Image
    raws = [Path(item['path']).read_bytes() for item in audit['inputs']]
    if any(hashlib.sha256(raw).hexdigest() != item['sha256'] for raw,item in zip(raws,audit['inputs'])):
        raise ValueError('Audit input changed')
    old, new = map(Image, raws)
    fixups = [im.fixups() for im in (old,new)]
    sections = audit['sections']

    def address(value):
        number = int(value, 16)
        hits = [int(row['d27'],16)+number-int(row['sheng'],16) for row in sections
                if int(row['sheng'],16) <= number < int(row['sheng'],16)+row['size']]
        if len(hits) != 1:
            raise ValueError('Address outside qualified families: '+value)
        return hex(hits[0])

    def read(im, raw, addr, size):
        for _,offset in im.entries.values():
            member = Image(raw,offset)
            if member.section(addr):
                return member.read(addr,size)
        raise ValueError(hex(addr))

    args.out.mkdir(parents=True,exist_ok=False)
    receipts = []
    for stem in ('legacy-display', 'hid-device'):
        source = BASE/'sources/sheng/scripts'/f'{stem}-24A446.json'
        fixture = json.loads(source.read_text())
        if fixture['kernelcache_sha256'] != audit['inputs'][0]['sha256']:
            raise ValueError('Reference fixture identity changed')
        old_vtable = int(fixture['vtable'],16)
        new_vtable = int(address(fixture['vtable']),16)
        slots = []
        for index,(target,diversity) in enumerate(fixture['slots']):
            left,right = fixups[0][old_vtable+8*index],fixups[1][new_vtable+8*index]
            caller = fixture.get('caller_diversity', {}).get(str(index))
            expected_diversity = int(caller['diversity'],16) if caller else left[3]
            if (left[0],expected_diversity) != (int(target,16),int(diversity,16)) or left[1:] != right[1:]:
                raise ValueError(f'{stem} slot{index} PAC schema differs')
            # Pure slots use the upstream reviewed caller schema, not the
            # never-called pure_virtual entry schema. The entire family code,
            # including MOV discriminator/AUT/BLRAA sequences, was compared.
            slots.append([hex(right[0]),hex(expected_diversity)])
        fixture['slots'] = slots
        fixture['vtable'] = hex(new_vtable)
        fixture['bindings'] = {name:address(value) for name,value in fixture['bindings'].items()}
        checks = []
        for site,expected in fixture.get('checks',[]):
            if read(old,raws[0],int(site,16),len(bytes.fromhex(expected))).hex()!=expected:
                raise ValueError('Reference byte check failed: '+site)
            translated=address(site)
            actual=read(new,raws[1],int(translated,16),len(bytes.fromhex(expected)))
            if actual.hex()!=expected:
                raise ValueError('D27 field/accessor byte check failed: '+site)
            checks.append([translated,actual.hex()])
        if checks:
            fixture['checks']=checks
        if stem=='legacy-display':
            row=next(row for row in sections if row['family']=='com.apple.iokit.IOMobileGraphicsFamily' and row['section']=='__text')
            fixture['family_text']=[row['d27'],hex(int(row['d27'],16)+row['size'])]
        fixture['kernelcache_sha256']=audit['inputs'][1]['sha256']
        fixture['collection_slide']=hex(0xfffffff007004000-new.base)
        fixture['provenance']={'reference_fixture_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
                               'audit_sha256':hashlib.sha256(args.audit.read_bytes()).hexdigest(),
                               'pac_metadata_modified':False}
        out=args.out/source.name
        out.write_text(json.dumps(fixture,indent=2)+'\n')
        receipts.append(dict(path=str(out),sha256=hashlib.sha256(out.read_bytes()).hexdigest(),slots=len(slots)))
    source=BASE/'sources/UniXNU/scripts/data/ioaccelerator-base-abi-24A446.json'
    fixture=json.loads(source.read_text())
    if fixture['kernelcache_sha256']!=audit['inputs'][0]['sha256']:
        raise ValueError('Accelerator reference identity changed')
    for key in ('metaclass','nondeleting_destructor','get_meta_class'):
        fixture[key]=address(fixture[key])
    fixture['protected_compatible_constructor_aliases']=[address(a) for a in fixture['protected_compatible_constructor_aliases']]
    fixture.update(kernelcache_sha256=audit['inputs'][1]['sha256'],collection_slide=hex(0xfffffff007004000-new.base),
                   evidence='D27 IOGPUFamily same function and section layout; normalized instructions, internal references and all chained PAC schemas checked against pinned sheng family',
                   audit_sha256=hashlib.sha256(args.audit.read_bytes()).hexdigest())
    out=args.out/source.name;out.write_text(json.dumps(fixture,indent=2)+'\n')
    receipts.append(dict(path=str(out),sha256=hashlib.sha256(out.read_bytes()).hexdigest()))
    (args.out/'result.json').write_text(json.dumps(dict(fixtures=receipts,device_operations=False),indent=2)+'\n')
    print(json.dumps(receipts,indent=2))


if __name__=='__main__':
    main()
