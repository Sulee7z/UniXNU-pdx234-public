#!/usr/bin/env python3
"""Verify D27 reviewed identities against both pinned original kernelcaches."""
import argparse
from array import array
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace


def sha256(path):
    with path.open('rb') as source:return hashlib.file_digest(source,'sha256').hexdigest()


def text_sha256(path):
    """Source-fixture provenance is stable across Git's LF/CRLF checkouts."""
    return hashlib.sha256(path.read_bytes().replace(b'\r\n',b'\n')).hexdigest()


def index_functions(image, scan, exec_segments):
    functions,pool={},defaultdict(list)
    starts=sorted(set(image.function_starts()))
    for index,start in enumerate(starts):
        segment=next((s for s in image.segments if s['name'] in exec_segments and
                      s['va']<=start<s['va']+s['filesize']),None)
        if segment is None:continue
        end=min(segment['va']+segment['filesize'],starts[index+1] if index+1<len(starts) else segment['va']+segment['filesize'])
        code=image.read(start,end-start)
        _,refs,shape=scan(code,start)
        shape_hash=hashlib.sha256(array('I',shape)).hexdigest()
        strings=sorted({text for _,target,_ in refs if (text:=image.cstring(target))})
        functions[start]={'size':end-start,'sha256':hashlib.sha256(code).hexdigest(),
                          'shape_sha256':shape_hash,'strings':strings}
        pool[shape_hash].append(start)
    return functions,pool


def check_recovery(entry, d27_functions, d27_pool, reference_functions, reference_pool, fixture):
    original=int(entry['original'],16)
    function=d27_functions[original]
    if (function['size'],function['sha256'])!=(entry['original_size'],entry['original_sha256']):
        raise ValueError('D27 function extent or digest changed: '+entry['original'])
    match=re.search(r'J820 (0x[0-9a-f]+)',entry['evidence'])
    if not match:
        if entry['native_symbol']!='_kprintf' and entry.get('verification')!='source-and-disassembly':
            raise ValueError('Missing cross-image provenance')
        return 'source-and-disassembly'
    reference=int(match.group(1),16)
    reviewed=[x for x in fixture['functions'] if int(x['original'],16)==reference and
              x['native_symbol']==entry['native_symbol']]
    if len(reviewed)!=1:raise ValueError('Transferred identity is not in the reviewed fixture')
    ref=reference_functions[reference]
    if ref['sha256']!=reviewed[0]['original_sha256']:raise ValueError('Reference function digest changed')
    key=function['shape_sha256']
    if ref['shape_sha256']!=key or ref['strings']!=function['strings']:
        raise ValueError('Code shape or referenced strings changed')
    if len(d27_pool[key])!=1 or len(reference_pool[key])!=1:
        raise ValueError('Code shape is ambiguous in an original kernelcache')
    return 'unique-pinned-code-and-strings'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tool',required=True,type=Path)
    parser.add_argument('--kernelcache',required=True,type=Path)
    parser.add_argument('--j820',required=True,type=Path,help='Read-only pinned ABI reference, never a runtime replacement')
    parser.add_argument('--native',required=True,type=Path)
    parser.add_argument('--report',required=True,type=Path)
    args=parser.parse_args()
    if args.report.exists():parser.error('Refuse to overwrite an existing report')
    sys.path.insert(0,str(args.tool.resolve()))
    from kc_image import Image,scan
    from fileset_match import EXEC_SEGMENTS,vtable_slots,Matcher
    target=args.tool/'fixtures/fileset-24A446-d27-symbols.json'
    record=json.loads(target.read_text())
    recovery=record['recovery']
    source=args.tool/'fixtures'/recovery['fixture']
    fixture=json.loads(source.read_text())
    if sha256(args.kernelcache)!=record['inputs']['kernelcache_sha256']:
        raise ValueError('Wrong D27 kernelcache')
    if sha256(args.j820)!=recovery['reference_kernelcache_sha256'] or text_sha256(source)!=recovery['fixture_sha256']:
        raise ValueError('ABI recovery reference changed')
    indexes=[]
    images=[]
    fixups=[]
    for path in (args.kernelcache,args.j820):
        raw=path.read_bytes()
        cache=Image(raw)
        image=Image(raw,cache.entries[record['inputs']['entry']][1])
        images.append(image)
        fixups.append(cache.fixups())
        indexes.append(index_functions(image,scan,EXEC_SEGMENTS))
    native=Image(args.native.read_bytes())
    native_fixups=native.fixups()
    native_starts=sorted(native.function_starts())
    destructor_side=SimpleNamespace(image=native,functions={a:{'end':b} for a,b in zip(native_starts,native_starts[1:])})
    names=defaultdict(set)
    for address,symbols in native.symbols().items():
        for symbol in symbols:names[symbol].add(address)
    results=[]
    for entry in record['functions']:
        method=check_recovery(entry,*indexes[0],*indexes[1],fixture)
        addresses=names[entry['native_symbol']]
        if len(addresses)!=1:raise ValueError('Missing/ambiguous native function: '+entry['native_symbol'])
        address=next(iter(addresses))
        if native.read(address,4) in (bytes.fromhex('200020d4'),bytes.fromhex('000020d4')):
            raise ValueError('Trap-only native symbol is not an ABI implementation: '+entry['native_symbol'])
        if entry.get('native_body')=='vptr-poison' and not Matcher.vptr_poison_destructor(destructor_side,address):
            raise ValueError('Native destructor does not retain the vtable poison store: '+entry['native_symbol'])
        if 'original_ctor' in entry:
            encoded_class=entry['native_symbol'][4:-4]
            table_name='__ZTV'+encoded_class
            ctor_name='__ZN'+encoded_class+'C2EPK11OSMetaClass'
            if len(names[table_name])!=1 or len(names[ctor_name])!=1:
                raise ValueError('Missing class-specific constructor or vtable')
            old_ctor=int(entry['original_ctor'],16)
            old_table=int(entry['original_vtable'],16)
            old_code=images[0].read(old_ctor,indexes[0][0][old_ctor]['size'])
            new_ctor=next(iter(names[ctor_name]))
            new_table=next(iter(names[table_name]))
            new_code=native.read(new_ctor,destructor_side.functions[new_ctor]['end']-new_ctor)
            old_refs={a for _,a,_ in scan(old_code,old_ctor)[1]}
            new_refs={a for _,a,_ in scan(new_code,new_ctor)[1]}
            if not old_refs&{old_table,old_table+16} or not new_refs&{new_table,new_table+16}:
                raise ValueError('Constructor does not reference its claimed class vtable: '+entry['native_symbol'])
            if images[0].read(old_table,16)!=bytes(16) or native.read(new_table,16)!=bytes(16):
                raise ValueError('Constructor vtable has a different RTTI/address-point layout')
        results.append({'original':entry['original'],'native_symbol':entry['native_symbol'],'method':method})
    for entry in record['data']:
        if len(names[entry['native_symbol']])!=1:raise ValueError('Missing/ambiguous native data: '+entry['native_symbol'])
        if 'original_metaclass' in entry:
            original=int(entry['original'],16)
            address=next(iter(names[entry['native_symbol']]))
            def table_side(image, pointers):
                ranges=[(s['va'],s['va']+s['size']) for s in image.segments if s['name'] in EXEC_SEGMENTS]
                return SimpleNamespace(fixups=pointers,in_exec=lambda a:any(b<=a<e for b,e in ranges))
            left=vtable_slots(table_side(images[0],fixups[0]),original)
            right=vtable_slots(table_side(native,native_fixups),address)
            if not left or [v[1:] for v in left]!=[v[1:] for v in right]:
                raise ValueError('Complete vtable PAC layout differs: '+entry['native_symbol'])
            if images[0].read(original,16)!=native.read(address,16):
                raise ValueError('Vtable RTTI header differs')
            cls=entry['native_symbol'][5:]
            meta='__ZN'+cls+'10gMetaClassE'
            if len(names[meta])!=1:raise ValueError('Missing native class identity')
            expected=int(entry['original_metaclass'],16)
            old_refs={a for _,a,_ in scan(images[0].read(fixups[0][original+0x48][0],16),fixups[0][original+0x48][0])[1]}
            new_getter=native_fixups[address+0x48][0]
            new_refs={a for _,a,_ in scan(native.read(new_getter,16),new_getter)[1]}
            if old_refs!={expected} or new_refs!=names[meta]:
                raise ValueError('Class-specific vtable getter differs: '+entry['native_symbol'])
    report={'kernelcache_sha256':sha256(args.kernelcache),'reference_sha256':sha256(args.j820),
            'native_sha256':sha256(args.native),'fixture_sha256':sha256(target),'functions':results,
            'data_symbols_checked':len(record['data']),'runtime_qualified':False,'device_operations':False}
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(f"Verified {len(results)} D27 function identities and {len(record['data'])} named data targets; runtime unqualified")


if __name__=='__main__':main()
