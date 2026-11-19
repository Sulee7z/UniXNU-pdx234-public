#!/usr/bin/env python3
"""Read the exact D27 Objective-C method/type/implementation without patching."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess

HERE=Path(__file__).resolve().parent

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image',required=True,type=Path);p.add_argument('--out',required=True,type=Path)
    p.add_argument('--cached-pages',type=Path,help='Reuse prior immutable extraction pages; no guest needed for covered ranges')
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    record=json.loads((a.image/'image.json').read_text());ranges=[]
    for s in record['segments']:
        data=Path(s['copy']).read_bytes()
        if hashlib.sha256(data).hexdigest()!=s['sha256']:raise ValueError('Original slice changed')
        ranges.append((s['va'],data))
    cached=[]
    if a.cached_pages:
        prior=[]
        for receipt in sorted(a.cached_pages.glob('batch-*/receipt.json')):
            prior.extend(json.loads(receipt.read_text()))
        for path in sorted(a.cached_pages.glob('page-*.bin')):
            data=path.read_bytes();address=int(path.stem.split('-')[1],16)
            if not any(row['va']==address and row['length']==len(data) and
                       row['sha256']==hashlib.sha256(data).hexdigest() for row in prior):
                raise ValueError('Cached ObjC page lacks original extraction receipt: '+str(path))
            ranges.append((address,data))
            cached.append(dict(path=str(path),sha256=hashlib.sha256(data).hexdigest(),va=hex(address),bytes=len(data)))
    spec=importlib.util.spec_from_file_location('sony_cb_extract',HERE/'audit-corebrightness.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    disk=Path(record['systemos']);mountpoint=Path('/mnt/sony-oled-host-e')
    if not disk.exists():
        mountpoint.mkdir(exist_ok=True)
        if not os.path.ismount(mountpoint):subprocess.run(['mount','-t','drvfs','E:',str(mountpoint),'-o','ro'],check=True)
    slices=m.Slices(a.out,disk)
    def available(va,n):return any(base<=va and va+n<=base+len(raw) for base,raw in ranges)
    def read(va,n):
        for base,raw in ranges:
            if base<=va and va+n<=base+len(raw):return raw[va-base:va-base+n]
        raise ValueError('Missing original slice '+hex(va))
    def fetch(addresses):
        pages=sorted({va&~4095 for va in addresses if va and not available(va,128)})
        if len(pages)>256:raise ValueError('Unbounded string pages')
        if not pages:return
        chunks=slices.extract([(f'objc-page-{va:x}',va,8192) for va in pages])
        for va,chunk in zip(pages,chunks):
            (a.out/f'page-{va:x}.bin').write_bytes(chunk);ranges.append((va,chunk))
    def pointer(va):
        raw=struct.unpack('<Q',read(va,8))[0]
        return 0x180000000+(raw&0x3ffffffff) if raw else 0
    def cstr(va):return read(va,128).split(b'\0')[0].decode()
    # Current D27 cache header: cacheSubType at0x1c8, ObjC optimization VM
    # offset/size at0x1d0/0x1d8. The original main-cache SHA is checked first.
    main=Path('/mnt/e/UniXNU-sheng27-sony-20261113/photo026-cache-002/export/main.bin').read_bytes()
    if hashlib.sha256(main).hexdigest()!=record['cache_main_sha256']:raise ValueError('Original cache main header differs')
    opts_offset,opts_size=struct.unpack_from('<QQ',main,0x1d0)
    if opts_size<56 or opts_size>4096:raise ValueError('Unexpected D27 ObjC optimization header size')
    opts_va=0x180000000+opts_offset;fetch([opts_va])
    opts_version,opts_flags=struct.unpack_from('<II',read(opts_va,8))
    selector_base=0x180000000+struct.unpack('<Q',read(opts_va+48,8))[0]
    section=next(s for s in record['sections'] if s['name']=='__objc_classlist')
    classes=[]
    for offset in range(0,section['size'],8):
        obj=pointer(section['va']+offset);ro=pointer(obj+32)&~7
        classes.append(dict(object=obj,ro=ro,name_va=pointer(ro+24),methods=pointer(ro+32)))
    fetch([r['name_va'] for r in classes])
    for row in classes:row['name']=cstr(row['name_va'])
    cls=next(r for r in classes if r['name']=='BrightnessSystemInternal')
    methods=[];start=cls['methods'];flags,count=struct.unpack('<II',read(start,8));size=flags&0xffff
    # Runtime method-list low bits are preoptimization flags. Entries are12-byte
    # relative triples when bit31 is set. Bit30 selects direct selector strings.
    if not flags&0x80000000 or size&~3!=12 or count>2048:raise ValueError('Unexpected method-list encoding')
    for i in range(count):
        at=start+8+i*12;name_rel,type_rel,imp_rel=struct.unpack('<iii',read(at,12))
        name=selector_base+(name_rel&0xffffffff) if flags&0x40000000 else pointer(at+name_rel)
        types=selector_base+(type_rel&0xffffffff) if flags&0x20000000 else at+4+type_rel
        methods.append(dict(entry=at,name_va=name,type_va=types,imp=at+8+imp_rel))
    fetch([r['name_va'] for r in methods]+[r['type_va'] for r in methods])
    for row in methods:row.update(name=cstr(row['name_va']),types=cstr(row['type_va']))
    method=next(r for r in methods if r['name']=='initBLControl:')
    following=sorted(r['imp'] for r in methods if r['imp']>method['imp'])
    length=min(following[0]-method['imp'],4096) if following else 1024
    body=read(method['imp'],length);(a.out/'initBLControl.bin').write_bytes(body)
    # A tiny Mach-O text wrapper for llvm-objdump, preserving the original VA and
    # original bytes. It is diagnostic only, never linked/loaded or patched.
    seg=struct.pack('<II16sQQQQiiII',0x19,152,b'__TEXT',method['imp'],len(body),4096,len(body),5,5,1,0)
    sec=struct.pack('<16s16sQQIIIIIIII',b'__text',b'__TEXT',method['imp'],len(body),4096,2,0,0,0x80000400,0,0,0)
    head=struct.pack('<8I',0xfeedfacf,0x100000c,2,1,1,len(seg+sec),0,0)+seg+sec
    image=a.out/'initBLControl.macho';image.write_bytes(head+bytes(4096-len(head))+body)
    dis=subprocess.check_output(['/usr/lib/llvm-23/bin/llvm-objdump','--macho','--disassemble','--no-symbolic-operands',str(image)],text=True)
    (a.out/'initBLControl.disassembly.txt').write_text(dis)
    branch_classes=[]
    # These classrefs are loaded by three distinct paths in this exact original
    # method. Name resolution uses original slide-encoded metadata, not symbol
    # guesses or a J820 implementation.
    for mode,ref in [(3,0x268b13c30),(2,0x268b13c28),(1,0x268b13a60)]:
        obj=pointer(ref);ro=pointer(obj+32)&~7;name_va=pointer(ro+24);fetch([name_va])
        branch_classes.append(dict(mode=mode,classref=hex(ref),object=hex(obj),name=cstr(name_va)))
    if [r['name'] for r in branch_classes]!=['VMBLControl','TMBLControl','BLControl']:
        raise ValueError('Actual D27 mode branch class identities differ')
    if read(0x22aa60134,8)!=bytes.fromhex('bf0e00f1c0030054') or method['types']!='B24@0:8q16':
        raise ValueError('Actual D27 mode3 branch/prototype differs')
    result=dict(original_image=str(a.image/'image.json'),original_image_sha256=m.sha(a.image/'image.json'),
                image_uuid=record['uuid'],class_info=cls,method=method,method_list_flags=hex(flags),
                objc_optimization_version=opts_version,objc_optimization_va=hex(opts_va),
                cache_selector_type_base=hex(selector_base),
                method_bytes=length,method_sha256=hashlib.sha256(body).hexdigest(),methods=methods,
                objc_declared_abi_matches_official=(method['types']=='B24@0:8q16'),
                mode_branch_classes=branch_classes,mode3_vm_to1_default_matches_official=True,
                cache_main_sha256=record['cache_main_sha256'],executable_patched=False,
                runtime_loading_qualified=False,slices=slices.rows,cached_page_provenance=cached)
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('methods','slices','cached_page_provenance')},indent=2))

if __name__=='__main__':main()
