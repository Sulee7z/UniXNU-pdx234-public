#!/usr/bin/env python3
"""Compile a staged Sony dual-DSI OLED service using the cached real D27 recipe.

Does not edit the shared native recipe/profile, install a transport owner, relink
the native kernel or claim device brightness. Archive constructors are made late
and called only through native_sony_oled_backlight_probe.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
CACHE=ROOT/'.cache/iphone14-ios27/ipsw/24A446/kernelcache.decompressed'
ORIGINAL='c28f4fc9b83cde00087e81f890c82d566b9e98b5ac228dfecd83afdf34070445'
NATIVE_SHA='80b2b18120eafde479aa2eaebd4017a677a67405b0ba0fe33e8d00ad6b6bc3dc'
STRICT_SHA='0855e4bb87d6d22e974cd07f28cf3d62de14f07eb10d43f3a1de7458c5da7cf3'

def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()

def load_builder():
    spec=importlib.util.spec_from_file_location('sony_oled_cached_builder',ROOT/'ci/qemu/display/input/build-input.py')
    builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
    return builder

def audit_abi(out,builder):
    if sha(CACHE)!=ORIGINAL:raise ValueError('Original iPhone14,7/d27ap 24A446 cache differs')
    sys.path.insert(0,str(ROOT/'ci/XnuPrelink'))
    from kc_image import Image,scan
    raw=CACHE.read_bytes();kc=Image(raw);fixups=kc.fixups()
    # The source fixture identifies this table by its own getMetaClass, not a
    # J820 address. Recheck identity and every compiled PAC slot independently.
    vptr=0xfffffff007c5cfc8;meta=0xfffffff00ad58758
    getter=fixups[vptr+7*8][0]
    if not any(target==meta for site,target,kind in scan(kc.read(getter,16),getter)[1]):
        raise ValueError('Original D27 IOService identity differs')
    actual=[]
    while (row:=fixups.get(vptr+len(actual)*8)) and row[1]==1 and row[2]==0 and row[4]==1:
        actual.append(row)
    info=builder.object_info(out/'objects/SonyOledBacklight.o')
    table=info['tables']['__ZTV17SonyOledBacklight']
    if len(table)!=len(actual):raise ValueError(f'IOService vtable extent: compiled{len(table)},D27{len(actual)}')
    for i,((name,word),(_,auth,key,div,addr)) in enumerate(zip(table,actual)):
        if (word>>63,word>>49&3,word>>32&65535,word>>48&1)!=(auth,key,div,addr):
            raise ValueError(f'D27 service PAC mismatch slot{i}:{name}')
    # AppleARMBacklight's original named constructor supplies the same metaobject
    # as its virtual getter. No pointer to an Apple instance is ever substituted.
    apple_meta=0xfffffff00adebc00;apple_name=0xfffffff0071691ea;ctor=0xfffffff00831f198
    if kc.read(apple_name,18)!=b'AppleARMBacklight\0':raise ValueError('Original D27 class name differs')
    body=kc.read(ctor,144);refs=scan(body,ctor)[1]
    if not all(any(target==address for site,target,kind in refs) for address in (apple_meta,apple_name)):
        raise ValueError('Original D27 named AppleARMBacklight constructor differs')
    apple_getters=[]
    for site,(target,auth,key,div,addr) in fixups.items():
        if auth==1 and key==0 and div==actual[7][3] and addr==1:
            try:body_getter=kc.read(target,16)
            except ValueError:continue
            if any(t==apple_meta for s,t,k in scan(body_getter,target)[1]):apple_getters.append((site,target))
    if not apple_getters:raise ValueError('Original AppleARMBacklight virtual getter not found')
    dwarf=subprocess.check_output([str(builder.LLVM/'llvm-dwarfdump'),'--debug-info','--name=IOService','--show-children',
                                   str(out/'objects/SonyOledBacklight.o')],text=True)
    if 'DW_AT_byte_size\t(0x88)' not in dwarf:raise ValueError('Actual native IOService extent differs')
    (out/'IOService.dwarf.txt').write_text(dwarf)
    result=dict(original_kernelcache_sha256=ORIGINAL,os='iOS27.0.1/24A446',device='iPhone14,7/d27ap',
                original_io_service_vptr=hex(vptr),original_io_service_metaclass=hex(meta),
                service_slots=len(actual),all_service_pac_slots_match=True,native_io_service_bytes=136,
                apple_backlight_metaclass=hex(apple_meta),apple_backlight_name=hex(apple_name),
                apple_named_constructor=hex(ctor),apple_named_constructor_sha256=hashlib.sha256(body).hexdigest(),
                apple_getters=[dict(site=hex(s),target=hex(t),sha256=hashlib.sha256(kc.read(t,16)).hexdigest()) for s,t in apple_getters],
                compiled_table=[dict(slot=i,symbol=n,diversity=hex(w>>32&65535)) for i,(n,w) in enumerate(table)],
                runtime_qualified=False,corebrightness_userspace_abi_requalified=False)
    (out/'abi.json').write_text(json.dumps(result,indent=2)+'\n')
    return result

def audit_imports(out,builder,members):
    sys.path.insert(0,str(ROOT/'ci/XnuPrelink'))
    from kc_image import Image
    native=BASE/'native-sony-touch-066-002/native.macho'
    strict=BASE/'strict-sony-touch-066-002/kernel.macho'
    if sha(native)!=NATIVE_SHA or sha(strict)!=STRICT_SHA:raise ValueError('Correct066002 base kernel differs')
    infos=[builder.object_info(p) for p in members]
    defined={s['name'] for info in infos for s in info['symbols'] if s['type']&14 in (2,14)}
    external={s['name'] for info in infos for s in info['symbols'] if s['type']==1}-defined
    names={name:address for address,group in Image(native.read_bytes()).symbols().items() for name in group}
    missing=external-names.keys()
    if missing:raise ValueError('Imports absent from correct066002 native: '+repr(sorted(missing)))
    for info in infos:
        if any(s['name']=='__mod_init_func' for s in info['sections']):raise ValueError('Archive initializer is not late')
    if '__GLOBAL__sub_I_SonyOledBacklight.cpp' not in defined:raise ValueError('Late initializer missing')
    # Inspect actual emitted authentication/memory barriers, not just flags.
    for name,required in (('SonyDsi',('blraa','pacibsp')),('SonyDsiMapped',('braa','dsb\tsy')),
                          ('SonyOledBacklight',('blraa','pacibsp'))):
        text=subprocess.check_output([str(builder.LLVM/'llvm-objdump'),'--macho','--disassemble','--no-symbolic-operands',
                                     str(out/'objects'/(name+'.o'))],text=True)
        if not all(token in text for token in required):raise ValueError('Actual auth/barrier instructions missing: '+name)
        (out/(name+'.disassembly.txt')).write_text(text)
    result=dict(base_native=str(native),base_native_sha256=NATIVE_SHA,base_strict=str(strict),base_strict_sha256=STRICT_SHA,
                external_imports=len(external),missing=[],all_imports_resolve_in_correct_native=True,
                archive_constructors_late=True,actual_auth_and_mmio_barriers_present=True,
                original_apple_auth_instructions_modified=False,
                imports={n:hex(names[n]) for n in sorted(external)},strict_prelink_performed=False)
    (out/'imports.json').write_text(json.dumps(result,indent=2)+'\n')
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',required=True,type=Path);p.add_argument('--tests',required=True,type=Path)
    a=p.parse_args();out=a.out.resolve()
    if not str(out).startswith(str(BASE)+'/sony-oled-driver-'):raise ValueError('Use an isolated EXT4 Sony OLED output')
    if out.exists():raise ValueError('Preserve previous driver builds')
    if shutil.disk_usage('/mnt/g').free<2*1024**3:raise ValueError('G reserve below2GiB')
    tests=json.loads(a.tests.read_text())
    if not tests['passed']:raise ValueError('Production-core sanitizer tests required')
    for path,digest in tests['sources'].items():
        if sha(path)!=digest:raise ValueError('Tested source differs: '+path)
    out.mkdir();(out/'objects').mkdir();(out/'source').mkdir()
    driver=ROOT/'drivers/SonyOledBacklight'
    builder=load_builder();sys.path.insert(0,str(ROOT/'ci'))
    from block_descriptor_abi import FLAGS
    from compile_dependencies import valid
    includes=['-I',str(driver),'-idirafter',str(builder.SDK/'System/Library/Frameworks/Kernel.framework/Versions/A/Headers')]
    commands={};members=[]
    for name in ('SonyDsi.c','SonyOledPolicy.c','SonyDsiMapped.cpp','SonyOledBacklight.cpp','BacklightProbe.cpp'):
        source=driver/name;shutil.copyfile(source,out/'source'/name)
        obj=out/'objects'/(source.stem+'.o');commands[name]=builder.compile_cpp(source,obj,includes,FLAGS)
        receipt=json.loads(obj.with_name(obj.name+'.dependencies.json').read_text())
        if not valid(receipt):raise ValueError('Compile dependency receipt invalid')
        if '-fptrauth-function-pointer-type-discrimination' not in commands[name]:raise ValueError('Native PAC flag missing')
        if name=='SonyOledBacklight.cpp':
            late=obj.with_name('SonyOledBacklight.late.o')
            subprocess.run(['llvm-objcopy-23','--remove-section=__DATA,__mod_init_func',
                            '--globalize-symbol=__GLOBAL__sub_I_SonyOledBacklight.cpp',str(obj),str(late)],check=True)
            members.append(late)
        else:members.append(obj)
    abi=audit_abi(out,builder)
    imports=audit_imports(out,builder,members)
    archive=out/'libSonyD27OledBacklight.a'
    subprocess.run(['llvm-ar','rcs',str(archive),*map(str,members)],check=True)
    result=dict(archive=str(archive),sha256=sha(archive),objects={str(p):sha(p) for p in members},
                sources={str(p):sha(p) for p in driver.iterdir() if p.is_file()},commands=commands,
                tests=str(a.tests),tests_sha256=sha(a.tests),abi_sha256=sha(out/'abi.json'),
                imports_sha256=sha(out/'imports.json'),external_imports=imports['external_imports'],missing_imports=[],
                base_native_sha256=NATIVE_SHA,base_strict_sha256=STRICT_SHA,
                service_slots=abi['service_slots'],native_pac=True,signed_block_descriptors=True,
                startup='native_sony_oled_backlight_probe',bind='native_sony_oled_bind_mapped',
                required_args=['backlight=1'],base_native='native-sony-touch-066-002',
                base_strict='strict-sony-touch-066-002',staged=True,hardware_enabled=False,
                physical_mmio_provider_installed=False,backlight_control_published=False,
                corebrightness_userspace_abi_requalified=False,runtime_verified=False,device_operations=False,
                blockers=['Display-owner quiesce/rail/clock/ULPS lease not provided by current GOP path',
                          'No inherited UEFI-to-XNU dual-controller register/geometry snapshot',
                          'DCS0x52 support/order and broadcast acceptance need physical panel qualification',
                          'BacklightMode.m is source-reviewed only; D27 CoreBrightness initBLControl ABI not yet locally verified',
                          'Suspend/resume and thermal policy are not integrated; HBM remains disabled'])
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('commands','sources','objects')},indent=2))

if __name__=='__main__':main()
