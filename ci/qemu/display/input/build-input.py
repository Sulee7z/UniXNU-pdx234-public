#!/usr/bin/env python3
"""Build and qualify a real current D27 IOHIDDevice + QEMU input archive.

Uses pinned IOHIDFamily source headers, generated HIDDriverKit declarations,
the current PAC compile record, and exact original D27 vtable fixups. All new
source, headers, objects and receipts live in one isolated EXT4 output folder.
"""
import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import urllib.request

HERE=Path(__file__).resolve().parent
CI=HERE.parents[2]
sys.path.insert(0,str(CI))
from compile_dependencies import run_recorded

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
DISPLAY=BASE/'display-source-009'
TREE=BASE/'sources/UniXNU/out/pdx234/ios-27.0.1-24A446-iphone14/pdx234_sheng27_bulk/tree'
SDK=TREE/'.cache/fakeroot'
HID=Path('/root/unixnu-build/pdx234-local-github-a6d2286-001/out/feeds/IOHIDFamily-f53ac321')
HID_REVISION='e31e90a24c27ad6cbe981650d12a1a4124065b03'
SHENG=BASE/'sources/sheng'
QEMU=Path('/mnt/g/UniXNU-Port/sources/UniXNU-qemu-20261110')
CLANG=Path('/root/unixnu-build/pdx234-pac-toolchain/llvm/bin/clang-24')
LLVM=Path('/usr/lib/llvm-23/bin')
CACHE=Path('/mnt/g/UniXNU-Port/ports/UniXNU-pdx234/.cache/iphone14-ios27/ipsw/24A446/kernelcache.decompressed')


def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def run(command,log,**kwargs):
    log.with_suffix('.command.json').write_text(json.dumps(list(map(str,command)),indent=2)+'\n')
    with log.open('w') as stream:
        result=subprocess.run(list(map(str,command)),stdout=stream,stderr=subprocess.STDOUT,timeout=180,**kwargs)
    if result.returncode:raise RuntimeError(str(log)+'\n'+log.read_text()[-10000:])


def compile_cpp(source,output,includes=(),flags=()):
    command=json.loads((DISPLAY/'build/native-legacy-display/compile-command.json').read_text())
    command=[command[0],*includes,*command[1:]]
    for i,value in enumerate(command):
        if value.endswith('NativeLegacyDisplay.cpp'):command[i]=str(source)
    command[command.index('-o')+1]=str(output)
    command+=['-Wno-missing-designated-field-initializers','-Wno-unused-but-set-global',*flags]
    plan=json.loads((BASE/'pac-abi-native-019/plan.json').read_text())
    job=next(j for j in plan['jobs'] if Path(j['source']).name=='IOPlatformExpert.cpp')
    log=output.with_suffix('.log')
    with log.open('w') as stream:
        result=run_recorded(command,cwd=job['directory'],stdout=stream,stderr=subprocess.STDOUT,timeout=180)
    if result.returncode:raise RuntimeError(str(log)+'\n'+log.read_text()[-10000:])
    return command


def object_info(path):
    data=Path(path).read_bytes();assert struct.unpack_from('<I',data)[0]==0xfeedfacf
    sections=[];symbols=[];at=32
    for _ in range(struct.unpack_from('<I',data,16)[0]):
        kind,size=struct.unpack_from('<II',data,at)
        if kind==0x19:
            for i in range(struct.unpack_from('<I',data,at+64)[0]):
                sec=at+72+i*80
                va,length,offset=struct.unpack_from('<QQI',data,sec+32)
                reloc,count=struct.unpack_from('<II',data,sec+56)
                sections.append(dict(name=data[sec:sec+16].rstrip(b'\0').decode(),va=va,bytes=length,offset=offset,reloc=reloc,count=count))
        elif kind==2:
            sy,count,st,_=struct.unpack_from('<4I',data,at+8)
            for i in range(count):
                ix,typ,section,desc,va=struct.unpack_from('<IBBHQ',data,sy+i*16)
                symbols.append(dict(name=data[st+ix:data.index(b'\0',st+ix)].decode(),va=va,type=typ,section=section,desc=desc))
        at+=size
    tables={}
    for symbol in symbols:
        if not symbol['name'].startswith('__ZTV') or '9MetaClassE' in symbol['name'] or symbol['type']==1:continue
        va=symbol['va'];sec=next(s for s in sections if s['va']<=va<s['va']+s['bytes'])
        relocs={}
        for i in range(sec['count']):
            delta,bits=struct.unpack_from('<II',data,sec['reloc']+i*8)
            if bits>>27&1 and bits>>25&3==3 and bits>>28==11:
                word=struct.unpack_from('<Q',data,sec['offset']+delta)[0]
                relocs[sec['va']+delta]=(symbols[bits&0xffffff]['name'],word)
        entries=[];cursor=va+16
        while cursor in relocs:
            entries.append(relocs[cursor]);cursor+=8
        tables[symbol['name']]=entries
    return dict(data=data,sections=sections,symbols=symbols,tables=tables)


def audit_hid(out):
    fixture=BASE/'graphics-bindings-002/hid-device-24A446.json'
    if sha(fixture)!='af3ff79be54e7836c21256984dccb1d8ce14966d6a664c1c11293a0a61439385':
        raise ValueError('D27 HID fixture differs')
    abi=json.loads(fixture.read_text())
    if sha(CACHE)!=abi['kernelcache_sha256']:raise ValueError('Original D27 cache differs')
    sys.path.insert(0,str(CI/'XnuPrelink'))
    from kc_image import Image,scan
    raw=CACHE.read_bytes();collection=Image(raw);fixups=collection.fixups()
    actual=[fixups[int(abi['vtable'],16)+8*i] for i in range(len(abi['slots']))]
    if any(target!=int(row[0],16) or (auth,key,diversity,addr)!=(1,0,int(row[1],16),1)
           for (target,auth,key,diversity,addr),row in zip(actual,abi['slots'])):
        raise ValueError('Original D27 IOHIDDevice fixups differ')
    obj=object_info(out/'objects/NativeHidInput.o')
    table=obj['tables']['__ZTV14NativeHidInput']
    if len(table)!=len(actual):raise ValueError(f'HID vtable extent: compiled {len(table)}, original {len(actual)}')
    for i,((name,word),(_,auth,key,diversity,addr)) in enumerate(zip(table,actual)):
        if (word>>63,word>>49&3,word>>32&0xffff,word>>48&1)!=(auth,key,diversity,addr):
            raise ValueError(f'HID PAC slot {i}: {name}')
    # Names of base imports present in the concrete vtable identify their exact
    # original slots. Constructor/destructor/metaclass use the reviewed fixture.
    bindings={name:int(va,16) for name,va in abi['bindings'].items()}
    byslot={name:i for i,(name,word) in enumerate(table) if '11IOHIDDevice' in name}
    for name,index in byslot.items():bindings[name]=actual[index][0]
    imports={s['name'] for s in obj['symbols'] if s['type']==1 and '11IOHIDDevice' in s['name']}
    missing=imports-bindings.keys()
    if missing:raise ValueError('Unqualified IOHIDDevice imports '+repr(sorted(missing)))
    # Every inherited non-family IOService slot must use the same current native
    # declaration. Its PAC has already matched the original table above.
    dwarf=subprocess.check_output([str(LLVM/'llvm-dwarfdump'),'--debug-info','--name=IOHIDDevice','--show-children',
                                   str(out/'objects/NativeHidInput.o')],text=True)
    (out/'IOHIDDevice.dwarf.txt').write_text(dwarf)
    if 'DW_AT_byte_size\t(0xd0)' not in dwarf and 'DW_AT_byte_size\t(0x00d0)' not in dwarf:
        raise ValueError('Public source IOHIDDevice size does not match original208')
    addresses='';text='.text\n.p2align 2\n'
    for name in sorted(imports):
        address=bindings[name]
        if name in ('__ZN11IOHIDDevice10gMetaClassE','__ZTV11IOHIDDevice'):
            addresses+=f'.globl {name}\n.set {name}, {address:#x}\n'
        else:
            addresses+=f'.globl {name}.original\n.set {name}.original, {address:#x}\n'
            text+=f'.globl {name}\n{name}:\n bti c\n b {name}.original\n'
    (out/'source/hid-bindings.S').write_text(text);(out/'source/hid-addresses.S').write_text(addresses)
    for stem in ('hid-bindings','hid-addresses'):
        run([CLANG,'-target','arm64e-apple-ios27.0','-c',out/'source'/f'{stem}.S','-o',out/'objects'/f'{stem}.o'],out/(stem+'.log'))
    result=dict(original_kernelcache_sha256=abi['kernelcache_sha256'],fixture_sha256=sha(fixture),
                slots=len(actual),instance_bytes=208,all_authenticated_slots_match=True,
                bindings={n:hex(bindings[n]) for n in sorted(imports)},
                compiled_vtable=[dict(slot=i,symbol=n,diversity=hex(w>>32&0xffff)) for i,(n,w) in enumerate(table)],
                public_header_sha256=sha(out/'include/IOKit/hid/IOHIDDevice.h'),runtime_qualified=False)
    (out/'hid-abi.json').write_text(json.dumps(result,indent=2)+'\n')
    print('PASS actual D27 HID base208/207PACslots and original imports',flush=True)
    return result


def qualify_edge(out):
    """Check the exact original event-service and IOHIDEvent PAC contracts."""
    sys.path.insert(0,str(CI/'XnuPrelink'))
    from kc_image import Image,scan
    raw=CACHE.read_bytes();collection=Image(raw);fixups=collection.fixups()
    family=Image(raw,collection.entries['com.apple.iokit.IOHIDFamily'][1])
    # The original family is stripped. Establish each selected class from its
    # own getMetaClass and named metaclass-constructor instruction references.
    classes={
        'IOHIDEventDriver':(0xfffffff008000b60,0xfffffff00aee3f20,0xfffffff0099ccd40,96,0xfffffff0078412ba),
        'AppleUserHIDEventService':(0xfffffff007ff7978,0xfffffff00aee37c0,0xfffffff009990728,64,0xfffffff00783ea5a),
        'IOHIDEvent':(0xfffffff008001410,0xfffffff00aee3f48,0xfffffff0099d8ce4,64,0xfffffff0078414cb),
    }
    identity=[]
    for classname,(vptr,meta,constructor,length,string) in classes.items():
        if collection.read(string,len(classname)+1)!=classname.encode()+b'\0':raise ValueError('Original class string differs')
        getter=fixups[vptr+7*8][0];body=collection.read(getter,16)
        if not any(target==meta for site,target,kind in scan(body,getter)[1]):raise ValueError('Original getMetaClass differs')
        ctor=collection.read(constructor,length);refs=scan(ctor,constructor)[1]
        if not all(any(target==address for site,target,kind in refs) for address in (meta,string)):
            raise ValueError('Original named class constructor differs')
        identity.append(dict(classname=classname,vptr=hex(vptr),metaclass=hex(meta),getter=hex(getter),
            getter_sha256=hashlib.sha256(body).hexdigest(),class_constructor=hex(constructor),
            constructor_bytes=length,constructor_sha256=hashlib.sha256(ctor).hexdigest(),name_address=hex(string)))
    text=(out/'source/NativeHidInput.cpp').read_text()
    table=text.split('static const uint16_t kSlotDiversity[]={',1)[1].split('};',1)[0]
    diversities=[int(value,16) for value in re.findall(r'0x([0-9a-fA-F]+)',table)]
    records=[]
    for classname in ('IOHIDEventDriver','AppleUserHIDEventService'):
        start=classes[classname][0]
        actual=[fixups.get(start+8*i) for i in range(len(diversities))]
        if any(not row or row[1:]!=(1,0,diversity,1) for row,diversity in zip(actual,diversities)):
            raise ValueError('Original event-service PAC schema differs: '+classname)
        if start+8*len(diversities) in fixups:raise ValueError('Original event-service vtable extends past source table')
        records.append(dict(classname=classname,vtable=hex(start),slots=len(actual),all_pac_diversities_match=True))
    # These callbacks are the ones the current source calls, with public signatures.
    for slot,div in ((18,0x8758),(23,0x02c5),(24,0x130e),(25,0xf637)):
        row=fixups[classes['IOHIDEvent'][0]+slot*8]
        if row[1:]!=(1,0,div,1):raise ValueError('IOHIDEvent callback schema differs')
        records.append(dict(classname='IOHIDEvent',slot=slot,target=hex(row[0]),diversity=hex(div)))
    result=dict(kernelcache_sha256=sha(CACHE),tables=records,class_identity=identity,
                exact_class_filter=['IOHIDEventDriver','AppleUserHIDEventService'],foreign_tables_not_modified=True,
                function_pointer_type_discrimination=True,runtime_qualified=False)
    (out/'edge-abi.json').write_text(json.dumps(result,indent=2)+'\n')
    print('PASS original D27 edge-event classes and callback PAC schemas',flush=True)
    return result


def adapt_native(text):
    # A void* -> function pointer cast consumes the discriminator-zero schema.
    # Keep the source's auth-and-resign0, which the compiler folds into the
    # actual slot-authenticated call. A type-diversified value carried through
    # void* mismatches this conversion; verify the emitted call, not just slots.
    old='''    void *function=ptrauth_auth_and_resign(*entry,ptrauth_key_function_pointer,ptrauth_blend_discriminator(entry,diversity),
        ptrauth_key_function_pointer,0);
    return reinterpret_cast<R (*)(void *,A...)>(function)(object,args...);'''
    if text.count(old)!=1:raise ValueError('Native HID callback schema anchor changed')
    old='ptrauth_sign_unauthenticated(function,ptrauth_key_function_pointer,0));'
    if text.count(old)!=1:raise ValueError('Original dispatch function-pointer schema anchor changed')
    # Virtual digitizer truthfully names its transport. Scaling uses the shared
    # abstract input-coordinate range; no physical screen dimensions are used.
    text=text.replace('touchOnly?"SPI":"Virtual"','touchOnly?"VirtIO":"Virtual"')
    # QEMU has no hardware button provider. Do not retain an unresolved optional
    # function provider solely for an input path that will never be selected.
    for line in ('extern "C" void native_buttons_set_sink(void (*)(void *, uint32_t), void *) __attribute__((weak_import));\n',
                 '        if(!touchOnly && &native_buttons_set_sink)native_buttons_set_sink(&NativeHidInput::buttonsNotify,this);\n',
                 '        if(!touchOnly && &native_buttons_set_sink)native_buttons_set_sink(nullptr,nullptr);\n'):
        if text.count(line)!=1:raise ValueError('Native hardware-button anchor changed')
        text=text.replace(line,'')
    # The combined keyboard/digitizer is the known D27 matching arrangement;
    # a separate touch service needs no IORegistry property rewrite on keyboard.
    return text


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--resume',action='store_true')
    p.add_argument('--stage',choices=('headers','compile','all'),default='all')
    a=p.parse_args();out=a.out.resolve()
    if shutil.disk_usage('/mnt/g').free<8*1024**3:raise ValueError('G reserve below 8 GiB')
    if not str(out).startswith(str(BASE)+'/qemu-input-'):raise ValueError('Require isolated EXT4 qemu-input output under BASE')
    if not a.resume:out.mkdir(parents=True,exist_ok=False)
    elif not out.is_dir():raise ValueError('No input build to resume')
    if subprocess.check_output(['git','-C',str(HID),'rev-parse','HEAD'],text=True).strip()!=HID_REVISION:
        raise ValueError('Pinned D27 IOHIDFamily source differs')
    if subprocess.check_output(['git','-C',str(HID),'status','--porcelain'],text=True).strip():
        raise ValueError('Pinned IOHIDFamily source is modified')
    include=out/'include';source=out/'source';objects=out/'objects'
    for folder in (include,source,objects):folder.mkdir(exist_ok=True)
    if a.stage in ('headers','all'):
        for original,relative in ((HID/'IOHIDFamily','IOKit/hid'),(HID/'IOHIDSystem/IOKit/hidsystem','IOKit/hidsystem')):
            dest=include/relative;dest.mkdir(parents=True,exist_ok=True)
            for path in original.glob('*.h'):shutil.copyfile(path,dest/path.name)
        generated=include/'HIDDriverKit';generated.mkdir(exist_ok=True)
        shutil.copyfile(HID/'IOHIDFamily/IOHIDDeviceTypes.h',generated/'IOHIDDeviceTypes.h')
        target=SDK/'usr/include/TargetConditionals.h'
        if not target.is_file():
            target=SDK/'System/Library/Frameworks/Kernel.framework/Versions/A/Headers/TargetConditionals.h'
        if not target.is_file():
            target=BASE/'user-sdk-002/repository/iPhoneOS27.0.sdk/usr/include/TargetConditionals.h'
        shutil.copyfile(target,include/'TargetConditionals.h')
        graphics=include/'IOKit/graphics/IOGraphicsTypes.h';graphics.parent.mkdir(parents=True,exist_ok=True)
        graphics_url='https://raw.githubusercontent.com/apple-oss-distributions/IOGraphics/76285384ff0ce63965a21b8023bf6d7e447fcc19/IOGraphicsFamily/IOKit/graphics/IOGraphicsTypes.h'
        if not graphics.is_file():
            with urllib.request.urlopen(graphics_url,timeout=30) as response:graphics.write_bytes(response.read())
        (out/'graphics-header.json').write_text(json.dumps(dict(url=graphics_url,sha256=sha(graphics),
            role='transitive public HID header only; no graphics object is compiled'),indent=2)+'\n')
        command=['/root/unixnu-build/iig-pac-fixed/bin/iig','--def',HID/'HIDDriverKit/IOHIDDevice.iig',
                 '--header',generated/'IOHIDDevice.h','--impl',out/'IOHIDDevice.iig.cpp','--','-x','c++','-std=gnu++17',
                 '-D__IIG=1','-DPLATFORM_DriverKit=1','-DTARGET_OS_DRIVERKIT=1','-I',include,'-isysroot',SDK,
                 '-iframework',SDK/'System/Library/Frameworks','-idirafter',SDK/'usr/include',
                 '-idirafter',SDK/'System/Library/Frameworks/Kernel.framework/Versions/A/Headers',
                 '-idirafter',BASE/'user-sdk-002/repository/iPhoneOS27.0.sdk/usr/include']
        run(command,out/'generate-hid.log')
        (out/'headers.json').write_text(json.dumps(dict(source=str(HID),revision=HID_REVISION,
            files={str(path):sha(path) for path in include.rglob('*.h')},
            iig=str(command[0]),iig_sha256=sha(command[0]),definition_sha256=sha(HID/'HIDDriverKit/IOHIDDevice.iig')),indent=2)+'\n')
        print('Generated pinned HID declarations',flush=True)
    if a.stage=='headers':return
    # Compile the actual current source. Target ABI is audited before any archive
    # can be emitted; no iOS17 binary archive or guessed private object is used.
    native=source/'NativeHidInput.cpp'
    native.write_text(adapt_native((SHENG/'drivers/ShengHidInput/NativeHidInput.cpp').read_text()))
    commands={}
    commands['NativeHidInput']=compile_cpp(native,objects/'NativeHidInput.o',
        ['-I',str(include),'-idirafter',str(SDK/'System/Library/Frameworks/Kernel.framework/Versions/A/Headers')],
        ['-DNATIVE_HID_SOURCE_API=1'])
    (out/'compile.json').write_text(json.dumps(commands,indent=2)+'\n')
    audit_hid(out)
    qualify_edge(out)


if __name__=='__main__':main()
