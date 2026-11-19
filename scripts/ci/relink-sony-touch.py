#!/usr/bin/env python3
"""Relink Sony-only HID, inheriting the Blocks-ABI-corrected physical063 by default."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--touch',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--touch-screen',action='store_true')
    parser.add_argument('--panic-reserve',action='store_true',help='Reserve a dedicated zero RX section for the checked panic renderer')
    parser.add_argument('--from-native',type=Path,default=BASE/'native-block-abi-063-001')
    args=parser.parse_args()
    before=args.from_native
    result=json.loads((before/'result.json').read_text())
    if sha(before/'native.macho') not in ('423782c03b6a0e5d637ac1db990c196cfc5a490720b9df8f19db151e022705f3',
        '83d8980f0158874f53684035b4606e14fc83657a4d7a5737e8e656e35344d0c1'):
        raise ValueError('Require exact physical060 or Block-ABI-corrected063 native')
    touch=json.loads((args.touch/'result.json').read_text())
    if sha(touch['archive'])!=touch['sha256'] or touch['virtual_backend_included'] is not False:
        raise ValueError('Sony-only touch archive required')
    for key in ('sources','objects'):
        for path,digest in touch[key].items():
            if sha(path)!=digest:raise ValueError('Qualified touch input changed: '+path)
    sys.path.insert(0,str(ROOT/'ci'));from native_source_overlays import validate_overlays
    from compile_dependencies import run_recorded,valid
    validate_overlays(result,sha)
    display=BASE/'display-source-009';original=display/'kits/sheng/LegacyDisplayProbe.cpp'
    original_display=json.loads((display/'result.json').read_text())
    if sha(original)!=original_display['staged_probe_sha256']:
        raise ValueError('Physical display startup source differs')
    dependency=json.loads((display/'build/native-legacy-display/LegacyDisplayProbe.o.dependencies.json').read_text())
    if not valid(dependency):raise ValueError('Physical display compile dependencies changed')
    args.out.mkdir(parents=True,exist_ok=False);out=args.out.resolve()
    source=out/'LegacyDisplayProbe.cpp'
    text=original.read_text();anchor='    sheng_gpu_power_probe();\n'
    if text.count(anchor)!=1:raise ValueError('Qualified display late-start anchor differs')
    source.write_text(text.replace(anchor,anchor+
        '    extern void native_sony_touch_start(void);\n    native_sony_touch_start();\n'))
    obj=out/'LegacyDisplayProbe.o';command=[];old_command=list(dependency['command']);index=0
    while index<len(old_command):
        value=old_command[index]
        if value in ('-MF','-MT','-MQ'):index+=2;continue
        if value in ('-MD','-MMD'):index+=1;continue
        command.append(value);index+=1
    command[command.index(str(original))]=str(source);command[command.index('-o')+1]=str(obj)
    command+=['-Wno-missing-designated-field-initializers','-Wno-unused-but-set-global']
    plan=json.loads((BASE/'pac-abi-native-019/plan.json').read_text())
    directory=next(j['directory'] for j in plan['jobs'] if Path(j['source']).name=='IOPlatformExpert.cpp')
    with (out/'startup-compile.log').open('x') as stream:
        done=run_recorded(command,cwd=directory,stdout=stream,stderr=subprocess.STDOUT,timeout=120)
    if done.returncode:raise RuntimeError((out/'startup-compile.log').read_text()[-8000:])
    archive=out/'libPhysicalDisplaySonyTouch.a'
    archive.write_bytes(Path(result['display_source']['archive']).read_bytes())
    subprocess.run(['llvm-ar','r',str(archive),str(obj)],check=True)
    screen_archive=None;screen_source=None
    if args.touch_screen:
        screen=BASE/'boot-screen-015';screen_original=screen/'BootProgress.c'
        screen_row=next(row for row in json.loads((screen/'result.json').read_text())['sources'] if row['source']==str(screen_original))
        if sha(screen_original)!=screen_row['sha256']:
            raise ValueError('Baseline screen source differs')
        screen_text=screen_original.read_text();screen_anchor='  if(0 && &native_touch_rows) {'
        if screen_text.count(screen_anchor)!=1:raise ValueError('Touch screen row anchor differs')
        screen_source=out/'BootProgress.c'
        screen_source.write_text(screen_text.replace(screen_anchor,'  if(&native_touch_rows && native_touch_rows[0][0]) {'))
        screen_dep=json.loads((screen/'BootProgress.o.dependencies.json').read_text())
        if not valid(screen_dep):raise ValueError('Baseline screen dependencies differ')
        screen_directory=Path(next(p for p in screen_dep['dependencies'] if Path(p).name=='meta_features.h')).parent
        screen_command=[];index=0;old_command=screen_dep['command']
        while index<len(old_command):
            value=old_command[index]
            if value in ('-MF','-MT','-MQ'):index+=2;continue
            if value in ('-MD','-MMD'):index+=1;continue
            screen_command.append(value);index+=1
        screen_obj=out/'BootProgress.o'
        screen_command[screen_command.index(str(screen_original))]=str(screen_source)
        screen_command[screen_command.index('-o')+1]=str(screen_obj)
        screen_command+=['-I',str(screen)]
        with (out/'screen-compile.log').open('x') as stream:
            done=run_recorded(screen_command,cwd=screen_directory,stdout=stream,stderr=subprocess.STDOUT,timeout=120)
        if done.returncode:raise RuntimeError((out/'screen-compile.log').read_text()[-8000:])
        screen_archive=out/'libSonyTouchBootScreen.a'
        screen_archive.write_bytes(Path(result['boot_screen']['archive']).read_bytes())
        subprocess.run(['llvm-ar','r',str(screen_archive),str(screen_obj)],check=True)
    link=json.loads((before/'native-link.command.json').read_text())
    old='-Wl,-force_load,'+result['display_source']['archive']
    if link.count(old)!=1:raise ValueError('Unique physical display archive required')
    link[link.index(old)]='-Wl,-force_load,'+str(archive)
    if result.get('sony_touch'):
        old='-Wl,-force_load,'+result['sony_touch']['archive']
        if link.count(old)!=1:raise ValueError('Unique previous Sony touch archive required')
        link[link.index(old)]='-Wl,-force_load,'+touch['archive']
    else:link.append('-Wl,-force_load,'+touch['archive'])
    if screen_archive:
        old='-Wl,-force_load,'+result['boot_screen']['archive']
        if link.count(old)!=1:raise ValueError('Unique baseline screen archive required')
        link[link.index(old)]='-Wl,-force_load,'+str(screen_archive)
    reserve=None
    if args.panic_reserve:
        reserve=out/'panic-reserve.bin';reserve.write_bytes(bytes(4096))
        if any('__pdxpanic' in value for value in link):raise ValueError('Duplicate panic reserve')
        link.append('-Wl,-sectcreate,__TEXT_EXEC,__pdxpanic,'+str(reserve))
    link[link.index('-o')+1]=str(out/'native.macho')
    env=dict(os.environ,CROSS_CLANG='/root/unixnu-build/pdx234-pac-toolchain/llvm/bin/clang-24',
             DARWIN_TRIPLE='arm64e-apple-ios27.0',CROSS_EXTRA_FLAGS=result['pac_flag'],TMPDIR=str(out))
    env['PATH']=str(Path(link[0]).parent)+':'+env['PATH']
    with (out/'native-link.log').open('x') as stream:
        done=subprocess.run(link,env=env,stdout=stream,stderr=subprocess.STDOUT,timeout=300)
    if done.returncode:raise RuntimeError((out/'native-link.log').read_text()[-10000:])
    receipt=copy.deepcopy(result)
    receipt.update(native=str(out/'native.macho'),native_sha256=sha(out/'native.macho'),
                    sony_touch=touch,runtime_qualified=False)
    if reserve:
        receipt['panic_reserve']=dict(section='__TEXT_EXEC,__pdxpanic',bytes=4096,input=str(reserve),sha256=sha(reserve))
    receipt['display_source'].update(archive=str(archive),sha256=sha(archive),
        staged_probe_sha256=sha(source),sony_touch_start_connected=True)
    if screen_archive:
        receipt['boot_screen'].update(archive=str(screen_archive),sha256=sha(screen_archive),sony_touch_rows_enabled=True)
        row=next(row for row in receipt['boot_screen']['sources'] if Path(row['source']).name=='BootProgress.c')
        row.update(source=str(screen_source),sha256=sha(screen_source))
    (out/'native-link.command.json').write_text(json.dumps(link,indent=2)+'\n')
    (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
    record={'native_sha256':receipt['native_sha256'],'touch_archive_sha256':touch['sha256'],
            'display_archive_sha256':sha(archive),'baseline':str(before),'baseline_sha256':result['native_sha256'],
            'virtual_backends_selected':False,'staging_only':True,'image_delivered':False,
            'device_operations':False,'known_limits':touch['known_limits']}
    (out/'touch-integration.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))


if __name__=='__main__':main()
