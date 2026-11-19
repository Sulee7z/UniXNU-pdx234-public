#!/usr/bin/env python3
"""Add the qualified D27 virtual input transport to an isolated QEMU derivative."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def sha(path):
    with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--from-work',type=Path,default=BASE/'qemu-current-20261117-010')
    p.add_argument('--input',type=Path,default=BASE/'qemu-input-002')
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    if shutil.disk_usage('/mnt/g').free<8*1024**3:raise ValueError('G reserve below8GiB')
    before=json.loads((a.from_work/'native/result.json').read_text())
    if sha(a.from_work/'native/native.macho')!=before['native_sha256'] or not before['qemu_workloop_event_classification']:
        raise ValueError('Require the current PM-classification repair')
    hid=json.loads((a.input/'result.json').read_text())
    if sha(hid['archive'])!=hid['sha256'] or hid['hid_slots']!=207:raise ValueError('HID archive differs')
    for path,digest in hid['objects'].items():
        if sha(path)!=digest:raise ValueError('Qualified HID member changed')
    display=before['display_source']
    if sha(display['archive'])!=display['sha256']:raise ValueError('Display archive differs')
    a.out.mkdir(parents=True,exist_ok=False);native=a.out/'native';native.mkdir()
    source=Path(next(path for path in display['source_sha256'] if path.endswith('/LegacyDisplayProbe.cpp')))
    if sha(source)!=display['source_sha256'][str(source)]:raise ValueError('Display startup source differs')
    text=source.read_text();anchor='    native_keystore_probe();\n'
    if text.count(anchor)!=1:raise ValueError('Display late initializer changed')
    text=text.replace(anchor,anchor+'    extern void native_qemu_input_start(void);\n    native_qemu_input_start();\n')
    adapted=native/'LegacyDisplayProbe.cpp';adapted.write_text(text)
    spec=importlib.util.spec_from_file_location('display_compile',ROOT/'ci/qemu/display/build-qemu-display.py')
    builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
    command=display['commands']['LegacyDisplayProbe']
    job=json.loads((BASE/'pac-abi-native-019/plan.json').read_text())
    directory=next(j['directory'] for j in job['jobs'] if Path(j['source']).name=='IOPlatformExpert.cpp')
    obj=native/'LegacyDisplayProbe.o'
    builder.compile_cpp(adapted,obj,command,directory,native/'probe-compile.log')
    archive=native/'libQemuD27DisplayInput.a'
    objects=[]
    for path,digest in display['members'].items():
        original=Path(path)
        if sha(original)!=digest:raise ValueError('Display member changed')
        objects.append(obj if original.name=='LegacyDisplayProbe.o' else original)
    subprocess.run(['llvm-ar','rcs',str(archive),*map(str,objects)],check=True)
    command=json.loads((a.from_work/'native/native-link.command.json').read_text())
    old='-Wl,-force_load,'+display['archive']
    if command.count(old)!=1:raise ValueError('Unique display archive required')
    command[command.index(old)]='-Wl,-force_load,'+str(archive)
    command.append('-Wl,-force_load,'+hid['archive'])
    command[command.index('-o')+1]=str(native/'native.macho')
    save(native/'native-link.command.json',command)
    env=dict(os.environ,CROSS_CLANG='/root/unixnu-build/pdx234-pac-toolchain/llvm/bin/clang-24',
             DARWIN_TRIPLE='arm64e-apple-ios27.0',CROSS_EXTRA_FLAGS=before['pac_flag'],TMPDIR=str(native))
    env['PATH']=str(Path(command[0]).parent)+':'+env['PATH']
    with (native/'native-link.log').open('x') as f:
        done=subprocess.run(command,env=env,stdout=f,stderr=subprocess.STDOUT,timeout=300)
    if done.returncode:raise RuntimeError((native/'native-link.log').read_text()[-10000:])
    result=copy.deepcopy(before)
    result.update(native=str(native/'native.macho'),native_sha256=sha(native/'native.macho'),
                  qemu_virtual_input=hid,runtime_qualified=False)
    result['display_source'].update(archive=str(archive),sha256=sha(archive),input_startup_connected=True)
    save(native/'result.json',result)
    save(a.out/'input-integration.json',dict(native_sha256=result['native_sha256'],input_archive_sha256=hid['sha256'],
        display_archive_sha256=sha(archive),original_display_source_unchanged=True,physical_sources_changed=False,
        guest_runtime_verified=False,device_operations=False))
    print(json.dumps(json.loads((a.out/'input-integration.json').read_text()),indent=2))


if __name__=='__main__':main()
