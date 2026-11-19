#!/usr/bin/env python3
"""Build an isolated authenticated VirtIO read-cache derivative of work011."""
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
sys.path.insert(0,str(ROOT/'ci'))
from compile_dependencies import run_recorded,valid
from qemu.verified_read_cache import adapt


def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--from-work',type=Path,default=BASE/'qemu-current-20261117-011')
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--read-ahead',action='store_true',help='Verify and cache complete bounded64KiB readonly windows')
    a=p.parse_args()
    if shutil.disk_usage('/mnt/g').free<8*1024**3:raise ValueError('G reserve below8GiB')
    previous=a.from_work/'native';before=json.loads((previous/'result.json').read_text())
    if sha(previous/'native.macho')!=before['native_sha256'] or not before['qemu_workloop_event_classification']:
        raise ValueError('Exact current PM/input native required')
    old_archive=Path(before['qemu_storage_archive'])
    if sha(old_archive)!=before['qemu_storage_archive_sha256']:raise ValueError('Qualified storage archive differs')
    selected=next(row for row in before['qemu_current_sources'] if Path(row['source']).name=='NativeVirtioBlock.cpp')
    if sha(selected['source'])!=selected['source_sha256'] or sha(selected['object'])!=selected['object_sha256']:
        raise ValueError('Exact selected transport object required')
    a.out.mkdir(parents=True,exist_ok=False);storage=a.out/'storage';storage.mkdir();native=a.out/'native';native.mkdir()
    source=storage/'NativeVirtioBlock.cpp';source.write_text(adapt(Path(selected['source']).read_text(),read_ahead=a.read_ahead))
    shutil.copyfile(ROOT/'ci/qemu/D27VerifiedReadCache.h',storage/'D27VerifiedReadCache.h')
    subprocess.run(['python3','-B',str(ROOT/'ci/qemu/check-d27-verified-cache.py'),
        '--source',str(source),'--out',str(a.out/'tests')],check=True,timeout=60)
    command=json.loads((old_archive.parent/'NativeVirtioBlock.command.json').read_text())
    command[command.index(selected['source'])]=str(source)
    command[command.index('-o')+1]=str(storage/'NativeVirtioBlock.o')
    command+=['-I',str(storage)]
    directory=next(row['directory'] for row in json.loads((BASE/'native-screen007-055-001/plan.json').read_text())['jobs'] if Path(row['source']).name=='NativeRamBlock.cpp')
    with (storage/'compile.log').open('x') as stream:
        done=run_recorded(command,cwd=directory,stdout=stream,stderr=subprocess.STDOUT,timeout=180)
    if done.returncode:raise RuntimeError((storage/'compile.log').read_text()[-10000:])
    deps=storage/'NativeVirtioBlock.o.dependencies.json'
    if not valid(json.loads(deps.read_text())):raise ValueError('Compile dependencies changed')
    save(storage/'compile-command.json',command)
    late=storage/'NativeVirtioBlock.late.o'
    subprocess.run(['llvm-objcopy-23','--remove-section=__DATA,__mod_init_func',
        '--globalize-symbol=__GLOBAL__sub_I_NativeVirtioBlock.cpp',str(storage/'NativeVirtioBlock.o'),str(late)],check=True)
    audit=load('cache_block_audit',ROOT/'scripts/ci/audit-d27-block-interface.py')
    tables=load('cache_block_tables',ROOT/'scripts/ci/build-qemu-source-block.py')
    interface=json.loads((old_archive.parent/'interface-audit.json').read_text())
    base=old_archive.parent/'IOBlockStorageDevice.late.o'
    tables.validate_tables(interface['methods'],audit.object_vtable(base.read_bytes(),'__ZTV20IOBlockStorageDevice'),
        audit.object_vtable(late.read_bytes(),'__ZTV17NativeVirtioBlock'))
    members=subprocess.check_output(['llvm-ar','t',str(old_archive)],text=True).splitlines()
    objects=[]
    for name in members:
        old=old_archive.parent/name
        if subprocess.check_output(['llvm-ar','p',str(old_archive),name])!=old.read_bytes():raise ValueError('Stored archive member differs')
        objects.append(late if name=='NativeVirtioBlock.late.o' else old)
    archive=storage/'libQemuCurrentStorage.a'
    subprocess.run(['llvm-ar','rcs',str(archive),*map(str,objects)],check=True)
    link=json.loads((previous/'native-link.command.json').read_text())
    marker='-Wl,-force_load,'+str(old_archive)
    if link.count(marker)!=1:raise ValueError('Unique actual storage archive required')
    link[link.index(marker)]='-Wl,-force_load,'+str(archive)
    link[link.index('-o')+1]=str(native/'native.macho');save(native/'native-link.command.json',link)
    env=dict(os.environ,CROSS_CLANG='/root/unixnu-build/pdx234-pac-toolchain/llvm/bin/clang-24',
        CROSS_EXTRA_FLAGS=before['pac_flag'],DARWIN_TRIPLE='arm64e-apple-ios27.0',TMPDIR=str(native))
    env['PATH']=str(Path(link[0]).parent)+':'+env['PATH']
    with (native/'native-link.log').open('x') as stream:done=subprocess.run(link,env=env,stdout=stream,stderr=subprocess.STDOUT,timeout=300)
    if done.returncode:raise RuntimeError((native/'native-link.log').read_text()[-10000:])
    result=copy.deepcopy(before)
    for row in result['qemu_current_sources']:
        if row['source']==selected['source']:
            row.update(source=str(source),source_sha256=sha(source),object=str(late),object_sha256=sha(late),
                compile_recipe_sha256=sha(storage/'compile-command.json'))
    receipt=dict(source=str(source),source_sha256=sha(source),header_sha256=sha(storage/'D27VerifiedReadCache.h'),
        object_sha256=sha(late),dependency_receipt=str(deps),dependency_sha256=sha(deps),
        cache_bytes_per_device=32*1024**2,cache_slots=8192,block_bytes=4096,
        every_cache_hit_reverified=True,read_ahead_bytes=65536 if a.read_ahead else 0,
        original_verifier_changed=False,authenticated_slots=190,
        host_tests=str(a.out/'tests/result.json'),host_tests_sha256=sha(a.out/'tests/result.json'),
        runtime_verified=False,device_operations=False)
    result.update(native=str(native/'native.macho'),native_sha256=sha(native/'native.macho'),
        qemu_storage_archive=str(archive),qemu_storage_archive_sha256=sha(archive),qemu_verified_read_cache=receipt)
    save(native/'result.json',result);save(a.out/'cache-qualification.json',receipt)
    print(json.dumps(dict(native_sha256=result['native_sha256'],storage_sha256=sha(archive),
        pac_slots=190,cache_bytes_per_device=receipt['cache_bytes_per_device'],every_hit_reverified=True),indent=2))


if __name__=='__main__':main()
