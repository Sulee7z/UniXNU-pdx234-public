#!/usr/bin/env python3
"""Relink work011 with pinned upstream PAC-user/JOP, PAR sync and union-fsid hunks."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
sys.path.insert(0,str(ROOT/'ci/qemu'))
from upstream_20261108_parity import FILES,adapt,make_diff,PINS,COMMITS
sys.path.insert(0,str(ROOT/'ci'))
from compile_dependencies import run_recorded,valid,capture as capture_dependencies


def sha(path):
    with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--from-work',type=Path,default=BASE/'qemu-current-20261117-011')
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    if shutil.disk_usage('/mnt/g').free<8*1024**3:raise ValueError('G reserve below8GiB')
    source_native=a.from_work/'native';prior=json.loads((source_native/'result.json').read_text())
    if sha(source_native/'native.macho')!=prior['native_sha256'] or not prior['qemu_workloop_event_classification']:
        raise ValueError('Require the exact PM-repaired D27 native baseline')
    layout=json.loads((BASE/'native-screen007-055-001/plan.json').read_text())
    from native_source_overlays import validate_overlays
    validate_overlays(prior,sha)
    out=a.out.resolve()
    if out.exists():raise ValueError('Preserve existing parity build')
    native=out/'native';native.mkdir(parents=True,exist_ok=False)
    records={}
    for unit in FILES:
        name=Path(unit).name
        jobs=[row for row in layout['jobs'] if Path(row['source']).name==name]
        if len(jobs)!=1:raise ValueError('Require one exact original compile recipe for '+unit)
        job=jobs[0];original=Path(job['source'])
        if sha(original)!=job['source_sha256']:raise ValueError('Pinned XNU source changed: '+unit)
        before=original.read_text();after=adapt(unit,before)
        target=native/name;target.write_text(after)
        command=list(job['command']);command[command.index(str(original))]=str(target)
        command+=['-iquote',str(original.parent)]
        object_path=native/(name+'.o');command[command.index('-o')+1]=str(object_path)
        assembly=original.suffix in ('.s','.S')
        if assembly:
            assym=BASE/'native-screen007-055-001/generated-assym/assym.s'
            expected='845994a700faef3a21777b9534c0480bac50742ca6ef59ff0506316c05db4276'
            if sha(assym)!=expected:raise ValueError('Retained generated arm64e assym differs')
            if str(assym.parent) not in command:raise ValueError('Assembly recipe must use the actual PAC-generated assym')
            command+=['-MD','-MF',str(object_path)+'.d','-MT','pdx_object']
        log=native/(name+'.compile.log')
        with log.open('x') as stream:
            run=subprocess.run if assembly else run_recorded
            done=run(command,cwd=job['directory'],stdout=stream,stderr=subprocess.STDOUT,timeout=300)
        if done.returncode:raise RuntimeError(log.read_text()[-10000:])
        if assembly:
            deps=capture_dependencies(str(object_path)+'.d',job['directory'],command[0])
            deps.update(source=str(target),object=str(object_path),object_sha256=sha(object_path),command=command)
            save(Path(str(object_path)+'.dependencies.json'),deps)
        dep=Path(str(object_path)+'.dependencies.json');receipt=json.loads(dep.read_text())
        if receipt.get('exit',0)!=0 or not valid(receipt):raise ValueError('Input/source dependencies changed: '+unit)
        base_source=Path(job.get('original_source',str(original)))
        if job.get('original_source') and sha(base_source)!=job['original_source_sha256']:
            raise ValueError('Underlying XNU source changed: '+unit)
        records[unit]=dict(patch_shas=PINS,original_source=str(base_source),original_sha256=sha(base_source),
            input_source=str(original),input_source_sha256=sha(original),replaces=job['output'],
            adapted_source=str(target),adapted_sha256=sha(target),object=str(object_path),object_sha256=sha(object_path),
            dependency_receipt=str(dep),dependency_sha256=sha(dep),compile_command=command,
            source_diff=make_diff(unit,before,after))

    command=json.loads((source_native/'native-link.command.json').read_text())
    filelist=Path(command[command.index('-filelist')+1]);files=filelist.read_text().splitlines()
    replaced=[]
    for unit,record in records.items():
        old=record['replaces']
        if files.count(old)!=1:raise ValueError('Actual selected object missing/ambiguous: '+unit)
        files[files.index(old)]=record['object'];record['replaces']=old;replaced.append(old)
    new_list=native/'link.filelist';new_list.write_text('\n'.join(files)+'\n')
    command[command.index('-filelist')+1]=str(new_list);command[command.index('-o')+1]=str(native/'native.macho')
    save(native/'native-link.command.json',command)
    env=dict(os.environ,CROSS_CLANG='/root/unixnu-build/pdx234-pac-toolchain/llvm/bin/clang-24',
        CROSS_EXTRA_FLAGS=prior['pac_flag'],DARWIN_TRIPLE='arm64e-apple-ios27.0',TMPDIR=str(native))
    env['PATH']=str(Path(command[0]).parent)+':'+env['PATH']
    with (native/'native-link.log').open('x') as stream:done=subprocess.run(command,env=env,stdout=stream,stderr=subprocess.STDOUT,timeout=360)
    if done.returncode:raise RuntimeError((native/'native-link.log').read_text()[-12000:])
    result=copy.deepcopy(prior)
    result['native_source_patches']=[row for row in result['native_source_patches'] if Path(row['original_source']).name not in ('locore.s','machine_routines_asm.s','vfs_syscalls.c')]
    for unit,record in records.items():
        tag='upstream-union-readdir' if unit=='bsd/vfs/vfs_syscalls.c' else 'official-upstream-parity:'+Path(unit).name
        result['native_source_patches'].append(dict(native_source_patch=tag,
            original_source=record['original_source'],original_source_sha256=record['original_sha256'],
            source=record['adapted_source'],source_sha256=record['adapted_sha256']))
    result.update(native=str(native/'native.macho'),native_sha256=sha(native/'native.macho'),
        runtime_qualified=False,
        official_upstream_parity=dict(commits=COMMITS,objects=replaced,
            source_and_object_hashes=records,strict_pending=True))
    validate_overlays(result,sha)
    save(native/'result.json',result)
    save(out/'parity-qualification.json',dict(native_sha256=result['native_sha256'],source_hashes={u:r['adapted_sha256'] for u,r in records.items()},
        object_hashes={u:r['object_sha256'] for u,r in records.items()},upstream_patch_pins=PINS,
        only_selected_generic_hunks=True,source_permissions_or_signatures_changed=False,device_operations=False,guest_runtime_verified=False))
    print(json.dumps(dict(native=str(native/'native.macho'),native_sha256=result['native_sha256'],
        original_objects=replaced,upstream_patch_pins=PINS),indent=2),flush=True)


if __name__=='__main__':main()
