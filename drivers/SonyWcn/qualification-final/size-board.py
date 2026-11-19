#!/usr/bin/env python3
"""Isolated -Oz rebuild of frozen radio002 board objects, never rewrite inputs.

Only the optimization level and new output/dependency paths change. A verbatim
source copy is compiled with every original header hash checked before/after.
The previously frozen board source/headers/archive remain untouched.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113/sony-wcn-067-002')

def sha(path):
    with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def execute(args,cwd=None):
    r=subprocess.run(list(map(str,args)),cwd=cwd,capture_output=True,text=True,timeout=180)
    if r.returncode:raise RuntimeError(r.stdout+r.stderr)
    return r.stdout+r.stderr

def run(source_name,out):
    old=BASE/'objects'/(source_name+'.o')
    receipt=BASE/'objects'/(source_name+'.o.dependencies.json')
    before=json.loads(receipt.read_text())
    if sha(old)!=before['object_sha256'] or sha(before['dependency_compiler'])!=before['dependency_compiler_sha256']:
        raise ValueError('Frozen compile object/compiler identity differs')
    for p,h in before['dependencies'].items():
        if sha(p)!=h:raise ValueError('Frozen dependency changed: '+p)
    src=Path(before['source']);staged=out/'source'/src.name
    staged.parent.mkdir(exist_ok=True)
    shutil.copyfile(src,staged)
    obj=out/'objects'/old.name;obj.parent.mkdir(exist_ok=True)
    cmd=list(before['command'])
    if cmd.count('-O2')!=1:raise ValueError('Unique original O2 required')
    cmd[cmd.index('-O2')]='-Oz'
    cmd[cmd.index(str(src))]=str(staged)
    cmd[cmd.index('-o')+1]=str(obj)
    cmd[cmd.index('-MF')+1]=str(obj.with_name(obj.name+'.d'))
    log=execute(cmd,cwd=before['cwd']);obj.with_suffix('.log').write_text(log)
    obj.with_name(obj.name+'.command.json').write_text(json.dumps(cmd,indent=2)+'\n')
    deps=shlex.split(obj.with_name(obj.name+'.d').read_text().replace('\\\n','').partition(':')[2])
    actual={str((Path(before['cwd'])/p).absolute()):sha(Path(before['cwd'])/p) for p in deps}
    expected=dict(before['dependencies']);expected.pop(str(src));expected[str(staged)]=sha(src)
    # Source relocation must not change any include identity.
    if actual!=expected:
        raise ValueError('Header closure changed: '+repr(set(actual)^set(expected)))
    for p,h in before['dependencies'].items():
        if sha(p)!=h:raise ValueError('Frozen dependency changed while compiling: '+p)
    rec=dict(before,source=str(staged),object=str(obj),object_sha256=sha(obj),command=cmd,dependencies=actual,
             optimization_change={'before':'-O2','after':'-Oz'},frozen_receipt=str(receipt),frozen_receipt_sha256=sha(receipt))
    obj.with_name(obj.name+'.dependencies.json').write_text(json.dumps(rec,indent=2)+'\n')
    return obj,rec

def text_bytes(path):
    # Mach-O object code sizes: __TEXT,__text plus __TEXT stubs/literals remain
    # individually recorded. Final page alignment can only be proven by relink.
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    from qualify import Object
    obj=Object(path)
    return sum(s['size'] for s in obj.sections if s['segment']=='__TEXT' and s['name']=='__text')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--minimum-saving',type=int,default=16384)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False);out=a.out.resolve()
    archive=out/'libSonyWcn.a';frozen=BASE/'libSonyWcn.a'
    if sha(frozen)!='6cf62fdf57c7ffa34985857e37f4e57ebdcafe7f8f3ba482d8033da50bfdf566':raise ValueError('Frozen board archive changed')
    shutil.copyfile(frozen,archive)
    sys.path.insert(0,str(ROOT/'ci/platform067/arm64e'))
    from audit import ar_members
    old_members={name:digest for name,digest,size in ar_members(frozen)}
    replacements=[];receipts=[];saved=0
    for name in ('WifiProbe','WifiNet'):
        obj,receipt=run(name,out)
        old=BASE/'objects'/(name+'.o')
        final=obj
        if name=='WifiNet':
            final=out/'objects/WifiNet.late.o'
            execute(['llvm-objcopy-23','--remove-section=__DATA,__mod_init_func','--globalize-symbol=__GLOBAL__sub_I_WifiNet.cpp',obj,final])
            old=BASE/'objects/WifiNet.late.o'
        saving=text_bytes(old)-text_bytes(final);saved+=saving
        execute(['llvm-ar','r',archive,final])
        replacements.append(dict(member=final.name,old_object=str(old),old_sha256=sha(old),new_object=str(final),
                                 new_sha256=sha(final),old_text_bytes=text_bytes(old),new_text_bytes=text_bytes(final),text_bytes_saved=saving))
        receipts.append(str(obj.with_name(obj.name+'.dependencies.json')))
        if saved>=a.minimum_saving:break
    new_members={name:digest for name,digest,size in ar_members(archive)}
    changed={r['member'] for r in replacements}
    if set(new_members)!=set(old_members) or any(new_members[n]!=h for n,h in old_members.items() if n not in changed):
        raise ValueError('Untouched archive member changed')
    old_symbols={line.split()[-1] for line in execute(['llvm-nm','-g','--defined-only',frozen]).splitlines() if len(line.split())==3}
    new_symbols={line.split()[-1] for line in execute(['llvm-nm','-g','--defined-only',archive]).splitlines() if len(line.split())==3}
    if old_symbols!=new_symbols:raise ValueError('Public board ABI symbol set changed')
    result=dict(passed=True,archive=str(archive),sha256=sha(archive),frozen_archive=str(frozen),frozen_sha256=sha(frozen),
                optimization='-Oz',same_source_and_headers=True,pac_flags_unchanged=True,other_members_byte_identical=True,
                replacements=replacements,compile_receipts=receipts,text_bytes_saved=saved,required_saving=a.minimum_saving,
                raw_saving_meets_request=saved>=a.minimum_saving,final_page_layout_qualified=False,
                defined_symbols_retained=len(old_symbols),device_operations=False,frozen_inputs_modified=False)
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
