#!/usr/bin/env python3
"""Audit all062 link inputs; rebuild every local Block producer/header consumer with D27 descriptor PAC."""
import argparse
import concurrent.futures
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
sys.path.insert(0,str(ROOT/'ci'))
from compile_dependencies import run_recorded,valid
from block_descriptor_abi import FLAGS,enabled,validate_record


def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')


def clean_command(command):
    result=[];i=0
    while i<len(command):
        if command[i] in ('-MF','-MT','-MQ','-MJ'):i+=2;continue
        if command[i] in ('-MD','-MMD','-MP'):i+=1;continue
        result.append(command[i]);i+=1
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--from-native',type=Path,default=BASE/'native-sony-touch-062-002')
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--jobs',type=int,default=6)
    a=parser.parse_args()
    if not 1<=a.jobs<=12:raise ValueError('Bounded compiler parallelism required')
    prior=json.loads((a.from_native/'result.json').read_text())
    if sha(a.from_native/'native.macho')!=prior['native_sha256'] or prior['native_sha256']!='013dd95dd917f3f8152efb607a8e4b9ed1eca90cc36c53606d8f493ee249c1d8':
        raise ValueError('Require the exact photo062 native')
    from native_source_overlays import validate_overlays
    validate_overlays(prior,sha)
    link=json.loads((a.from_native/'native-link.command.json').read_text())
    files=Path(link[link.index('-filelist')+1]).read_text().splitlines()
    archives=[s.split('-Wl,-force_load,')[-1] for s in link if s.endswith('.a')]
    tails=[s for s in link if s.endswith('.o')]
    inputs=files+archives+tails
    symbols=subprocess.run(['llvm-nm','-A','--format=posix',*inputs],capture_output=True,text=True,check=True).stdout
    owners={}
    for line in symbols.splitlines():
        owner,sep,entry=line.partition(': ')
        if not sep:continue
        fields=entry.split()
        if len(fields)<2:continue
        name,kind=fields[:2]
        producer='block_descriptor' in name or 'block_literal_global' in name or (
            kind=='U' and name in ('__NSConcreteStackBlock','__NSConcreteGlobalBlock'))
        runtime=name in ('__Block_copy','__Block_release','_Block_size') and kind!='U'
        if producer or runtime:owners.setdefault(owner,set()).add('producer' if producer else 'runtime')
    receipts={}
    for obj in files+tails:
        for suffix in ('.dependencies.json','.json'):
            path=Path(obj+suffix)
            if path.exists():
                receipt=json.loads(path.read_text());receipts[obj]=(path,receipt)
                if any(Path(s).name=='Block_private.h' for s in receipt.get('dependencies',{})):
                    owners.setdefault(obj,set()).add('private-header-consumer')
                break
    if any(owner not in files for owner in owners):
        raise ValueError('A producer outside the directly linked object list needs its own qualified archive recipe: '+repr([p for p in owners if p not in files]))
    a.out.mkdir(parents=True,exist_ok=False);out=a.out.resolve();(out/'objects').mkdir()
    (out/'block-owner-symbols.txt').write_text('\n'.join(s for s in symbols.splitlines() if s.partition(': ')[0] in owners)+'\n')
    records=[];commands=[]
    for index,(obj,reasons) in enumerate(sorted(owners.items())):
        if obj not in receipts:raise ValueError('Block object has no compile receipt: '+obj)
        path,receipt=receipts[obj]
        if not valid(receipt):raise ValueError('Original Block dependencies changed: '+obj)
        if sha(obj)!=receipt.get('object_sha256',receipt.get('sha256')):
            raise ValueError('Original Block object receipt identity differs: '+obj)
        source=Path(receipt['source'])
        if receipt.get('source_sha256') and sha(source)!=receipt['source_sha256']:
            raise ValueError('Original Block source differs')
        directory=receipt.get('directory')
        if not directory:
            candidates=[Path(p).parent for p in receipt['dependencies'] if Path(p).name=='meta_features.h']
            if len(candidates)!=1:raise ValueError('Cannot recover the exact compile directory')
            directory=str(candidates[0])
        command=clean_command(receipt['command']);new=out/'objects'/f'{index:03d}-{Path(obj).name}'
        command[command.index('-o')+1]=str(new)
        if not enabled(command):command+=FLAGS
        command+=['-Wno-missing-designated-field-initializers','-Wno-unused-but-set-global']
        if any(x.startswith('-fno-ptrauth') for x in command):raise ValueError('PAC disabling flag forbidden')
        row=dict(old_object=obj,old_sha256=sha(obj),new_object=str(new),source=str(source),source_sha256=sha(source),
                 prior_receipt=str(path),prior_receipt_sha256=sha(path),reasons=sorted(reasons),directory=directory,command=command)
        records.append(row);commands.append(command)
    if not any('runtime' in r['reasons'] for r in records):raise ValueError('Missing actual Blocks runtime')
    save(out/'plan.json',dict(baseline_native_sha256=prior['native_sha256'],compiler_flags=FLAGS,
        audited_inputs={p:sha(p) for p in inputs},replacements=records))
    print(f'Audited {len(inputs)} link inputs; compiling {len(records)} Block producer/runtime/header-consumer objects',flush=True)
    def compile_one(row):
        obj=Path(row['new_object']);log=obj.with_suffix(obj.suffix+'.log')
        with log.open('x') as stream:
            done=run_recorded(row['command'],cwd=row['directory'],stdout=stream,stderr=subprocess.STDOUT,timeout=180)
        if done.returncode:raise RuntimeError(str(log)+'\n'+log.read_text()[-10000:])
        row['new_sha256']=sha(obj);row['dependency_receipt']=str(obj)+'.dependencies.json'
        row['dependency_sha256']=sha(row['dependency_receipt'])
        return row
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as pool:
        futures=[pool.submit(compile_one,row) for row in records]
        complete=0
        for future in concurrent.futures.as_completed(futures):
            future.result();complete+=1
            if complete%8==0 or complete==len(records):print(f'Compiled {complete}/{len(records)}',flush=True)
    replacements={r['old_object']:r['new_object'] for r in records}
    new_files=[replacements.get(obj,obj) for obj in files]
    (out/'link.filelist').write_text('\n'.join(new_files)+'\n')
    link[link.index('-filelist')+1]=str(out/'link.filelist');link[link.index('-o')+1]=str(out/'native.macho')
    save(out/'native-link.command.json',link)
    env=dict(os.environ,CROSS_CLANG=records[0]['command'][0],CROSS_EXTRA_FLAGS=prior['pac_flag']+' -Xclang -fptrauth-block-descriptor-pointers',
             DARWIN_TRIPLE='arm64e-apple-ios27.0',TMPDIR=str(out))
    env['PATH']=str(Path(link[0]).parent)+':'+env['PATH']
    with (out/'native-link.log').open('x') as stream:
        done=subprocess.run(link,env=env,stdout=stream,stderr=subprocess.STDOUT,timeout=300)
    if done.returncode:raise RuntimeError((out/'native-link.log').read_text()[-12000:])
    qualification=dict(passed=True,compiler_flags=FLAGS,replacements=records,
        all_selected_producers_rebuilt=True,all_private_header_consumers_rebuilt=True,
        audited_link_inputs=len(inputs),producer_objects=sum('producer' in r['reasons'] for r in records),
        source_text_changed=False,auth_instructions_removed=False,original_abi='DA/address/0xc0bb',
        baseline_native_sha256=prior['native_sha256'],native_sha256=sha(out/'native.macho'),runtime_verified=False)
    validate_record(qualification)
    result=copy.deepcopy(prior);result.update(native=str(out/'native.macho'),native_sha256=sha(out/'native.macho'),
        block_descriptor_abi=qualification,runtime_qualified=False)
    save(out/'block-descriptor-qualification.json',qualification);save(out/'result.json',result)
    validate_overlays(result,sha)
    print(json.dumps(dict(native=result['native'],sha256=result['native_sha256'],recompiled_objects=len(records),
        source_text_changed=False,descriptor_authentication_enabled=True),indent=2),flush=True)


if __name__=='__main__':main()
