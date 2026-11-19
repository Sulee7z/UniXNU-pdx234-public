#!/usr/bin/env python3
"""Rebuild every pinned Ath12k production object at Oz, changing no source or ABI."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
sys.path.insert(0,str(ROOT/'ci'))
from compile_dependencies import run_recorded,valid
from platform067.integration import sha
from block_descriptor_abi import enabled


def clean(command):
    result=[];i=0
    while i<len(command):
        if command[i] in ('-MF','-MT','-MQ','-MJ'):i+=2;continue
        if command[i] in ('-MD','-MMD','-MP'):i+=1;continue
        result.append(command[i]);i+=1
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build',type=Path,default=BASE/'sony-wcn-067-002')
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--jobs',type=int,default=6,choices=range(1,13))
    args=parser.parse_args()
    before=json.loads((args.build/'result.json').read_text());core=before['wifi_core']
    if sha(core['archive'])!=core['sha256'] or len(core['objects'])!=125:
        raise ValueError('Exact125-object official production core required')
    args.out.mkdir(parents=True,exist_ok=False);out=args.out.resolve();(out/'objects').mkdir()
    mapping=args.build/'wifi-core/rename.txt'
    if not mapping.is_file():raise ValueError('Pinned original core namespace map required')
    jobs=[]
    for path,digest in core['objects'].items():
        if sha(path)!=digest:raise ValueError('Original production object changed')
        dep_path=Path(path+'.dependencies.json');dep=json.loads(dep_path.read_text())
        if not valid(dep) or dep['object_sha256']!=digest or not enabled(dep['command']):
            raise ValueError('Original complete compile dependencies/Blocks ABI required')
        command=clean(dep['command']);optimization=[i for i,value in enumerate(command) if value.startswith('-O')]
        if len(optimization)!=1 or command[optimization[0]]!='-O2':raise ValueError('Expectedone O2 optimization flag')
        command[optimization[0]]='-Oz';obj=out/'objects'/Path(path).name;command[command.index('-o')+1]=str(obj)
        directory=dep.get('cwd')
        if not directory or not Path(directory).is_dir():raise ValueError('Recorded core compilation cwd required')
        if sha(mapping)!=dep['namespace_map_sha256']:raise ValueError('Original namespace map differs')
        jobs.append(dict(old_object=path,old_sha256=digest,source=dep['source'],source_sha256=sha(dep['source']),
            object=str(obj),directory=directory,command=command,old_receipt=str(dep_path),old_receipt_sha256=sha(dep_path)))
    def compile_one(row):
        obj=Path(row['object'])
        with obj.with_suffix('.log').open('x') as stream:
            done=run_recorded(row['command'],cwd=row['directory'],stdout=stream,stderr=subprocess.STDOUT,timeout=180)
        if done.returncode:raise RuntimeError(obj.with_suffix('.log').read_text()[-8000:])
        receipt=obj.with_name(obj.name+'.dependencies.json');dep=json.loads(receipt.read_text())
        if not valid(dep) or not enabled(dep['command']):raise ValueError('Recompiled dependencies invalid')
        raw_sha=sha(obj)
        subprocess.run(['llvm-objcopy-23','--redefine-syms='+str(mapping),str(obj)],check=True,timeout=30)
        dep.update(raw_object_sha256=raw_sha,object_sha256=sha(obj),namespace_map=str(mapping),
                   namespace_map_sha256=sha(mapping))
        receipt.write_text(json.dumps(dep,indent=2)+'\n')
        row.update(object_sha256=sha(obj),dependency_receipt=str(receipt),dependency_sha256=sha(receipt))
        return row
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:rows=list(pool.map(compile_one,jobs))
    archive=out/'libSonyAth12kCore.a'
    subprocess.run(['llvm-ar','rcs',str(archive),*[row['object'] for row in rows]],check=True)
    names=subprocess.check_output(['llvm-ar','t',str(archive)],text=True).splitlines()
    if len(names)!=125 or set(names)!={Path(path).name for path in core['objects']}:
        raise ValueError('All original production members must remain')
    result=dict(passed=True,archive=str(archive),sha256=sha(archive),original_archive=core['archive'],
        original_sha256=core['sha256'],optimization_before='-O2',optimization_after='-Oz',
        object_count=125,objects={row['object']:row['object_sha256'] for row in rows},replacements=rows,
        compile_receipts=[row['dependency_receipt'] for row in rows],source_text_changed=False,
        source_and_header_bytes_retained=True,pac_and_blocks_abi_retained=True,
        firmware_or_driver_removed=False,hardware_verified=False,device_operations=False)
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('objects','replacements','compile_receipts')},indent=2))


if __name__=='__main__':main()
