#!/usr/bin/env python3
"""Exercise the new2GiB seed with the actual linked NativeRamBlock sparse helper."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def sha(p):
    with Path(p).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seed',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    seed=json.loads(args.seed.read_text())
    if not seed['passed'] or sha(seed['seed'])!=seed['seed_sha256'] or seed['logical_bytes']!=2*1024**3:
        raise ValueError('Verified2GiB seed required')
    native=json.loads((BASE/'native-sony-touch-066-002/result.json').read_text())
    archive=BASE/'native-screen007-055-001/archives/libShengUfs.a'
    if sha(archive)!=native['archive_sha256']['libShengUfs.a']:
        raise ValueError('Actually linked storage archive differs')
    object_path=BASE/'native-screen007-055-001/objects/storage/NativeRamBlock.late.o'
    actual=subprocess.check_output(['llvm-ar','p',str(archive),'NativeRamBlock.late.o'])
    if hashlib.sha256(actual).hexdigest()!=sha(object_path):raise ValueError('Selected storage archive member differs')
    plan=json.loads((BASE/'native-screen007-055-001/plan.json').read_text())
    job=next(job for job in plan['jobs'] if Path(job['source']).name=='NativeRamBlock.cpp')
    source=Path(job['source'])
    if sha(source)!=job['source_sha256'] or 'if(logical>0x80000000ULL)' not in source.read_text():
        raise ValueError('Actual volatile capacity branch differs')
    args.out.mkdir(parents=True,exist_ok=False)
    exe=args.out/'volatile-seed'
    command=['clang++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror',
             '-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(source.parent),
             str(ROOT/'tests/sony_volatile_seed.cpp'),'-o',str(exe)]
    subprocess.run(command,check=True,timeout=30)
    done=subprocess.run([str(exe),seed['seed']],capture_output=True,text=True,timeout=15)
    (args.out/'run.log').write_text(done.stdout+done.stderr)
    if done.returncode:raise RuntimeError(done.stdout+done.stderr)
    result=dict(passed=True,command=command,output=done.stdout,seed_receipt_sha256=sha(args.seed),
        seed_sha256=seed['seed_sha256'],logical_bytes=seed['logical_bytes'],
        actually_linked_storage_archive_sha256=sha(archive),actually_linked_ramblock_object_sha256=sha(object_path),
        sources={str(p):sha(p) for p in [source,source.parent/'SparseDisk.h',ROOT/'tests/sony_volatile_seed.cpp']},
        sanitizers=['address','undefined'],persistence_required=False,device_operations=False,hardware_verified=False)
    (args.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(done.stdout,end='')


if __name__=='__main__':main()
