#!/usr/bin/env python3
"""Test and native-compile the inert owner core; do not bind physical access."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
def sha(p):
    with Path(p).open('rb') as s:return hashlib.file_digest(s,'sha256').hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',required=True,type=Path);a=p.parse_args()
    a.out.mkdir(parents=True,exist_ok=False)
    test=['clang++','-x','c++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-pthread',
          '-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(HERE),
          str(HERE/'owner-host.cpp'),str(HERE/'SonyDisplayCommandOwner.c'),'-o',str(a.out/'owner-host')]
    subprocess.run(test,check=True,timeout=90)
    run=subprocess.run([str(a.out/'owner-host')],capture_output=True,text=True,timeout=45)
    (a.out/'host.log').write_text(run.stdout+run.stderr)
    if run.returncode:raise RuntimeError(run.stdout+run.stderr)
    # Host fixture removes only AArch64 memory-barrier assembly. The native
    # object's actual DMB instructions are checked independently below.
    snapshot=HERE/'SonyDisplayCommandSnapshot.cpp';text=snapshot.read_text()
    barrier='__asm__ volatile("dmb oshld" ::: "memory");'
    if text.count(barrier)!=2:raise ValueError('Snapshot barrier anchors changed')
    host_source=a.out/'actual-snapshot.cpp';host_source.write_text(text.replace(barrier,'__atomic_thread_fence(__ATOMIC_SEQ_CST);'))
    snapshot_test=['clang++','-x','c++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror',
                   '-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(HERE),
                   str(HERE/'snapshot-host.cpp'),str(HERE/'SonyDisplayCommandOwner.c'),str(host_source),
                   '-o',str(a.out/'snapshot-host')]
    subprocess.run(snapshot_test,check=True,timeout=90)
    snapshot_run=subprocess.run([str(a.out/'snapshot-host')],capture_output=True,text=True,timeout=20)
    (a.out/'snapshot-host.log').write_text(snapshot_run.stdout+snapshot_run.stderr)
    if snapshot_run.returncode:raise RuntimeError(snapshot_run.stdout+snapshot_run.stderr)
    spec=importlib.util.spec_from_file_location('sony_owner_builder',ROOT/'ci/qemu/display/input/build-input.py')
    builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
    obj=a.out/'SonyDisplayCommandOwner.o'
    command=builder.compile_cpp(HERE/'SonyDisplayCommandOwner.c',obj,['-I',str(HERE)],
                                ['-Xclang','-fptrauth-block-descriptor-pointers'])
    mapped=a.out/'SonyDisplayCommandSnapshot.o'
    mapped_command=builder.compile_cpp(HERE/'SonyDisplayCommandSnapshot.cpp',mapped,['-I',str(HERE)],
                                      ['-Xclang','-fptrauth-block-descriptor-pointers'])
    archive=a.out/'libSonyDisplayCommandOwner.a';subprocess.run(['llvm-ar','rcs',str(archive),str(obj),str(mapped)],check=True)
    dis=subprocess.check_output([str(builder.LLVM/'llvm-objdump'),'--macho','--disassemble',str(obj)],text=True)
    if 'blraa' not in dis or 'ldaxr' not in dis and 'casal' not in dis:raise ValueError('Actual native auth/atomic operations missing')
    (a.out/'owner.disassembly.txt').write_text(dis)
    mapped_dis=subprocess.check_output([str(builder.LLVM/'llvm-objdump'),'--macho','--disassemble',str(mapped)],text=True)
    if 'dmb\toshld' not in mapped_dis:raise ValueError('Actual device read barrier missing')
    (a.out/'snapshot.disassembly.txt').write_text(mapped_dis)
    record=dict(passed=True,archive=str(archive),sha256=sha(archive),command=command,mapped_command=mapped_command,host_command=test,
                snapshot_host_command=snapshot_test,
                sources={str(p):sha(p) for p in [HERE/'SonyDisplayCommandOwner.c',HERE/'SonyDisplayCommandOwner.h',
                         HERE/'SonyDisplayCommandSnapshot.cpp',HERE/'SonyDisplayCommandSnapshot.h',HERE/'owner-host.cpp',HERE/'snapshot-host.cpp']},
                output=run.stdout+snapshot_run.stdout,physical_access_bound=False,presenter_hooks_installed=False,
                safe_to_enable_on_phone=False,device_operations=False,driver006_immutable=True)
    (a.out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({k:v for k,v in record.items() if k not in ('command','mapped_command','host_command','snapshot_host_command')},indent=2))
if __name__=='__main__':main()
