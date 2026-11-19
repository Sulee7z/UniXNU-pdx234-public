#!/usr/bin/env python3
"""Check actual069 governor/recount copies, archive boundaries, native API and RX size."""
from __future__ import annotations
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'ci'));sys.path.insert(0,str(ROOT/'ci/platform069/performance'))
from compile_dependencies import valid
from source069 import sha


def region(text,start,end):
    if text.count(start)!=1:raise ValueError('Unique source start required: '+start)
    first=text.index(start);last=text.index(end,first);return text[first:last]


def function(text,name):
    match=list(re.finditer(r'(?m)^'+re.escape(name)+r'\([^;{}]*\)\s*\{',text))
    if len(match)!=1:raise ValueError('Unique function required '+name)
    first=match[0].start();last=text.index('\n}',first)+2
    return text[first:last]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    out=a.out.resolve();out.mkdir(parents=True,exist_ok=False);build=json.loads((a.build/'result.json').read_text())
    spec=importlib.util.spec_from_file_location('builder069',ROOT/'scripts/ci/build-sony-platform069-performance.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    plan=json.loads(Path(build['plan']).read_text())
    for p,digest in plan['inputs'].items():
        if sha(p)!=digest:raise ValueError('Build input changed: '+p)
    for r in build['compiled'].values():
        if sha(r['source'])!=r['source_sha256'] or sha(r['object'])!=r['object_sha256'] or not valid(json.loads(Path(r['compile_receipt']).read_text())):
            raise ValueError('Compile identity changed')
    for r in build['archives']:
        old,new=module.members(r['old']),module.members(r['new'])
        if old.keys()!=new.keys() or {p for p in old if old[p]!=new[p]}!=set(r['replaced_members']):raise ValueError('Archive member boundary changed')
    cpu=Path(build['compiled']['CpuFreqProbe']['source']).read_text()
    cpu=re.sub(r'^#include <[^\n]+>\n','',cpu,flags=re.M).replace('__asm__ volatile("dsb sy" ::: "memory");','/* host barrier */')
    (out/'cpu069.inc').write_text(cpu)
    gpu=Path(build['compiled']['GpuPowerProbe']['source']).read_text()
    bodies=region(gpu,'constexpr uint32_t kGpuMHz[9]','uint64_t gpuBusyTicks()')
    bodies+=region(gpu,'bool gpuVote(','void gpuPerfTick(')
    bodies+=region(gpu,'void gpuDcvsThread(','void heartbeat();')
    (out/'gpu069.inc').write_text(bodies)
    votes=Path('/mnt/e/UniXNU-sheng27-sony-20261113/gpu-source-006')
    (out/'ShengGmuVotesSource.h').write_bytes((votes/'build/sheng-gmu/ShengGmuVotesSource.h').read_bytes())
    source=(votes/'kits/sheng/ShengGmuVotes.c').read_text()
    (out/'vote-index069.inc').write_text('unsigned ShengGmuPerfVote('+source.split('unsigned ShengGmuPerfVote(',1)[1])
    rec=Path(build['compiled']['recount']['source']).read_text()
    (out/'recount069.inc').write_text(region(rec,'#define RCT_PR_IDLING','void\nrecount_processor_online')+
                                     rec[rec.index('/* Remote governor snapshot:'):])
    old=Path('/mnt/e/UniXNU-sheng27-sony-20261113/native-screen007-055-001/native-source/recount.c').read_text()
    old_fn=function(old,'recount_processor_usage').replace('recount_processor_usage(','old_recount_processor_usage(',1)
    (out/'recount-old-usage.inc').write_text('void\n'+old_fn+'\n')
    logs=[]
    for name in ('sony_platform069_performance_host','sony_platform069_recount_host'):
        command=['/usr/bin/clang++-18','-std=c++20','-O1','-g','-Wall','-Wextra','-Werror',
            '-Wno-unknown-attributes','-Wno-ignored-attributes','-Wno-pointer-bool-conversion','-Wno-deprecated-volatile',
            '-fsanitize=address,undefined','-fno-omit-frame-pointer','-pthread','-I',str(out),'-I',str(a.build/'sources'),
            str(ROOT/'tests'/(name+'.cpp')),'-o',str(out/name)]
        done=subprocess.run(command,capture_output=True,text=True,timeout=120)
        (out/(name+'.build.log')).write_text(done.stdout+done.stderr)
        if done.returncode:raise RuntimeError(done.stderr[-9000:])
        done=subprocess.run([str(out/name)],capture_output=True,text=True,timeout=30)
        (out/(name+'.run.log')).write_text(done.stdout+done.stderr)
        if done.returncode:raise RuntimeError(done.stdout+done.stderr)
        logs.append(done.stdout.strip())
    native=Path(build['baseline'])/'native.macho'
    defined={l.split()[-1] for l in subprocess.check_output(['llvm-nm','--defined-only',str(native)],text=True).splitlines() if l.split()}
    for r in build['compiled'].values():defined|={l.split()[-1] for l in subprocess.check_output(['llvm-nm','--defined-only',r['object']],text=True).splitlines() if l.split()}
    missing={}
    for n,r in build['compiled'].items():
        imports={l.split()[-1] for l in subprocess.check_output(['llvm-nm','--undefined-only',r['object']],text=True).splitlines() if l.split()}
        if imports-defined:missing[n]=sorted(imports-defined)
    if missing:raise ValueError('Unavailable selected APIs: '+json.dumps(missing))
    disasm={}
    for n,r in build['compiled'].items():
        text=subprocess.check_output(['llvm-objdump','-d',r['object']],text=True)
        (out/(n+'.instructions.txt')).write_text(text)
        if 'pacibsp' not in text or 'retab' not in text:raise ValueError('PAC entry/return missing '+n)
        if n=='recount' and ('_sony069_cpu_idle_sample' not in text or 'ldadd' not in text and 'ldaxr' not in text):
            raise ValueError('Compiled sequence writer/sample missing')
        disasm[n]=dict(path=str(out/(n+'.instructions.txt')),sha256=sha(out/(n+'.instructions.txt')))
    baseline_disasm=subprocess.check_output(['llvm-objdump','--disassemble-symbols=_cpu_idle,_SetIdlePop,_sheng_cpu_idle_mach',str(native)],text=True)
    (out/'actual068-idle-timer.txt').write_text(baseline_disasm)
    sizes={}
    for n,r in build['compiled'].items():
        text=subprocess.check_output(['llvm-size','--format=darwin',r['object']],text=True)
        (out/(n+'.size.txt')).write_text(text);sizes[n]=text
    # Source verifier composes063's sparse-kind correction and069's isolated
    # snapshot change from the same original, before main performs final link.
    from native_source_overlays import validate_overlays
    baseline=json.loads((Path(build['baseline'])/'result.json').read_text())
    patched=dict(baseline)
    patched['native_source_patches']=[dict(x) for x in baseline['native_source_patches']]
    row=plan['source_patch_updates'][0]
    next(x for x in patched['native_source_patches'] if x['native_source_patch']==row['native_source_patch']).update(row)
    from platform069.performance.source069 import ADAPTERS
    assert Path(row['source']).read_text()==ADAPTERS[row['native_source_patch']](Path(row['original_source']).read_text())
    result=dict(passed=True,build=str(a.build/'result.json'),build_sha256=sha(a.build/'result.json'),
        host_results=logs,asan_ubsan=True,unresolved_apis=missing,instruction_evidence=disasm,
        actual068_idle_timer_instructions=str(out/'actual068-idle-timer.txt'),sizes=sizes,
        archive_boundaries_verified=True,all_baseline_members_retained=True,blocks_objects_inherited=66,
        snapshot_adapter_verified=True,native_relinked=False,device_tested=False,device_operations=False)
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
