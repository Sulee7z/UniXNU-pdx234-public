#!/usr/bin/env python3
"""Compile immutable069 governor/recount deltas over exact067full002/068, no relink/device I/O."""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
HERE=ROOT/'ci/platform069/performance'
sys.path.insert(0,str(ROOT/'ci'));sys.path.insert(0,str(HERE))
from compile_dependencies import run_recorded,valid
import source069
from source069 import sha

S=Path('/mnt/f/UniXNU-Port-artifacts/platform069-20261118')
P=Path('/mnt/f/UniXNU-Port-artifacts/platform067-20261118')
B=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
BASE=P/'native-platform067-full-002'
NATIVE_SHA='734bb8fc84437371c34f4e2afc43ef4a0b4191d1bfbcd4b6cf1d52d5080c37dd'


def members(archive):
    import hashlib
    names=subprocess.check_output(['llvm-ar','t',str(archive)],text=True).splitlines()
    if len(names)!=len(set(names)):raise ValueError('Duplicate archive members')
    return {n:hashlib.sha256(subprocess.check_output(['llvm-ar','p',str(archive),n])).hexdigest() for n in names}


def command_for(dep,source,obj,include):
    old=dep['command'];command=[];i=0
    while i<len(old):
        v=old[i]
        if v in ('-MF','-MT','-MQ','-MJ'):i+=2;continue
        if v not in ('-MD','-MMD','-MP'):command.append(v)
        i+=1
    command[command.index(dep['source'])]=str(source);command[command.index('-o')+1]=str(obj)
    if '-fptrauth-function-pointer-type-discrimination' not in command:raise ValueError('Selected PAC flag missing')
    if '-fptrauth-block-descriptor-pointers' not in command:command+=['-Xclang','-fptrauth-block-descriptor-pointers']
    command+=['-I',str(include),'-mgeneral-regs-only','-Wno-unused-but-set-global','-Wno-missing-designated-field-initializers']
    return command


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--jobs',type=int,choices=range(1,9),default=3);a=p.parse_args()
    if sha(BASE/'native.macho')!=NATIVE_SHA:raise ValueError('Exact full068 native required')
    result=json.loads((BASE/'result.json').read_text())
    if len(result['block_descriptor_abi']['replacements'])!=66:raise ValueError('Inherited66 Blocks objects missing')
    for name,pin in [('UniXNU','563595abedfdfa413ad583b66b6176d82007e633'),('sheng','c8f92b208068eeaa4cd2b0f592671f04ee70076e')]:
        if subprocess.check_output(['git','-C',str(S/name),'rev-parse','HEAD'],text=True).strip()!=pin:raise ValueError('New snapshot pin changed')
    for name in ('CpuFreqProbe.cpp','GpuPowerProbe.cpp','ThermalProbe.cpp'):
        if (S/'sheng/package'/name).read_bytes()!=(P/'sheng/package'/name).read_bytes():raise ValueError('Unreviewed official governor delta')
    out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    for n in ('sources','objects','frozen'):(out/n).mkdir()
    for name in ('SonyGovernor069.h','SonyTouchBoost069.h'):
        shutil.copyfile(HERE/name,out/'sources'/name)
    for source in (HERE/'source069.py',HERE/'audit_inputs.py',Path(__file__).resolve()):
        shutil.copyfile(source,out/'frozen'/source.name)
    # Pin Sony hardware and derive CPU->L3 ceil-floor tables, never use tablet values.
    sys.path.insert(0,str(S/'UniXNU/scripts'))
    from unixnu.devicetree import read_fdt
    dt=S/'device-post068-readonly-001/live.dtb'
    if sha(dt)!='6ab06c177a7131338cd8cc374b304838738497bf0d709a48ed50f0282c03bb8a':raise ValueError('Saved068 Sony DT changed')
    def path(n):return path(n.parent).rstrip('/')+'/'+n.name if n.parent else '/'
    nodes={path(n):n for n in read_fdt(dt.read_bytes()).walk()}
    cpu=nodes['/soc/qcom,cpufreq-hw']
    if cpu.cells('reg')!=[0x17d91000,0x1000,0x17d92000,0x1000,0x17d93000,0x1000]:raise ValueError('EPSS domains differ')
    if nodes['/soc/qcom,dcvs/l3'].cells('reg')!=[0x17d90000,0x4000,0x17d90100,0xa0] or nodes['/soc/qcom,dcvs/l3/sp'].cells('qcom,shared-offset')!=[0x90]:
        raise ValueError('L3 resource/vote differs')
    ph=cpu.cells('phandle')[0]
    if [nodes[f'/cpus/cpu@{i*256:x}'].cells('qcom,freq-domain') for i in range(8)]!=[[ph,d] for d in (0,0,0,1,1,1,1,2)]:raise ValueError('CPU domain topology differs')
    tables=[];header='// Sony live-DT cpufreq-memfreq mappings; kHz pairs.\n'
    for name in ('silver','gold','prime'):
        table=nodes['/soc/qcom,memlat/l3/'+name].cells('qcom,cpufreq-memfreq-tbl')
        pairs=list(zip(table[::2],table[1::2]))
        if len(table)%2 or not pairs or any(a[0]>=b[0] or a[1]>b[1] for a,b in zip(pairs,pairs[1:])):raise ValueError('Invalid Sony L3 floor table')
        tables.append(pairs)
        header+='static const uint32_t sony069_l3_'+name+'[][2]={'+','.join('{%d,%d}'%v for v in pairs)+'};\n'
    header+='''static uint32_t sony069_l3_floor(unsigned d,uint32_t cpuKHz) {
    const uint32_t (*p)[2]=d==0?sony069_l3_silver:d==1?sony069_l3_gold:sony069_l3_prime;
    const unsigned n=d==0?sizeof(sony069_l3_silver)/sizeof(*p):d==1?sizeof(sony069_l3_gold)/sizeof(*p):sizeof(sony069_l3_prime)/sizeof(*p);
    unsigned i=0;while(i+1<n && p[i][0]<cpuKHz)++i;return p[i][1];
}
'''
    (out/'sources/SonyMemlatMap069.h').write_text(header)
    src_cpu=P/'performance-006/sources/CpuFreqProbe.cpp';src_gpu=P/'performance-006/sources/GpuPowerProbe.cpp'
    selected_recount=next(r for r in result['native_source_patches'] if r['native_source_patch']=='recount-sparse-cpu-kind-span')
    if sha(selected_recount['source'])!=selected_recount['source_sha256']:raise ValueError('Selected patched recount source changed')
    rec_text=source069.recount_selected(Path(selected_recount['source']).read_text())
    if rec_text!=source069.adapt_recount(Path(selected_recount['original_source']).read_text()):raise ValueError('Recount adapter composition differs')
    texts={'CpuFreqProbe':source069.cpu(src_cpu.read_text()),'GpuPowerProbe':source069.gpu(src_gpu.read_text()),'recount':rec_text}
    deps={n:json.loads((P/'performance-006/objects'/(n+'.o.dependencies.json')).read_text()) for n in ('CpuFreqProbe','GpuPowerProbe')}
    link=json.loads((BASE/'native-link.command.json').read_text());filelist=Path(link[link.index('-filelist')+1]).read_text().splitlines()
    selected_obj=next(p for p in filelist if Path(p).name=='recount.o')
    rec_dep=Path(selected_obj+'.dependencies.json')
    if not rec_dep.exists():rec_dep=Path(selected_obj+'.json')
    if not rec_dep.exists():raise ValueError('Missing actual selected recount compiler receipt: '+str(rec_dep))
    deps['recount']=json.loads(rec_dep.read_text())
    for n,dep in deps.items():
        if not valid(dep):raise ValueError('Selected dependency differs: '+n)
    def build_one(n):
        suffix='.c' if n=='recount' else '.cpp';source=out/'sources'/(n+suffix);source.write_text(texts[n]);obj=out/'objects'/(n+'.o')
        command=command_for(deps[n],source,obj,out/'sources')
        directory=Path(next(x for x in deps[n]['dependencies'] if Path(x).name=='meta_features.h')).parent
        env=dict(os.environ,CCC_OVERRIDE_OPTIONS='# +-Wno-unused-but-set-global +-Wno-missing-designated-field-initializers')
        with (out/(n+'.compile.log')).open('x') as log:
            done=run_recorded(command,cwd=directory,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=180)
        if done.returncode:raise RuntimeError((out/(n+'.compile.log')).read_text()[-8000:])
        return n,dict(source=str(source),source_sha256=sha(source),object=str(obj),object_sha256=sha(obj),
                      compile_receipt=str(obj)+'.dependencies.json',command=command,directory=str(directory))
    with ThreadPoolExecutor(max_workers=a.jobs) as pool:compiled=dict(pool.map(build_one,texts))
    archives=[]
    for key,n,filename in [('display_source','CpuFreqProbe','libDisplayPerformance069.a'),('gpu_source','GpuPowerProbe','libGpuPerformance069.a')]:
        old=Path(result[key]['archive']);new=out/filename;new.write_bytes(old.read_bytes());before=members(old)
        subprocess.run(['llvm-ar','r',str(new),compiled[n]['object']],check=True)
        after=members(new);changes=[p for p in before if before[p]!=after.get(p)]
        if set(changes)!={n+'.o'} or before.keys()!=after.keys():raise ValueError('Unexpected archive delta')
        archives.append(dict(old=str(old),new=str(new),old_sha256=sha(old),new_sha256=sha(new),
                             replaced_members=changes,added_members=[],unchanged_members={p:v for p,v in before.items() if p not in changes}))
    patch=dict(selected_recount);patch.update(source=compiled['recount']['source'],source_sha256=compiled['recount']['source_sha256'])
    inputs={str(p):sha(p) for p in [HERE/'source069.py',dt,*[Path(r['object']) for r in compiled.values()],
             *[Path(r['source']) for r in compiled.values()],*[out/'sources'/n for n in ('SonyGovernor069.h','SonyTouchBoost069.h','SonyMemlatMap069.h')],
             *[Path(r['new']) for r in archives]]}
    plan=dict(baseline_native_sha256=NATIVE_SHA,inputs=inputs,archive_replacements=[{k:r[k] for k in ('old','new','replaced_members','added_members')} for r in archives],
        object_replacements=[dict(old=selected_obj,new=compiled['recount']['object'])],source_patch_updates=[patch],
        compile_receipts=[r['compile_receipt'] for r in compiled.values()],
        source_qualifiers=[dict(module='platform069.performance.source069',sha256=sha(HERE/'source069.py'))],
        result_metadata={'platform069_performance':dict(build=str(out),source_sha256={n:r['source_sha256'] for n,r in compiled.items()},
            snapshot='c8f92b208068eeaa4cd2b0f592671f04ee70076e',official_governor_unchanged_since006=True,
            guarded_l3_dt_policy=True,per_cpu_recount_snapshot=True,gpu_sparse_load_span=3,gpu_rest_vote=1,
            init_single_owner=True,thread_local_touch_state=True,thermal_controller_added=False,whole_phone_sleep=False,device_verified=False)})
    (out/'integration-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    receipt=dict(baseline_native_sha256=NATIVE_SHA,baseline=str(BASE),compiled=compiled,archives=archives,selected_recount_object=selected_obj,
        l3_mapping=tables,live_dtb=str(dt),live_dtb_sha256=sha(dt),plan=str(out/'integration-plan.json'),
        plan_sha256=sha(out/'integration-plan.json'),frozen_headers={str(p):sha(p) for p in (out/'sources').glob('*.h')},
        target_compiled=True,host_tested=False,linked=False,device_operations=False)
    (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(dict(result=str(out/'result.json'),plan=receipt['plan'],archives=archives),indent=2))


if __name__=='__main__':main()
