#!/usr/bin/env python3
"""Build/test a pure Sony120 preflight archive; no live hardware backend or startup hook."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
SNAP=Path('/mnt/f/UniXNU-Port-artifacts/platform067-20261118')
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
sys.path.insert(0,str(ROOT/'ci'))
from compile_dependencies import run_recorded,valid
from qualify_modes import decode_commands


def sha(path):
    with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--qualification',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False);out=a.out.resolve()
    info=json.loads((a.qualification/'modes.json').read_text())
    if sha(a.qualification/'modes.json')!='4d83aa3b7ea4df232340e617e2822728090ee537e73eeaa93d259960ff903fca':
        raise ValueError('Exact qualified mode-property/packet receipt required')
    if info['sha256']!='9dc4b4512490d77ef0e6230815ceb731937bcd65b74397e718970f2ab91c37ef':raise ValueError('Wrong live DT')
    modes=info['modes'];rows=[]
    def scalar(mode,key):
        value=mode[key]
        if not isinstance(value,list) or len(value)!=1 or not isinstance(value[0],int):raise ValueError('Expected scalar '+key)
        return value[0]
    for i in range(4):
        m=modes['timing@'+str(i)]
        keys=('panel-width','panel-height','panel-framerate','panel-clockrate')
        values=[i]+[scalar(m,'qcom,mdss-dsi-'+k) for k in keys]+[scalar(m,'qcom,mdss-mdp-transfer-time-us')]
        values += [scalar(m,'qcom,mdss-dsi-'+k) for k in ('h-front-porch','h-pulse-width','h-back-porch','v-front-porch','v-pulse-width','v-back-porch')]
        values += [scalar(m,'qcom,mdss-dsc-'+k) for k in ('slice-width','slice-height','bit-per-component','bit-per-pixel')]
        values += [2,scalar(m,'qcom,mdss-dsc-encoders'),scalar(m,'qcom,mdss-dsc-slice-per-pkt'),int(m['qcom,mdss-dsc-block-prediction-enable'])]
        phy=list(bytes.fromhex(m['qcom,mdss-dsi-panel-phy-timings']['hex']))
        rows.append('{'+','.join(map(str,values))+',{'+','.join(map(str,phy))+'}}')
    header='// Generated only from pinned post066 somc,1_panel properties.\n'
    header+='static const SonyPanelModeFacts kSonyPanelModes[4]={\n'+',\n'.join(rows)+'\n};\n'
    for i,name in ((2,'kSonySwitch120Low'),(3,'kSonySwitch120Native')):
        raw=bytes.fromhex(modes['timing@'+str(i)]['qcom,mdss-dsi-timing-switch-command']['hex'])
        if len(raw)!=72 or len(decode_commands(raw))!=7:raise ValueError('Malformed pinned panel commands')
        header+='static const uint8_t '+name+'[]={'+','.join('0x%02x'%v for v in raw)+'};\n'
    generated=out/'SonyPanelModes.generated.h';generated.write_text(header)
    cxx='/usr/bin/clang++-18'
    command=[cxx,'-std=c++20','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
             '-fno-omit-frame-pointer','-I',str(out),'-I',str(HERE),str(HERE/'SonyPanel120.cpp'),
             str(HERE/'test_panel120.cpp'),'-o',str(out/'host')]
    with (out/'host-build.log').open('x') as f:r=subprocess.run(command,stdout=f,stderr=subprocess.STDOUT,timeout=120)
    if r.returncode:raise RuntimeError((out/'host-build.log').read_text())
    r=subprocess.run([str(out/'host')],capture_output=True,text=True,timeout=30)
    (out/'host-run.log').write_text(r.stdout+r.stderr)
    if r.returncode:raise RuntimeError((out/'host-run.log').read_text())
    # Decoder negatives and all four real command sets; no semantic payload edits.
    decoder_tests=0
    for key,m in modes.items():
        for prop,value in m.items():
            if not isinstance(value,dict) or 'packets' not in value:continue
            raw=bytes.fromhex(value['hex']);packets=decode_commands(raw)
            assert packets==value['packets'];decoder_tests+=1
    for raw in (b'\x39',b'\x39\x01\x00\x00\x00\x00\x05\x60'):
        try:decode_commands(raw)
        except ValueError:decoder_tests+=1
        else:raise ValueError('Truncated command accepted')
    dep_path=BASE/'display-source-009/build/native-legacy-display/CpuFreqProbe.o.dependencies.json'
    dep=json.loads(dep_path.read_text())
    if not valid(dep):raise ValueError('Selected target compile recipe dependencies changed')
    old=dep['command'];target=[];i=0
    while i<len(old):
        v=old[i]
        if v in ('-MF','-MT','-MQ','-MJ'):i+=2;continue
        if v not in ('-MD','-MMD','-MP'):target.append(v)
        i+=1
    obj=out/'SonyPanel120.o'
    target[target.index(dep['source'])]=str(HERE/'SonyPanel120.cpp');target[target.index('-o')+1]=str(obj)
    target+=['-I',str(out),'-I',str(HERE),'-Xclang','-fptrauth-block-descriptor-pointers','-mgeneral-regs-only']
    directory=Path(next(p for p in dep['dependencies'] if Path(p).name=='meta_features.h')).parent
    env=dict(os.environ,CCC_OVERRIDE_OPTIONS='# +-Wno-missing-designated-field-initializers +-Wno-unused-but-set-global')
    with (out/'target-build.log').open('x') as f:
        done=run_recorded(target,cwd=directory,env=env,stdout=f,stderr=subprocess.STDOUT,timeout=180)
    if done.returncode:raise RuntimeError((out/'target-build.log').read_text())
    undefined=subprocess.check_output(['llvm-nm','--undefined-only',str(obj)],text=True)
    (out/'undefined-symbols.txt').write_text(undefined)
    if undefined.strip():raise ValueError('Pure planner unexpectedly imports runtime/backend symbols')
    archive=out/'libSonyPanel120Preflight.a';subprocess.run(['llvm-ar','rcs',str(archive),str(obj)],check=True)
    result=dict(passed=True,qualification=str(a.qualification/'modes.json'),qualification_sha256=sha(a.qualification/'modes.json'),
                generated_header=str(generated),generated_header_sha256=sha(generated),
                host_result=r.stdout.strip(),host_command=command,decoder_checks=decoder_tests,asan_ubsan=True,
                target_object=str(obj),target_object_sha256=sha(obj),target_command=target,
                target_dependencies=str(obj)+'.dependencies.json',archive=str(archive),archive_sha256=sha(archive),
                source_hashes={str(p):sha(p) for p in (HERE/'SonyPanel120.cpp',HERE/'SonyPanel120.h',HERE/'test_panel120.cpp',HERE/'build_check.py')},
                mmio_access=False,backend_imports=[],startup_hook=False,mode_switch_executable=False,
                linked_into_native=False,device_tested=False,panel120_proven=False,device_operations=False)
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('host_command','target_command','source_hashes')},indent=2))


if __name__=='__main__':main()
