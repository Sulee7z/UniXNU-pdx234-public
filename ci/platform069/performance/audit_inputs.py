#!/usr/bin/env python3
"""Read-only heat-path input audit for the measured068 kernel."""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

S=Path('/mnt/f/UniXNU-Port-artifacts/platform069-20261118')
P=Path('/mnt/f/UniXNU-Port-artifacts/platform067-20261118')
B=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
TREE=B/'sources/UniXNU/out/pdx234/ios-27.0.1-24A446-iphone14/pdx234_sheng27_bulk/tree'
CAP=S/'device-post068-readonly-001'


def sha(p):
    with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    a.out.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(S/'UniXNU/scripts'))
    from unixnu.devicetree import read_fdt
    def path(n):return path(n.parent).rstrip('/')+'/'+n.name if n.parent else '/'
    nodes={path(n):n for n in read_fdt((CAP/'live.dtb').read_bytes()).walk()}
    def encode(n):
        props={}
        for k,v in n.properties.items():
            if not v:props[k]=True
            elif any(v) and v[-1:]==b'\0' and all(c==0 or 32<=c<127 for c in v):props[k]=n.strings(k)
            elif len(v)%4==0:props[k]=n.cells(k)
            else:props[k]=v.hex()
        return props
    hardware={q:encode(n) for q,n in nodes.items() if q.startswith(('/soc/qcom,dcvs','/soc/qcom,memlat','/soc/qcom,llcc-l3-vote'))
              or ('tsens' in n.name) or q.startswith('/cpus')}
    (a.out/'hardware.json').write_text(json.dumps(hardware,indent=2)+'\n')
    sources={}
    for name in ('CpuFreqProbe.cpp','GpuPowerProbe.cpp','ThermalProbe.cpp','ThermalProbe.h'):
        old=P/'sheng/package'/name;new=S/'sheng/package'/name
        sources[name]=dict(old_sha256=sha(old),new_sha256=sha(new),identical=old.read_bytes()==new.read_bytes())
    logroot=CAP/'decoded/PDX068-3fbe8890'
    logs={n:(logroot/n).read_text(errors='replace') for n in ('header.txt','msgbuf.txt','slots.txt','latest.txt')}
    perf=[];cpu=[];profiles=[]
    for filename,text in logs.items():
        for ln,line in enumerate(text.splitlines(),1):
            if '[sony-perf]' in line:perf.append(dict(file=filename,line=ln,text=line))
            if '[sony-cpufreq-state]' in line:cpu.append(dict(file=filename,line=ln,text=line))
            if re.search(r'\[(?:kcpu|cpu profile|cpu sample|profile|task cpu|process cpu|thermal)',line,re.I):profiles.append(dict(file=filename,line=ln,text=line))
    categories=Counter(re.findall(r'\[([^]\n]{1,50})\]',logs['slots.txt']))
    (a.out/'actual068.json').write_text(json.dumps(dict(log_hashes={n:sha(logroot/n) for n in logs},
        perf=perf,cpufreq=cpu,pid_profiles=profiles,slot_categories=categories,
        notes=['gov triples are last10s level-change/meanMHz/mean busiest-corebusy%, NOT instantaneous utilization',
               'instantaneous domain_state/vote are sampled later than the gov summary',
               'DPU timing=counter-enable=0 invalidates panel-Hz interpretation',
               'PID CPU-profile samples are absent if only log-round source duration appears']),indent=2)+'\n')
    result=dict(source_comparison=sources,native=sha(P/'native-platform067-full-002/native.macho'),
                live_dtb_sha256=sha(CAP/'live.dtb'),perf_samples=len(perf),pid_profile_rows=len(profiles),
                slot_categories=categories,hardware_file=str(a.out/'hardware.json'),log_audit=str(a.out/'actual068.json'))
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
