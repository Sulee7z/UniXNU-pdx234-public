#!/usr/bin/env python3
"""Add the shared SM8550 CPU topology and PSCI node to the retained Sony ADT."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess

DEVICE=Path(__file__).resolve().parents[2]


def serialize(tree):
    props=tree['properties'];kids=tree['children']
    data=bytearray(struct.pack('<II',len(props),len(kids)))
    for key,value in props.items():
        name=key.encode('ascii')
        if len(name)>31:raise ValueError('ADT property name too long')
        data+=struct.pack('<32sI',name,len(value))+value+bytes((-len(value))%4)
    for child in kids.values():data+=serialize(child)
    return bytes(data)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline',type=Path,required=True)
    p.add_argument('--sony-dtb',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    spec=importlib.util.spec_from_file_location('adt',DEVICE/'scripts/apple-device-tree.py')
    codec=importlib.util.module_from_spec(spec);spec.loader.exec_module(codec)
    raw=a.baseline.read_bytes();tree=codec.parse(raw);before=copy.deepcopy(tree)
    if len(tree['children']['cpus']['children'])!=1 or 'psci' in tree['children']:
        raise ValueError('Require the retained single-core baseline')
    boot=tree['children']['cpus']['children']['cpu0']
    if struct.unpack('<I',boot['properties']['reg'])[0]!=0:raise ValueError('Unexpected boot affinity')
    compatibles=['arm,cortex-a510']*3+['arm,cortex-a715']*2+['arm,cortex-a710']*2+['arm,cortex-x3']
    nodes={}
    for index,compatible in enumerate(compatibles):
        affinity=index*0x100
        text=subprocess.check_output(['fdtget','-t','x',str(a.sony_dtb),f'/cpus/cpu@{affinity:x}','reg'],text=True)
        if [int(v,16) for v in text.split()]!=[0,affinity]:raise ValueError('Sony affinity differs')
        node=copy.deepcopy(boot);props=node['properties']
        props.update(name=f'cpu{index}\0'.encode(),reg=struct.pack('<I',affinity),
                     state=b'running\0' if index==0 else b'waiting\0',
                     compatible=(compatible+'\0').encode())
        props['cluster-type']=struct.pack('<I',ord('E' if index<3 else 'P'))
        nodes[f'cpu{index}']=node
    tree['children']['cpus']['children']=nodes
    tree['children']['psci']={'properties':{'name':b'psci\0','compatible':b'arm,psci-1.0\0','method':b'smc\0'},'children':{}}
    encoded=serialize(tree)
    if codec.parse(encoded)!=tree:raise ValueError('ADT roundtrip failed')
    restored=copy.deepcopy(tree);restored['children']['cpus']=before['children']['cpus'];del restored['children']['psci']
    if restored!=before:raise ValueError('Non-CPU ADT changed')
    a.out.mkdir(parents=True,exist_ok=False);(a.out/'kernel.macho.adt').write_bytes(encoded)
    result=dict(baseline_sha256=hashlib.sha256(raw).hexdigest(),adt_sha256=hashlib.sha256(encoded).hexdigest(),
                sony_dtb_sha256=hashlib.sha256(a.sony_dtb.read_bytes()).hexdigest(),cpu_count=8,affinities=[i*0x100 for i in range(8)],
                cluster_types=['E']*3+['P']*5,psci='smc',topology_source='shared pinned sm8550.dtsi and sheng dts/sheng.dts',
                non_cpu_adt_unchanged=True,hardware_secondary_verified=False,device_operations=False)
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
