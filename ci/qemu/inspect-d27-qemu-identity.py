#!/usr/bin/env python3
"""Locate the preserved current D27 ADT and report only portable identity fields."""
import hashlib
import importlib.util
import json
from pathlib import Path

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
EXPECTED='86e1c9093e1faa3ac0842f462f089e4bc2e8e828a93bd936039879215114435a'

def main():
    spec=importlib.util.spec_from_file_location('codec','/mnt/g/UniXNU-Port/sources/UniXNU-qemu-20261110/scripts/make-qemu-adt.py')
    codec=importlib.util.module_from_spec(spec);spec.loader.exec_module(codec)
    matches=[]
    for path in BASE.glob('payload-*/kernel.macho.adt'):
        digest=hashlib.sha256(path.read_bytes()).hexdigest()
        if digest==EXPECTED:matches.append(path)
    if not matches:raise ValueError('Current058 ADT not retained in staging')
    path=matches[0];tree,end=codec.parse(path.read_bytes())
    if end!=path.stat().st_size:raise ValueError('ADT parse incomplete')
    result=dict(path=str(path),sha256=EXPECTED,matches=[str(p) for p in matches],root_properties={k:v.hex() for k,v in tree[1] if k in ('model','target-type','compatible')})
    for node_name in ('product','buttons','chosen'):
        node=codec.child(tree,node_name)
        allowed=('unique-chip-id','serial-number','target-type','chip-id','board-id','security-domain','certificate-production-status','effective-production-status-ap','certificate-security-mode','effective-security-mode-sep')
        result[node_name]={k:dict(hex=v.hex(),text=v.rstrip(b'\0').decode('utf-8','replace')) for k,v in node[1] if node_name!='chosen' or k in allowed}
    seed=path.with_name('platform-seed')
    if seed.exists():result['platform_seed']=dict(path=str(seed),bytes=seed.stat().st_size,sha256=hashlib.sha256(seed.read_bytes()).hexdigest())
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
