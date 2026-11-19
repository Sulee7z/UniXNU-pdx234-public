#!/usr/bin/env python3
"""Package057: reconcile manual xnu default with UniXNU confirmation policy."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tomllib

ROOT=Path(__file__).resolve().parents[2]
BASELINE='a92ba5411705b1c033a27d8068255abe60170d9aef57b05d79688d18f511aaf2'

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ['release','work','out']:p.add_argument('--'+key,type=Path,required=True)
    a=p.parse_args();helpers=load('native_helpers','package-d27-reviewed-native.py')
    transport=load('metal_refresh','package-d27-metal-refresh.py');helpers.require_space()
    if a.work.exists() or a.out.exists():p.error('Use new output directories')
    a.work.mkdir(parents=True);v=helpers.readback(a.release,a.work/'baseline-readback.log');record=v['j']
    if record['sha256']!=BASELINE:raise ValueError('Require exact056')
    original=v['get']('EFI/UniXNU/unixnu.toml').decode();before=tomllib.loads(original)
    entry=next(e for e in before['entry'] if e['id']=='xnu')
    if before['boot']['timeout']!=-1 or before['boot']['default']!='xnu':raise ValueError('Unexpected manual menu policy')
    line='confirm = '+json.dumps(entry['confirm'])+'\n'
    if original.count(line)!=1:raise ValueError('Ambiguous confirmation')
    text=original.replace(line,'').replace('PAC-ABI-056','PAC-ABI-057').replace('build-tag=PDX056','build-tag=PDX057')
    after=tomllib.loads(text);expected=copy.deepcopy(before)
    e=next(e for e in expected['entry'] if e['id']=='xnu');e.pop('confirm');e['args']=e['args'].replace('PDX056','PDX057')
    expected['ui']['title']=expected['ui']['title'].replace('056','057')
    if after!=expected:raise ValueError('Unexpected configuration delta')
    config=a.work/'unixnu.toml';config.write_text(text);os.utime(config,(315532800,315532800))
    fat=a.work/'payload.fat';fat.write_bytes(v['fat']);old=helpers.fat_inventory(fat)
    subprocess.run(['mcopy','-o','-m','-i',str(fat),str(config),'::/EFI/UniXNU/unixnu.toml'],check=True)
    new=helpers.fat_inventory(fat)
    if old.keys()!=new.keys() or {k for k in old if old[k]!=new[k]}!={'EFI/UniXNU/unixnu.toml'}:raise ValueError('Non-config FAT delta')
    image,blob,commands=transport.pack_transport(v,fat.read_bytes(),a.work,helpers)
    a.out.mkdir(parents=True);target=a.out/'boot-pdx234-pac-abi-057.img';target.write_bytes(image)
    record.update(image=str(target),sha256=helpers.sha(image),bytes=len(image),label='PAC-ABI-057',
        source_image_sha256=BASELINE,kernel_args=e['args'],menu_title=after['ui']['title'],menu_default='xnu',
        screen_build_tag='PDX057',menu_confirmation_removed=True,
        arguments_removed=['build-tag=PDX056'],arguments_added=['build-tag=PDX057'],
        payload_sha256=helpers.sha(fat.read_bytes()),bundle_sha256=helpers.sha(blob),
        correction='Remove conflicting confirmation from manual default xnu entry; retain timeout=-1',
        hardware_boot_verified=False,desktop_verified=False)
    helpers.write_json(a.out/'release.json',record)
    (a.out/'SHA256SUMS').write_text(record['sha256']+'  '+target.name+'\n')
    helpers.readback(a.out,a.work/'final-readback.log')
    helpers.write_json(a.work/'report.json',dict(passed=True,changed_files=['EFI/UniXNU/unixnu.toml'],commands=commands,hardware_verified=False))
    print(json.dumps(dict(image=str(target),sha256=record['sha256']),indent=2))

if __name__=='__main__':main()
