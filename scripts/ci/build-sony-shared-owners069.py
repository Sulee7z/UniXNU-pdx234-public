#!/usr/bin/env python3
"""Route actual touch/ArmCpu/startup owners to the single069 resource provider."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
NATIVE=Path('/mnt/f/UniXNU-Port-artifacts/platform067-20261118/native-platform067-full-002')
sys.path.insert(0,str(ROOT/'ci'))
from compile_dependencies import run_recorded,valid
from block_descriptor_abi import FLAGS,enabled
from platform069.integration import BASELINE_SHA,sha


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True);a=parser.parse_args()
    if sha(NATIVE/'native.macho')!=BASELINE_SHA:raise ValueError('Exact068 native required')
    a.out.mkdir(parents=True,exist_ok=False);out=a.out.resolve();(out/'objects').mkdir();(out/'source').mkdir()
    before=json.loads((NATIVE/'result.json').read_text());touch=before['sony_touch'];touch_dir=Path(touch['archive']).parent
    adapter=load('sony069_owner_adapter',ROOT/'drivers/SonyWcn/platform069/adapt069.py')
    display_adapter=load('sony069_display_lifecycle',ROOT/'drivers/SonyOledBacklight/platform069/lifecycle069.py')
    def compile_one(label,source,receipt,transform,filename):
        record=json.loads(receipt.read_text())
        selected_object=record.get('object',record.get('output'))
        if not selected_object or not valid(record) or sha(selected_object)!=record.get('object_sha256',record.get('sha256')):raise ValueError('Selected owner compile receipt changed')
        old=Path(record['source']);text=old.read_text()
        if source is not None and source.read_text()!=text:raise ValueError('Owner source differs from actual selected object')
        target=out/'source'/old.name;target.write_text(transform(text));obj=out/'objects'/filename
        cmd=[];i=0
        while i<len(record['command']):
            v=record['command'][i]
            if v in ('-MF','-MT','-MQ'):i+=2;continue
            if v not in ('-MD','-MMD'):cmd.append(v)
            i+=1
        cmd[cmd.index(str(old))]=str(target);cmd[cmd.index('-o')+1]=str(obj)
        cmd+=['-iquote',str(old.parent),'-Wno-missing-designated-field-initializers','-Wno-unused-but-set-global']
        if not enabled(cmd):cmd+=FLAGS
        directory=record.get('directory',record.get('cwd'))
        if not directory:directory=str(Path(next(p for p in record['dependencies'] if Path(p).name=='meta_features.h')).parent)
        with (out/(label+'.log')).open('x') as log:r=run_recorded(cmd,cwd=directory,stdout=log,stderr=subprocess.STDOUT,timeout=120)
        if r.returncode:raise RuntimeError((out/(label+'.log')).read_text()[-10000:])
        return dict(source=str(target),source_sha256=sha(target),object=str(obj),object_sha256=sha(obj),
            original_source=str(old),original_source_sha256=sha(old),dependency_receipt=str(obj)+'.dependencies.json')
    arm=compile_one('ArmCpu',None,BASE/'native-screen007-055-001/objects/armcpu/ArmCpu.o.json',adapter.armcpu,'ArmCpu.o')
    touch_row=compile_one('SonyTouch',ROOT/'drivers/SonyLxsTouch/SonyTouch.cpp',touch_dir/'objects/SonyTouch.o.dependencies.json',adapter.touch,'SonyTouch.o')
    def startup(text):
        declaration='extern "C" int native_sony_radio_platform069_init(void);\n'
        anchor='    native_sony_touch_start();\n'
        if text.count(anchor)!=1:raise ValueError('Actual late startup anchor differs')
        text=declaration+text.replace(anchor,
            '    const int resourceError069=native_sony_radio_platform069_init();\n'
            '    if(resourceError069)IOLog("[sony069-resources] init error=%d; radio/display preparation incomplete\\n",resourceError069);\n'+anchor)
        return display_adapter.startup(text)
    late=compile_one('LegacyDisplayProbe',None,NATIVE/'LegacyDisplayProbe.o.dependencies.json',startup,'LegacyDisplayProbe.o')
    gop=compile_one('NativeLegacyDisplay',None,BASE/'display-source-009/build/native-legacy-display/NativeLegacyDisplay.o.dependencies.json',display_adapter.gop,'NativeLegacyDisplay.o')
    def late_object(row,name):
        raw=Path(row['object']);target=out/'objects'/name
        subprocess.run(['llvm-objcopy-23','--remove-section=__DATA,__mod_init_func',
            '--globalize-symbol=__GLOBAL__sub_I_'+Path(row['source']).name,str(raw),str(target)],check=True)
        row.update(compiled_object=str(raw),compiled_object_sha256=sha(raw),object=str(target),object_sha256=sha(target))
    late_object(gop,'NativeLegacyDisplay.late.o')
    def ufs(text):
        text=adapter.ufs(text)
        declaration='''extern "C" int sony_shared_config_lock(void);
extern "C" void sony_shared_config_unlock(void);
class SonyUfsConfigGuard069 {
public:
  SonyUfsConfigGuard069(){if(sony_shared_config_lock())panic("NATIVE_UFS shared SMMU owner unavailable");}
  ~SonyUfsConfigGuard069(){sony_shared_config_unlock();}
};
'''
        insertion=text.index('static void smmuBypassStream (')
        text=text[:insertion]+declaration+text[insertion:]
        anchor='                              uint64_t dma, uint64_t bytes)\n{\n'
        if text.count(anchor)!=1:raise ValueError('Actual UFS SMMU owner function differs')
        return text.replace(anchor,anchor+'  SonyUfsConfigGuard069 sharedOwner;\n')
    ufs_row=compile_one('NativeUfs',None,BASE/'native-screen007-055-001/objects/storage/NativeUfs.o.json',ufs,'NativeUfs.o')
    late_object(ufs_row,'NativeUfs.late.o')
    archive=out/'libSonyD27Touch.a';shutil.copyfile(touch['archive'],archive)
    subprocess.run(['llvm-ar','r',str(archive),touch_row['object']],check=True)
    updated=copy.deepcopy(touch);old_source=str(ROOT/'drivers/SonyLxsTouch/SonyTouch.cpp')
    if updated['sources'].get(old_source)!=touch_row['original_source_sha256']:raise ValueError('Original touch source identity differs')
    updated['sources'].pop(old_source);updated['sources'][touch_row['source']]=touch_row['source_sha256']
    old_obj=str(touch_dir/'objects/SonyTouch.o')
    if old_obj not in updated['objects']:raise ValueError('Selected touch object missing')
    updated['objects'].pop(old_obj);updated['objects'][touch_row['object']]=touch_row['object_sha256']
    updated.update(archive=str(archive),sha256=sha(archive),shared_resource_owner069=True,
        owner_compile_receipt=touch_row['dependency_receipt'],runtime_verified=False)
    # ABI inputs retain their actual006/015 contents at the new archive path.
    for name in ('hid-abi.json','edge-abi.json'):
        if (touch_dir/name).exists():shutil.copyfile(touch_dir/name,out/name)
    (out/'touch-result.json').write_text(json.dumps(updated,indent=2)+'\n')
    record=dict(passed=True,baseline_native_sha256=BASELINE_SHA,builds=dict(armcpu=arm,touch=touch_row,startup=late,gop=gop,ufs=ufs_row),
        touch_receipt=str(out/'touch-result.json'),touch_receipt_sha256=sha(out/'touch-result.json'),
        member_replacements=[dict(archive=before['display_source']['archive'],object=late['object']),
                             dict(archive=before['display_source']['archive'],object=gop['object']),
                             dict(archive=NATIVE/'libShengUfs.a',object=ufs_row['object']),
                             dict(archive=BASE/'native-screen007-055-001/archives/libArmCpu.a',object=arm['object'])],
        touch_archive_replacement=dict(old=touch['archive'],new=str(archive),replaced_members=['SonyTouch.o'],added_members=[]),
        compile_receipts=[r['dependency_receipt'] for r in [arm,touch_row,late,gop,ufs_row]],device_operations=False)
    record['member_replacements']=[{k:str(v) for k,v in row.items()} for row in record['member_replacements']]
    (out/'result.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
