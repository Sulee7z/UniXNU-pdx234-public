#!/usr/bin/env python3
"""Relink reviewed069 archive/object deltas; never reconstruct068 from an older base."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
BASELINE=Path('/mnt/f/UniXNU-Port-artifacts/platform067-20261118/native-platform067-full-002')
sys.path.insert(0,str(ROOT/'ci'))
from platform069.integration import BASELINE_SHA,sha,validate
from block_descriptor_abi import validate_record
from platform069.overlays import validate_overlays


def members(path):
    names=subprocess.check_output(['llvm-ar','t',str(path)],text=True).splitlines()
    if not names or len(names)!=len(set(names)):raise ValueError('Missing or duplicate archive members: '+str(path))
    return {name:hashlib.sha256(subprocess.check_output(['llvm-ar','p',str(path),name])).hexdigest() for name in names}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan',required=True,type=Path)
    parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args()
    before=json.loads((BASELINE/'result.json').read_text());plan=json.loads(args.plan.read_text())
    if sha(BASELINE/'native.macho')!=BASELINE_SHA or before['native_sha256']!=BASELINE_SHA:
        raise ValueError('Exact067full002/068 native required')
    if plan.get('baseline_native_sha256')!=BASELINE_SHA:raise ValueError('Wrong069 plan baseline')
    if args.out.exists():raise ValueError('Preserve all previous build directories')
    validate_overlays(before,sha)
    for path,digest in plan['inputs'].items():
        if sha(path)!=digest:raise ValueError('Reviewed069 input differs: '+path)
    command=json.loads((BASELINE/'native-link.command.json').read_text())
    files=Path(command[command.index('-filelist')+1]).read_text().splitlines()
    if len(files)!=len(set(files)):raise ValueError('Duplicate baseline direct link inputs')
    original_files=list(files);result=copy.deepcopy(before)
    args.out.mkdir(parents=True,exist_ok=False);out=args.out.resolve()
    archive_changes={};archive_proofs=[]
    def replace_archive(old,new,expected):
        if old in archive_changes:raise ValueError('Overlapping archive replacement: '+old)
        token='-Wl,-force_load,'+old
        if command.count(token)!=1:raise ValueError('Unique selected baseline archive required: '+old)
        old_members=members(old);new_members=members(new)
        if old_members.keys()-new_members.keys():raise ValueError('Cannot remove baseline driver archive members')
        changed={name for name in old_members if old_members[name]!=new_members[name]}
        added=set(new_members)-set(old_members)
        if changed!=set(expected['replaced_members']) or added!=set(expected.get('added_members',[])):
            raise ValueError('Archive delta differs from the explicit069 plan: '+old)
        command[command.index(token)]='-Wl,-force_load,'+str(new);archive_changes[old]=str(new)
        archive_proofs.append(dict(old=old,new=str(new),old_sha256=sha(old),new_sha256=sha(new),
            replaced_members=sorted(changed),added_members=sorted(added),old_members=old_members,new_members=new_members))
    # Compose nonoverlapping member deltas into a private archive copy.
    grouped={}
    for row in plan.get('member_replacements',[]):grouped.setdefault(row['archive'],[]).append(row)
    for old,rows in grouped.items():
        target=out/Path(old).name
        if target.exists():raise ValueError('Colliding archive basename: '+str(target))
        objects=[Path(row['object']) for row in rows]
        if len({obj.name for obj in objects})!=len(objects):raise ValueError('Duplicate replacement member')
        if any(str(obj) not in plan['inputs'] for obj in objects):raise ValueError('Member lacks a reviewed object hash')
        old_members=members(old)
        if any(obj.name not in old_members for obj in objects):raise ValueError('Replacement member absent from baseline')
        target.write_bytes(Path(old).read_bytes())
        subprocess.run(['llvm-ar','r',str(target),*map(str,objects)],check=True,timeout=30)
        replace_archive(old,target,dict(replaced_members=[obj.name for obj in objects]))
    for row in plan.get('archive_replacements',[]):
        if plan['inputs'].get(row['new'])!=sha(row['new']):raise ValueError('Replacement archive lacks reviewed identity')
        replace_archive(row['old'],Path(row['new']),row)
    for path in plan.get('added_archives',[]):
        if path not in plan['inputs'] or '-Wl,-force_load,'+path in command:
            raise ValueError('Duplicate or unreviewed additional archive')
        members(path);command.append('-Wl,-force_load,'+path)
    for row in plan.get('object_replacements',[]):
        if files.count(row['old'])!=1 or row['new'] in files or row['new'] not in plan['inputs']:
            raise ValueError('Unique, hash-bound direct object transition required')
        files[files.index(row['old'])]=row['new']
    for path in plan.get('added_objects',[]):
        if path in files or path not in plan['inputs']:raise ValueError('Duplicate or unreviewed additional object')
        files.append(path)
    # Metadata follows actual selection; inherited063 receipts cannot claim
    # old producers after a069 source/object replacement.
    for update in plan.get('block_replacement_updates',[]):
        if plan['inputs'].get(update['path'])!=update['sha256'] or sha(update['path'])!=update['sha256']:
            raise ValueError('Reviewed Blocks update differs')
        replacement=json.loads(Path(update['path']).read_text());index=replacement['replacement_index']
        old=result['block_descriptor_abi']['replacements'][index];new=replacement['replacement_row']
        if (old['new_object']!=replacement['replace_selected_object'] or
                new['old_object']!=old['old_object'] or new['old_sha256']!=old['old_sha256'] or
                files.count(new['new_object'])!=1 or
                not any(row['old']==old['new_object'] and row['new']==new['new_object'] for row in plan.get('object_replacements',[]))):
            raise ValueError('Blocks transition does not describe the actual069 linked input')
        result['block_descriptor_abi']['replacements'][index]=new
    for update in plan.get('source_patch_updates',[]):
        if plan['inputs'].get(update['source'])!=update['source_sha256']:raise ValueError('Source overlay lacks explicit input hash')
        selected=[row for row in result['native_source_patches'] if row['native_source_patch']==update['native_source_patch']]
        if len(selected)>1:raise ValueError('Ambiguous inherited source overlay')
        if selected:selected[0].update(update)
        else:
            if sha(update['original_source'])!=update['original_source_sha256']:raise ValueError('New overlay original differs')
            result['native_source_patches'].append(dict(update))
    for row in result['block_descriptor_abi']['replacements']:
        if files.count(row['new_object'])!=1:raise ValueError('Signed Blocks input is not actually selected')
    validate_record(result['block_descriptor_abi'])
    filelist=out/'link.filelist';filelist.write_text('\n'.join(files)+'\n')
    command[command.index('-filelist')+1]=str(filelist);command[command.index('-o')+1]=str(out/'native.macho')
    for key in ('display_source','gpu_source','boot_screen'):
        old=result[key]['archive']
        if old in archive_changes:result[key].update(archive=archive_changes[old],sha256=sha(archive_changes[old]))
    for old,new in archive_changes.items():
        if Path(old).name in result.get('archive_sha256',{}):result['archive_sha256'][Path(old).name]=sha(new)
    if plan.get('touch_receipt'):
        path=Path(plan['touch_receipt'])
        if plan['inputs'].get(str(path))!=sha(path):raise ValueError('Touch replacement lacks reviewed receipt')
        replacement=json.loads(path.read_text())
        if (archive_changes.get(before['sony_touch']['archive'])!=replacement['archive'] or
                sha(replacement['archive'])!=replacement['sha256'] or
                not replacement.get('shared_resource_owner069') or replacement.get('virtual_backend_included')):
            raise ValueError('Touch shared-owner selection differs')
        for key in ('hid_abi_sha256','geni_firmware','chain_regressions','temporary_probes_removed','sw82907_vendor_boot_policy'):
            if replacement[key]!=before['sony_touch'][key]:raise ValueError('Touch protocol/ABI changed during owner routing')
        for key in ('sources','objects'):
            for path,digest in replacement[key].items():
                if sha(path)!=digest:raise ValueError('Touch selected source/object changed')
        result['sony_touch']=replacement
    protected={'native','native_sha256','block_descriptor_abi','sony_touch','platform067','platform069',
               'native_source_patches','pac_flag','pac_authentication_retained','auth_instruction_patches',
               'virtual_backends_selected','physical_058_derived','physical_066_derived'}
    for key,value in plan.get('result_metadata',{}).items():
        if key in protected or not key.startswith('platform069_'):raise ValueError('Protected069 metadata override: '+key)
        result[key]=value
    inputs=dict(plan['inputs'])
    for path in (args.plan,BASELINE/'result.json',BASELINE/'native.macho',BASELINE/'native-link.command.json',filelist):inputs[str(path)]=sha(path)
    for value in command:
        if value.startswith('-Wl,-force_load,'):
            path=value.removeprefix('-Wl,-force_load,');inputs[path]=sha(path)
    for path in files:inputs[path]=sha(path)
    integration=dict(baseline_native_sha256=BASELINE_SHA,baseline_result=str(BASELINE/'result.json'),inputs=inputs,
        compile_receipts=plan.get('compile_receipts',[]),source_qualifiers=plan.get('source_qualifiers',[]),
        archive_deltas=archive_proofs,object_replacements=plan.get('object_replacements',[]),
        added_archives=plan.get('added_archives',[]),added_objects=plan.get('added_objects',[]),
        startup_calls=plan.get('startup_calls',before['platform067']['startup_calls']),
        baseline_direct_object_count=len(original_files),direct_object_count=len(files),
        inherited_block_descriptor_objects=66,all_baseline_archive_members_retained=True,
        virtual_backends_selected=False,device_operations=False)
    result['platform069']=integration;result['physical_068_derived']=True
    validate(integration);validate_overlays(result,sha)
    (out/'native-link.command.json').write_text(json.dumps(command,indent=2)+'\n')
    env=dict(os.environ,CROSS_CLANG='/root/unixnu-build/pdx234-pac-toolchain/llvm/bin/clang-24',
        DARWIN_TRIPLE='arm64e-apple-ios27.0',CROSS_EXTRA_FLAGS=result['pac_flag'],TMPDIR=str(out))
    env['PATH']=str(Path(command[0]).parent)+':'+env['PATH']
    with (out/'link.log').open('x') as log:done=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=300)
    if done.returncode:raise RuntimeError((out/'link.log').read_text()[-12000:])
    result.update(native=str(out/'native.macho'),native_sha256=sha(out/'native.macho'),runtime_qualified=False,device_operations=False)
    if plan.get('block_replacement_updates'):
        result['block_descriptor_abi'].update(native_sha256=result['native_sha256'],source_text_changed=True,
            source_updates_069=plan['block_replacement_updates'])
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(native=result['native'],sha256=result['native_sha256'],archive_deltas=archive_proofs,
        actual_signed_blocks_inputs=66,device_operations=False),indent=2))


if __name__=='__main__':main()
