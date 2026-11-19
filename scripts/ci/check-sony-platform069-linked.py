#!/usr/bin/env python3
"""Check actual069 archive selection,66 signed Blocks inputs, startup calls and final PAC."""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'ci'))
from block_descriptor_abi import validate_record
from platform069.integration import sha,validate
from platform069.overlays import validate_overlays


def require(condition,message):
    if not condition:raise ValueError(message)


def members(path):
    names=subprocess.check_output(['llvm-ar','t',str(path)],text=True).splitlines()
    require(bool(names) and len(names)==len(set(names)),'Duplicate or missing archive members')
    return {name:hashlib.sha256(subprocess.check_output(['llvm-ar','p',str(path),name])).hexdigest() for name in names}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('native','strict','requirements','out'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();n=json.loads((args.native/'result.json').read_text());s=json.loads((args.strict/'result.json').read_text())
    k=json.loads((args.strict/'kernel.json').read_text());required=json.loads(args.requirements.read_text())
    require(sha(args.native/'native.macho')==n['native_sha256']==s['native_sha256'] and
        sha(args.strict/'kernel.macho')==s['candidate_sha256']==k['candidate_sha256'] and
        not k['missing'] and not k['stubbed'] and not k['allow_missing'] and k['candidate_written'] and
        s['pac_enabled'] and not s['pac_metadata_adapters'] and not s['auth_instruction_patches'],'Strict physical PAC identities differ')
    validate(n['platform069']);validate_overlays(n,sha);validate_record(n['block_descriptor_abi'])
    for path,digest in required['inputs'].items():require(sha(path)==digest,'Linked requirement input changed: '+path)
    command=json.loads((args.native/'native-link.command.json').read_text())
    files=Path(command[command.index('-filelist')+1]).read_text().splitlines()
    for row in n['block_descriptor_abi']['replacements']:require(files.count(row['new_object'])==1,'Unselected signed Blocks input')
    require(len(n['block_descriptor_abi']['replacements'])==66,'Signed Blocks input closure reduced')
    deltas=[]
    for row in n['platform069']['archive_deltas']:
        require(command.count('-Wl,-force_load,'+row['new'])==1 and members(row['new'])==row['new_members'],
            'Actual selected069 archive differs')
        require(members(row['old'])==row['old_members'] and not row['old_members'].keys()-row['new_members'].keys(),
            'Baseline archive member lost')
        deltas.append(dict(old=row['old'],new=row['new'],replaced_members=row['replaced_members'],added_members=row['added_members']))
    args.out.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(args.strict/'XnuPrelink'));from kc_image import Image,scan
    raw=(args.strict/'kernel.macho').read_bytes();image=Image(raw);member=Image(raw,image.entries['com.apple.kernel'][1])
    names={name:address for address,values in member.symbols().items() for name in values}
    fixups=image.fixups();starts=member.function_starts();implementations={};call_cache={}
    def implementation(name):
        if name in implementations:return
        require(name in names,'Required069 function absent: '+name)
        at=names[name];index=bisect.bisect_right(starts,at)
        require(index<len(starts),'Unbounded069 function: '+name)
        size=starts[index]-at;body=member.read(at,size)
        require(size>0 and size%4==0,'Bad069 function boundary')
        stream='\n'.join(' '.join(f'0x{value:02x}' for value in body[i:i+4]) for i in range(0,size,4))
        done=subprocess.run(['llvm-mc-23','--disassemble','--triple=aarch64','--mattr=+v8.3a,+pauth,+lse'],input=stream,
            capture_output=True,text=True,check=True,timeout=20)
        lines=[line.strip() for line in done.stdout.splitlines() if line.strip() and line.strip()!='.text']
        require(len(lines)==size//4,'Incomplete069 instruction decode')
        destination=args.out/(name+'.asm');destination.write_text('\n'.join(f'{at+4*i:#x} {line}' for i,line in enumerate(lines))+'\n')
        implementations[name]=dict(address=hex(at),bytes=size,sha256=hashlib.sha256(body).hexdigest(),
            disassembly=str(destination),disassembly_sha256=sha(destination))
        call_cache[name]={target for _,target,_ in scan(body,at)[0]}
    require(bool(required.get('implementations')),'Explicit069 implementations required')
    for name in required['implementations']:implementation(name)
    calls=[]
    for caller,callee in required.get('direct_call_edges',[]):
        implementation(caller);implementation(callee)
        require(names[callee] in call_cache[caller],'Required actual069 direct call absent: '+caller+' -> '+callee)
        calls.append([caller,callee])
    require(bool(calls),'Actual startup/peripheral call-path qualification required')
    for text in required.get('present_markers',[]):require(text.encode() in raw,'Required069 marker absent: '+text)
    for text in required.get('absent_markers',[]):require(text.encode() not in raw,'Removed probe/old path survived: '+text)
    abi={};pac_tables={}
    for key,row in required.get('abi_files',{}).items():
        require(sha(row['path'])==row['sha256'],'ABI file changed: '+key)
        abi[key]=json.loads(Path(row['path']).read_text())
    tables=[]
    for key,name,field,count in [('touch','__ZTV14NativeHidInput','compiled_vtable',207),
                              ('buttons','__ZTV14SonyButtonsHid','compiled_vtable',207),
                              ('oled','__ZTV17SonyOledBacklight','compiled_table',168)]:
        require(key in abi,'Required final HID/OLED ABI missing: '+key)
        tables.append((key,name,abi[key][field],count))
    if 'radio' in abi:
        for group in ('classes','metaclasses'):
            for key,row in abi['radio'][group].items():
                tables.append(('radio:'+group+':'+key,row['symbol'],row['rows'],row['slots']))
    for key,name,rows,count in tables:
        require(name in names and len(rows)==count,'Final069 ABI table extent differs: '+key)
        table=names[name]+16;checked=[]
        for row in rows:
            diversity=int(row['diversity'],16) if isinstance(row['diversity'],str) else row['diversity']
            site=table+8*row['slot'];value=fixups.get(site)
            require(value is not None and value[1:]==(1,0,diversity,1),'Final069 PAC slot mismatch: '+key)
            if row.get('symbol') in names:require(value[0]==names[row['symbol']],'Wrong069 vtable target')
            checked.append(dict(slot=row['slot'],site=hex(site),target=hex(value[0]),diversity=diversity,
                file_offset=member.offset(site,8),raw_word=hex(struct.unpack('<Q',member.read(site,8))[0])))
        pac_tables[key]=dict(symbol=name,slots=count,rows=checked)
    radio_slots=sum(row['slots'] for key,row in pac_tables.items() if key.startswith('radio:'))
    require(radio_slots==928,'Complete radio method/MetaClass PAC tables required')
    # Use the same previously-qualified checker on these actual069 addresses,
    # not067 raw words or inherited startup booleans. It checks all five Qca
    # records, the active qsort/LOCKS/SYSCTL consumer and real BSD radio calls.
    startup=required.get('radio_startup_file')
    require(isinstance(startup,dict) and sha(startup['path'])==startup['sha256'],
        'Frozen Qca startup object provenance required')
    startup_rows=json.loads(Path(startup['path']).read_text())['records']
    require(len(startup_rows)==5,'Complete five Qca startup records required')
    import importlib.util
    helper_path=ROOT/'drivers/SonyWcn/qualification-final/final-closure.py'
    require(required['inputs'].get(str(helper_path))==sha(helper_path),'Qca startup checker must be hash-bound')
    spec=importlib.util.spec_from_file_location('sony069_qca_closure',helper_path)
    helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
    radio_startup={}
    for label,path in [('native',args.native/'native.macho'),('strict',args.strict/'kernel.macho')]:
        linked=helper.Linked(path,args.out,label)
        radio_startup[label]=linked.startup(startup_rows)
    record=dict(passed=True,native_sha256=n['native_sha256'],strict_sha256=s['candidate_sha256'],
        implementations=implementations,actual_call_edges=calls,actual_startup_branch_targets_verified=True,
        actual_signed_blocks_inputs_verified=66,archive_deltas=deltas,all_baseline_members_preserved=True,
        pac_tables=pac_tables,radio_pac_slots=radio_slots,abi=abi,
        radio_startup=radio_startup,qca_startup_records_per_image=5,
        requirements=str(args.requirements),requirements_sha256=sha(args.requirements),
        hardware_features_verified=False,device_operations=False)
    (args.out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({key:value for key,value in record.items() if key not in ('implementations','pac_tables','abi')},indent=2))


if __name__=='__main__':main()
