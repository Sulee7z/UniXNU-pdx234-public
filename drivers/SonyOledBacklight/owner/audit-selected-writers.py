#!/usr/bin/env python3
"""Bind display command-writer findings to actual066 link inputs and objects.

This is source/selection evidence, not a proof that firmware or unreviewed
retained Apple code can never touch an arbitrary physical address.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')

def sha(p):
    with Path(p).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def members(path):
    raw=path.read_bytes()
    if raw[:8]!=b'!<arch>\n':raise ValueError('Expected regular archive')
    at=8;strings=b'';result=[]
    while at<len(raw):
        header=raw[at:at+60]
        if len(header)!=60 or header[58:]!=b'`\n':raise ValueError('Bad ar header')
        name=header[:16].decode().strip();size=int(header[48:58]);data=raw[at+60:at+60+size]
        if len(data)!=size:raise ValueError('Short ar member')
        if name=='//':strings=data
        elif name not in ('/','/SYM64/'):
            if name.startswith('#1/'):
                n=int(name[3:]);name,data=data[:n].rstrip(b'\0').decode(),data[n:]
            elif name.startswith('/') and name[1:].isdigit():name=strings[int(name[1:]):].split(b'/\n',1)[0].decode()
            else:name=name.rstrip('/')
            if not name.startswith('__.SYMDEF'):result.append(dict(name=name,sha256=hashlib.sha256(data).hexdigest(),bytes=len(data)))
        at+=60+size+(size&1)
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    a.out.mkdir(parents=True,exist_ok=False);native=BASE/'native-sony-touch-066-002'
    if sha(native/'native.macho')!='80b2b18120eafde479aa2eaebd4017a677a67405b0ba0fe33e8d00ad6b6bc3dc':raise ValueError('Correct066 base differs')
    link=json.loads((native/'native-link.command.json').read_text());inputs=[]
    for i,value in enumerate(link):
        if value=='-filelist':inputs.extend(shlex.split(Path(link[i+1]).read_text()))
        elif value.startswith('-Wl,-force_load,'):inputs.append(value.split('-Wl,-force_load,',1)[1])
        elif value.endswith(('.o','.a')) and not value.startswith('-'):inputs.append(value)
    inputs=list(dict.fromkeys(inputs));archives=[];objects=[]
    for name in inputs:
        path=Path(name)
        if path.suffix=='.a':archives.append(dict(path=str(path),sha256=sha(path),members=members(path)))
        else:objects.append(dict(path=str(path),sha256=sha(path)))
    selected={r['name']:r for arc in archives for r in arc['members']}
    receipt_dirs=[native,BASE/'display-source-009/build/native-legacy-display',BASE/'gpu-source-006/build/adreno740',
                  BASE/'sony-touch-driver-014',BASE/'boot-screen-015',BASE/'native-block-abi-063-001/objects']
    sources=[]
    for folder in receipt_dirs:
        for receipt in folder.glob('*.dependencies.json'):
            row=json.loads(receipt.read_text());obj=Path(row['object']);source=Path(row['source'])
            matches=[r for r in selected.values() if r['sha256']==row['object_sha256']]
            if not matches or not source.exists():continue
            # Confirm source and every transitive file in the selected receipt.
            deps=row.get('dependencies',{});valid=all(sha(p)==d for p,d in deps.items())
            text=source.read_text(errors='replace')
            suspicious=[]
            for i,line in enumerate(text.splitlines(),1):
                if re.search(r'0x0?ae[0-9a-f]{5}|0x0?af[0-9a-f]{5}|\bDSI\b|\bdsi\b|DSI_|dsi_',line,re.I):
                    suspicious.append(dict(line=i,text=line.strip()[:220]))
            sources.append(dict(source=str(source),sha256=sha(source),receipt=str(receipt),receipt_sha256=sha(receipt),
                                object=obj.name,member_names=[r['name'] for r in matches],
                                dependencies_unchanged=valid,display_address_or_dsi_mentions=suspicious))
    # The late GOP object changes only constructor-section treatment. Bind its
    # archive member directly to retained actual late object and source receipt.
    display=next(r for r in archives if r['path'].endswith('libPhysicalDisplaySonyTouch.a'))
    late=BASE/'display-source-009/build/native-legacy-display/NativeLegacyDisplay.late.o'
    if sha(late)!=next(r['sha256'] for r in display['members'] if r['name']==late.name):raise ValueError('Selected GOP late object differs')
    source=BASE/'display-source-009/drivers/GopFramebuffer/NativeLegacyDisplay.cpp'
    text=source.read_text();gop_lines=[]
    for i,line in enumerate(text.splitlines(),1):
        if any(s in line for s in ('0xae','dpu-scanout','logical scanout','no panel power','applyStateRequest','void stop(', 'setPowerState(')):
            gop_lines.append(dict(line=i,text=line.strip()))
    symbols=subprocess.check_output(['/usr/lib/llvm-23/bin/llvm-nm','--defined-only',str(native/'native.macho')],text=True)
    dsi_symbols=[line for line in symbols.splitlines() if re.search(r'dsi|backlight|displaytiming|dpu_probe',line,re.I)]
    result=dict(native=str(native/'native.macho'),native_sha256=sha(native/'native.macho'),
                link_command_sha256=sha(native/'native-link.command.json'),
                input_objects=len(objects),archives=archives,objects=objects,selected_source_receipts=sources,
                selected_gop_late=dict(path=str(late),sha256=sha(late),source=str(source),source_sha256=sha(source),
                                       relevant_lines=gop_lines),
                defined_dsi_backlight_symbols=dsi_symbols,
                selected_known_sony_dsi_command_engine=False,source_complete_no_other_writer_proof=False,
                inactive_gop_direct_register_path='0xae01000 map through0xae90000; noDSI controller mapping; boot arg dpu-scanout0 skips it',
                native_pm_is_logical_not_supply_hold=True,
                remaining_unproven=['retained DPU hardwareautorefresh/MDP command requests',
                    'protected/firmware power or autonomous resource controllers',
                    'generic mapping primitives/retained Apple kext behavior are not disproved by symbol absence'],
                device_operations=False)
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('archives','objects','selected_source_receipts','selected_gop_late')},indent=2))

if __name__=='__main__':main()
