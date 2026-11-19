#!/usr/bin/env python3
"""Extend frozen size001 using only optimization changes to frozen radio002.

Never modifies size001, radio002, earlier helpers or receipts. BluetoothProbe
is the first additional compilation. The original C commands for qbt_core and
qbt_transport are used only if the total saving still falls short of16KiB.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import sys

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113/sony-wcn-067-002')
FIRST=Path('/mnt/f/UniXNU-Port-artifacts/platform067-20261118/radio-board-size-001')


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args();out=args.out.resolve()
    out.mkdir(parents=True,exist_ok=False)
    first=json.loads((FIRST/'result.json').read_text())
    frozen=BASE/'libSonyWcn.a'
    if sha(frozen)!='6cf62fdf57c7ffa34985857e37f4e57ebdcafe7f8f3ba482d8033da50bfdf566':
        raise ValueError('Frozen radio002 changed')
    if sha(FIRST/'libSonyWcn.a')!='956f44f00cd47569111951e78db4bc203544117d7edb081b7a29e4a17ef4a054':
        raise ValueError('Frozen size001 archive changed')
    helpers={str(HERE/'size-board.py'):sha(HERE/'size-board.py'),str(HERE/'qualify.py'):sha(HERE/'qualify.py')}
    helper=module('sony_size_original',HERE/'size-board.py')
    sys.path.insert(0,str(ROOT/'ci/platform067/arm64e'))
    from audit import ar_members
    sys.path.insert(0,str(ROOT/'ci'))
    from compile_dependencies import valid
    archive=out/'libSonyWcn.a';shutil.copyfile(FIRST/'libSonyWcn.a',archive)
    previous={n:h for n,h,_ in ar_members(FIRST/'libSonyWcn.a')}
    original={n:h for n,h,_ in ar_members(frozen)}
    replacements=list(first['replacements']);receipts=list(first['compile_receipts'])
    saved=first['text_bytes_saved'];additional=[]
    for name in ('BluetoothProbe','qbt_core','qbt_transport'):
        if saved>=16384:break
        obj,record=helper.run(name,out)
        old=BASE/'objects'/(name+'.o')
        saving=helper.text_bytes(old)-helper.text_bytes(obj)
        helper.execute(['llvm-ar','r',archive,obj])
        row=dict(member=obj.name,old_object=str(old),old_sha256=sha(old),new_object=str(obj),new_sha256=sha(obj),
                 old_text_bytes=helper.text_bytes(old),new_text_bytes=helper.text_bytes(obj),text_bytes_saved=saving)
        replacements.append(row);additional.append(row);saved+=saving
        receipts.append(str(obj.with_name(obj.name+'.dependencies.json')))
    current={n:h for n,h,_ in ar_members(archive)}
    changed={r['member'] for r in replacements}
    added={r['member'] for r in additional}
    if set(current)!=set(original) or any(current[n]!=h for n,h in original.items() if n not in changed):
        raise ValueError('Unselected original member changed')
    if any(current[n]!=h for n,h in previous.items() if n not in added):
        raise ValueError('Unselected size001 member changed')
    old_symbols={line.split()[-1] for line in helper.execute(['llvm-nm','-g','--defined-only',frozen]).splitlines() if len(line.split())==3}
    new_symbols={line.split()[-1] for line in helper.execute(['llvm-nm','-g','--defined-only',archive]).splitlines() if len(line.split())==3}
    if old_symbols!=new_symbols or len(new_symbols)!=216:
        raise ValueError('Public board ABI definitions changed')
    all_inputs={str(frozen):sha(frozen),str(FIRST/'libSonyWcn.a'):sha(FIRST/'libSonyWcn.a'),
                str(FIRST/'result.json'):sha(FIRST/'result.json'),**helpers}
    for path in receipts:
        record=json.loads(Path(path).read_text())
        if not valid(record) or sha(record['object'])!=record['object_sha256']:
            raise ValueError('Compiled source/header closure changed')
        command=record['command']
        if command.count('-Oz')!=1 or '-fptrauth-function-pointer-type-discrimination' not in command:
            raise ValueError('Optimization/PAC flags differ')
        i=command.index('-fptrauth-block-descriptor-pointers')
        if command[i-1]!='-Xclang':raise ValueError('Blocks PAC flags differ')
        all_inputs[path]=sha(path)
    # Audit the unchanged WifiNet member without rerunning the original-kernel
    # audit. Every original -O2 slot schema must match the retained -Oz object.
    abi=module('sony_final_abi',HERE/'qualify.py')
    old_net=abi.Object(BASE/'objects/WifiNet.late.o')
    size_net=abi.Object(Path(next(r['new_object'] for r in replacements if r['member']=='WifiNet.late.o')))
    tables=[]
    for symbol in old_net.names:
        if not symbol.startswith('__ZTV') or old_net.names[symbol]['type']==1:continue
        a,b=old_net.table(symbol),size_net.table(symbol)
        expected=[{k:r[k] for k in ('slot','symbol','auth','key','diversity','address_diversity')} for r in a['rows']]
        actual=[{k:r[k] for k in ('slot','symbol','auth','key','diversity','address_diversity')} for r in b['rows']]
        if expected!=actual:raise ValueError('WifiNet PAC table differs: '+symbol)
        tables.append(dict(symbol=symbol,slots=b['slots'],all_schemas_and_signatures_retained=True))
    if sum(t['slots'] for t in tables)!=928:
        raise ValueError('Expected5class+5metaclass/928 slots')
    # qbt startup records remain byte-identical in the common case. If the
    # transport was needed, compare all five startup fields and PAC schemas.
    old_qbt=abi.Object(BASE/'objects/qbt_transport.o')
    transport=next((r['new_object'] for r in additional if r['member']=='qbt_transport.o'),str(BASE/'objects/qbt_transport.o'))
    new_qbt=abi.Object(Path(transport));init=[]
    for s in old_qbt.symbols:
        if not s['name'].startswith('___startup_') or not s['section']:continue
        sec=old_qbt.sections[s['section']-1]
        if (sec['segment'],sec['name'])!=('__BOOTDATA','__init_entry_set'):continue
        n=new_qbt.names[s['name']];at,nat=s['va'],n['va']
        if old_qbt.read(at,8)!=new_qbt.read(nat,8) or not n['desc']&0x20:
            raise ValueError('Qca startup order/no-dead-strip changed')
        for offset in (8,16):
            a,b=old_qbt.relocations[at+offset],new_qbt.relocations[nat+offset]
            if any(a[k]!=b[k] for k in ('symbol','type','length','word')):
                raise ValueError('Qca startup callback/PAC/argument changed')
        init.append(s['name'])
    if len(init)!=5:raise ValueError('Qca startup closure incomplete')
    machine=[]
    for row in additional:
        path=Path(row['new_object'])
        text=helper.execute(['llvm-objdump-23','--macho','--disassemble','--no-symbolic-operands',path])
        output=out/(path.stem+'.asm');output.write_text(text)
        counts={name:len(re.findall(r'\b'+name+r'\b',text)) for name in ('pacibsp','retab','pacia','pacda','blraa','braa','autia')}
        if row['member']=='BluetoothProbe.o' and not (counts['pacibsp'] and counts['blraa'] and counts['pacia']):
            raise ValueError('Actual Bluetooth callback/return PAC instructions absent')
        machine.append(dict(object=str(path),disassembly=str(output),sha256=sha(output),instructions=counts))
    if any(sha(p)!=h for p,h in helpers.items()):raise ValueError('Read-only helper changed during operation')
    result=dict(passed=True,archive=str(archive),sha256=sha(archive),frozen_archive=str(frozen),frozen_sha256=sha(frozen),
                previous_archive=str(FIRST/'libSonyWcn.a'),previous_archive_sha256=first['sha256'],
                optimization='-Oz',same_source_and_headers=True,pac_flags_unchanged=True,
                replacements=replacements,additional_replacements=additional,compile_receipts=receipts,
                text_bytes_saved=saved,additional_text_bytes_saved=saved-first['text_bytes_saved'],
                required_saving=16384,raw_saving_meets_request=saved>=16384,final_page_layout_qualified=False,
                other_members_byte_identical=True,original_other_members=14-len(changed),size001_other_members=14-len(added),
                defined_symbols_retained=216,defined_symbols=sorted(new_symbols),
                wifi_vtables=tables,wifi_pac_slots_retained=928,qca_startup_records_retained=init,
                actual_machine_pac=machine,inputs=all_inputs,frozen_inputs_modified=False,device_operations=False)
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('defined_symbols','inputs','wifi_vtables','actual_machine_pac')},indent=2))


if __name__=='__main__':main()
