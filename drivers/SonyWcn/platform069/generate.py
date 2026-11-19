#!/usr/bin/env python3
"""Generate Sony069 resources from actual captured FDT and firmware manifests."""
from __future__ import annotations
import argparse, hashlib, importlib.util, json
from pathlib import Path, PureWindowsPath
import re, shutil, struct, sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def wsl(path):
    if re.match(r'^[A-Za-z]:',path):
        p=PureWindowsPath(path);return Path('/mnt/'+p.drive[0].lower(),*p.parts[1:])
    return Path(path)
def fdt_module():
    spec=importlib.util.spec_from_file_location('sony_frozen_fdt',HERE.parent/'board_inputs.py')
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
def firmware(manifest):
    data=json.loads(manifest.read_text());result={}
    for row in data['files']:
        p=wsl(row['local'])
        if not row['phone_hash_matches'] or p.stat().st_size!=row['bytes'] or sha(p)!=row['sha256']:
            raise ValueError('Sony phone/host firmware identity mismatch: '+str(p))
        result[row['android_path']]={**row,'path':str(p)}
    return result
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--capture',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False);out=a.out.resolve();m=fdt_module();f=m.Fdt(a.capture/'live.dtb')
    board=m.resolve(a.capture/'live.dtb')
    resources=[]
    for node,props in f.nodes.items():
        if 'qcom,resource-name' not in props or b'qcom,rpmh-vrm-regulator' not in props.get('compatible',b''):continue
        name=f.strings(node,'qcom,resource-name')[0]
        children=[n for n in f.nodes if n.rsplit('/',1)[0]==node and 'regulator-min-microvolt' in f.nodes[n]]
        if not children:continue
        minimum=min(f.cells(n,'regulator-min-microvolt')[0] for n in children)
        maximum=max(f.cells(n,'regulator-max-microvolt')[0] for n in children)
        resources.append(dict(name=name,min_uv=minimum,max_uv=maximum,node=node,children=children))
    rsc=f.unique('/apps_rsc@17a00000');drv=rsc+'/drv@2';channel=drv+'/channel@0'
    cfg=f.cells(channel,'qcom,tcs-config');offset=0;mask=0
    for i in range(0,len(cfg),2):
        typ,count=cfg[i:i+2]
        if typ==2:mask=((1<<count)-1)<<offset
        if typ!=4:offset+=count
    if not mask or f.cells(drv,'qcom,tcs-offset')!=[0xd00]:raise ValueError('Sony RSC layout changed')
    qmp=f.handles[0x65];qmp_controller=f.handles[f.cells(qmp,'qcom,qmp')[0]]
    apps_smmu=f.unique('/apps-smmu@15000000')
    if (f.strings(apps_smmu,'compatible')[0]!='qcom,qsmmu-v500' or
        f.cells(apps_smmu,'reg')[:2]!=[0x15000000,0x100000] or
        f.cells(apps_smmu,'#global-interrupts')!=[1]):
        raise ValueError('Sony Apps SMMU identity/geometry/global IRQ differs')
    smmu_irqs=f.cells(apps_smmu,'interrupts')
    triples=[smmu_irqs[i:i+3] for i in range(0,len(smmu_irqs),3)]
    if (len(triples)<3 or triples[:2]!=[[0,0x41,4],[0,0x61,4]] or
        any(len(row)!=3 or row[0]!=0 or row[2]!=4 or row[1]+32>=1020 for row in triples) or
        len({row[1] for row in triples})!=len(triples)):
        raise ValueError('Sony Apps SMMU global/context fault IRQ order differs')
    context_irqs=[cell+32 for _,cell,_ in triples[1:]]
    board.update(resources=resources,rsc_active_mask=mask,rsc_intid=f.cells(rsc,'interrupts')[7]+32,
                 qmp_node=qmp,qmp_controller=qmp_controller,qmp_properties={k:v.hex() for k,v in f.nodes[qmp_controller].items()})
    prefix='/* SPDX-License-Identifier: BSD-2-Clause-Patent */\n#pragma once\n#include <stdint.h>\n'
    header=prefix+'struct SonyResourceSpec {const char *name;uint32_t min_uv,max_uv;};\n'
    header+='static const SonyResourceSpec kSonyResources[]={\n'+''.join('{"%s",%d,%d},\n'%(r['name'],r['min_uv'],r['max_uv']) for r in resources)+'};\n'
    header+=f'#define SONY_RSC_ACTIVE_MASK {mask}u\n#define SONY_RSC_INTID {board["rsc_intid"]}u\n'
    header+='#define SONY_APPS_SMMU_REG_BASE 0x15000000u\n#define SONY_APPS_SMMU_REG_BYTES 0x100000u\n'
    header+='static constexpr uint16_t kSonyAppsSmmuContextIrqs[]={'+','.join(map(str,context_irqs))+'};\n'
    board.update(apps_smmu=dict(node=apps_smmu,compatible=f.strings(apps_smmu,'compatible'),
        reg=f.cells(apps_smmu,'reg'),global_interrupts=f.cells(apps_smmu,'#global-interrupts'),
        global_irq=triples[0],context_bank_fault_intids=context_irqs))
    qmpreg=f.cells(qmp_controller,'reg');header+='static constexpr uint32_t kSonyQmpReg[]={'+','.join(hex(x) for x in qmpreg)+'};\n'
    for prop in ('qcom,pmu_vreg_map','qcom,pdc_init_table'):
        n=f.unique('/qcom,cnss-qca-converged/chip_cfg@1');value=f.strings(n,prop)
        if prop.endswith('pdc_init_table'):header+='static const char *const kSonyPdcMessages[]={'+','.join(json.dumps(x) for x in value)+'};\n'
    (out/'SonyResources.generated.h').write_text(header)
    (out/'board-inputs.json').write_text(json.dumps(board,indent=2)+'\n')
    wifi=firmware(a.capture/'radio-firmware/manifest.json');bt=firmware(a.capture/'bluetooth-firmware/manifest.json')
    files=[];root=out/'runtime/firmware';wd=root/'ath12k/WCN7850/hw2.0';bd=root/'qca';wd.mkdir(parents=True);bd.mkdir()
    for android,dest in [('/vendor/firmware_mnt/image/kiwi/amss20.bin',wd/'amss.bin'),
                         ('/vendor/firmware_mnt/image/kiwi/phy_ucode20.elf',wd/'m3.bin'),
                         ('/vendor/firmware/kiwi/bdwlan.e31',wd/'sony-board.elf'),
                         ('/vendor/firmware/kiwi/regdb.bin',wd/'sony-regdb.bin')]:
        row=wifi[android];shutil.copyfile(row['path'],dest);files.append({**row,'staged':str(dest)})
    for android,row in bt.items():
        dest=bd/android.rsplit('/',1)[1];shutil.copyfile(row['path'],dest);files.append({**row,'staged':str(dest)})
    data=(wd/'sony-board.elf').read_bytes()
    if data[:6]!=b'\x7fELF\x01\x01':raise ValueError('Actual BDF not ELF32 LE')
    # Embedded bytes remain full ELF, since upstream QMI detects ELF and sends
    # ELF BDF type. No extraction/relabel of guessed raw calibration content.
    manifest=dict(device='Sony XQ-DQ72',schema=1,capture=str(a.capture),dtb_sha256=f.sha256,files=files,
        wifi=dict(active_BDF='sony-board.elf',container='runtime-built board-2 named by actual QMI response',
                  calibration='Android HW_XPA1 CalDB0; no synthetic CAL file',m3_source='actual phy_ucode20.elf'),
        bluetooth=dict(selection='original btqca controller ROM/BID query',all_BID_variants=True,forced_b31=False),hardware_verified=False)
    (out/'firmware-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'resources':len(resources),'firmware_files':len(files),'output':str(out)},indent=2))
if __name__=='__main__':main()
