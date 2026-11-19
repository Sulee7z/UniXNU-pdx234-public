#!/usr/bin/env python3
"""Execute original and adapted pm_init ARM64 code with mocked dependencies."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[2]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--pe',type=Path,required=True)
    p.add_argument('--python-tools',type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(ROOT/'ci'));sys.path.insert(0,str(a.python_tools))
    from sony_pmic_handoff import adapt_source,adapt_pe
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
    from unicorn.arm64_const import UC_ARM64_REG_PC,UC_ARM64_REG_SP,UC_ARM64_REG_X0,UC_ARM64_REG_X30
    source=a.source.read_text();(a.out/'pm_core_init.adapted.c').write_text(adapt_source(source))
    original=a.pe.read_bytes();modified=adapt_pe(original);(a.out/'PmicDxe.adapted.efi').write_bytes(modified)
    results=[]
    calls_map={0x12838:'device_setup',0x73e0:'model',0x10a18:'target_info',0x119b8:'time',
               0x19884:'config',0x7900:'coincell',0x11ac8:'comm_info',0x248e4:'resources',
               0x16b18:'rpmh',0x14780:'prm',0x126b0:'print'}
    for variant,data in [('original',original),('adapted',modified)]:
        for failure in ['none','device_setup','target_info','config','model']:
            u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);pe=struct.unpack_from('<I',data,0x3c)[0];opt=pe+24
            size=struct.unpack_from('<I',data,opt+56)[0];u.mem_map(0,(size+4095)&~4095)
            sec=opt+struct.unpack_from('<H',data,pe+20)[0]
            for i in range(struct.unpack_from('<H',data,pe+6)[0]):
                at=sec+40*i;_,va,n,off=struct.unpack_from('<4I',data,at+8)
                if n:u.mem_write(va,data[off:off+n])
            u.mem_map(0x100000,0x10000);u.reg_write(UC_ARM64_REG_SP,0x10f000);u.reg_write(UC_ARM64_REG_X30,0x100000)
            u.mem_write(0x3365c,b'\0');calls=[]
            def hook(uc,address,length,ctx):
                if address==0x100000:uc.emu_stop();return
                if address not in calls_map:return
                name=calls_map[address];calls.append(name)
                value=(0 if failure=='model' else 1) if name=='model' else (128 if name==failure else 0)
                uc.reg_write(UC_ARM64_REG_X0,value);uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_X30))
            u.hook_add(UC_HOOK_CODE,hook);u.emu_start(0x1275c,0x100004,count=1500)
            value=u.reg_read(UC_ARM64_REG_X0)
            assert value==(1 if failure=='model' else 0 if failure=='none' else 128),(variant,failure,value)
            if failure!='model':
                assert ('coincell' in calls)==(variant=='original')
                assert all(n in calls for n in ['device_setup','target_info','config','comm_info','resources','rpmh','prm'])
            results.append(dict(variant=variant,failure=failure,calls=calls,result=value))
    report=dict(passed=True,cases=results,source_sha256=hashlib.sha256(a.source.read_bytes()).hexdigest(),
        original_pe_sha256=hashlib.sha256(original).hexdigest(),adapted_pe_sha256=hashlib.sha256(modified).hexdigest(),
        hardware_verified=False,dependencies_modeled=True)
    (a.out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS ten ARM64 pm_init cases: coin-cell call omitted, other initialization and errors retained')

if __name__=='__main__':main()
