#!/usr/bin/env python3
"""Run the original/adapted cleanup ARM64 entry with modeled callees."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pe',type=Path,required=True)
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--python-tools',type=Path,required=True)
    a=p.parse_args();sys.path.insert(0,str(a.python_tools));sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'ci'))
    from sony_pmic_exit_handoff import adapt_pe,adapt_source
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
    from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X30,UC_ARM64_REG_PC,UC_ARM64_REG_SP
    original=a.pe.read_bytes();adapted=adapt_pe(original);cases=[]
    callees={0x126a8:'target',0x129e8:'irq_sweep',0x10bb0:'lock_config',0x128cc:'revoke_access'}
    for variant,data in [('original',original),('adapted',adapted)]:
        for failure in ['none',*callees.values()]:
            u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0,0x40000);u.mem_write(0,data)
            u.mem_map(0x100000,0x10000);u.reg_write(UC_ARM64_REG_SP,0x10f000);u.reg_write(UC_ARM64_REG_X30,0x100000)
            calls=[]
            def hook(uc,at,size,ctx):
                if at==0x100000:uc.emu_stop();return
                if at not in callees:return
                name=callees[at];calls.append(name)
                uc.reg_write(UC_ARM64_REG_X0,128 if failure==name else 0)
                uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_X30))
            u.hook_add(UC_HOOK_CODE,hook);u.emu_start(0x40f8,0x100004,count=200)
            expected_calls=list(callees.values()) if variant=='original' else ['target']
            assert calls==expected_calls,(variant,calls)
            status=u.reg_read(UC_ARM64_REG_X0)
            assert status==(0x8000000000000007 if failure in calls else 0),(variant,failure,status)
            cases.append(dict(variant=variant,failure=failure,calls=calls,status=hex(status)))
    a.out.mkdir(parents=True,exist_ok=False)
    (a.out/'pm_core_utils.adapted.c').write_text(adapt_source(a.source.read_text()))
    (a.out/'PmicDxe.adapted.efi').write_bytes(adapted)
    report=dict(passed=True,cases=cases,adapted_pe_sha256=hashlib.sha256(adapted).hexdigest(),
                source_sha256=hashlib.sha256(a.source.read_bytes()).hexdigest(),external_services_modeled=True,hardware_verified=False)
    (a.out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS ten ARM64 cleanup cases;',report['adapted_pe_sha256'])

if __name__=='__main__':main()
