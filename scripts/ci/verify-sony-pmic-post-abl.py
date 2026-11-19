#!/usr/bin/env python3
"""Execute original/adapted PmicInitialize with modeled external services."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pe',type=Path,required=True)
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--python-tools',type=Path,required=True)
    a=p.parse_args();sys.path.insert(0,str(a.python_tools));sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'ci'))
    from sony_pmic_handoff import adapt_pe as coin
    from sony_pmic_post_abl import adapt_pe,adapt_source
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
    from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X30,UC_ARM64_REG_PC,UC_ARM64_REG_SP
    original=coin(a.pe.read_bytes());adapted=adapt_pe(original);cases=[]
    calls_map={0x12318:'DAL',0x1194c:'timer',0x1275c:'pm_init',0x1710:'common_protocols',
               0x124f4:'target_protocols',0x19158:'power_key',0x151c:'exit_events',
               0x12560:'charger_board_policy',0x119b8:'time',0x19078:'pshold',0x4298:'ADC',0x4940:'debug'}
    for variant,data in [('original',original),('post-ABL',adapted)]:
        for failure in ['none','pm_init','common_protocols','target_protocols','power_key','charger_board_policy','pshold']:
            u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0,0x40000);u.mem_write(0,data)
            u.mem_map(0x100000,0x10000);u.reg_write(UC_ARM64_REG_SP,0x10f000);u.reg_write(UC_ARM64_REG_X30,0x100000)
            calls=[]
            def hook(uc,at,size,ctx):
                if at==0x100000:uc.emu_stop();return
                if at not in calls_map:return
                name=calls_map[at];calls.append(name)
                uc.reg_write(UC_ARM64_REG_X0,128 if failure==name else 0)
                uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_X30))
            u.hook_add(UC_HOOK_CODE,hook);u.emu_start(0x15d0,0x100004,count=1500)
            expected_error=failure!='none' and not (variant=='post-ABL' and failure in ['charger_board_policy','pshold'])
            result=u.reg_read(UC_ARM64_REG_X0)
            assert result==(0x8000000000000007 if expected_error else 0),(variant,failure,result)
            if variant=='post-ABL':assert not {'charger_board_policy','pshold'}&set(calls)
            assert 'ADC' in calls
            if failure=='none':assert {'pm_init','common_protocols','target_protocols','power_key','exit_events'}<=set(calls)
            cases.append(dict(variant=variant,injected_failure=failure,calls=calls,result=hex(result)))
    a.out.mkdir(parents=True,exist_ok=False)
    (a.out/'Pmic.adapted.c').write_text(adapt_source(a.source.read_text()))
    (a.out/'PmicDxe.adapted.efi').write_bytes(adapted)
    report=dict(passed=True,cases=cases,adapted_pe_sha256=hashlib.sha256(adapted).hexdigest(),
                source_sha256=hashlib.sha256(a.source.read_bytes()).hexdigest(),external_services_modeled=True,hardware_verified=False)
    (a.out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS 14 ARM64 entrypoint cases;',report['adapted_pe_sha256'])

if __name__=='__main__':main()
