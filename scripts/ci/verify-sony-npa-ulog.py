#!/usr/bin/env python3
"""Execute original NPA init through its ULog wrapper; model external services."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import uuid

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pe',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--python-tools',type=Path,required=True)
    a=p.parse_args()
    sys.path.insert(0,str(a.python_tools))
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
    from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X30,UC_ARM64_REG_PC,UC_ARM64_REG_SP
    data=a.pe.read_bytes();digest=hashlib.sha256(data).hexdigest()
    if digest!='23025cbcb30897ea90193174a2ca2ff66dec6b378ba249141a76eeb338cb2310':raise ValueError('Unknown NPA PE')
    cases=[]
    for variant in ['missing','available','service-error','cached']:
        u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0,0x20000);u.mem_write(0,data)
        u.mem_map(0x100000,0x10000);u.mem_map(0x200000,0x10000)
        u.reg_write(UC_ARM64_REG_SP,0x10f000);u.reg_write(UC_ARM64_REG_X30,0x20f000)
        def putq(at,value):u.mem_write(at,struct.pack('<Q',value))
        putq(0x117f8,0x201000);putq(0x201140,0x202000);putq(0x2000f0,0x203000)
        if variant=='cached':putq(0x11d30,0x200000)
        calls=[];stop=[]
        def hook(uc,at,size,ctx):
            if at in [0x28c8,0x1b00]:
                stop.append(at);uc.emu_stop();return
            ret=None
            if at==0xa710:
                uc.mem_write(uc.reg_read(UC_ARM64_REG_X0),bytes([uc.reg_read(UC_ARM64_REG_X1)&255])*uc.reg_read(UC_ARM64_REG_X2));ret=uc.reg_read(UC_ARM64_REG_X0)
            elif at==0xd5b4:ret=0;calls.append('DAL init')
            elif at==0xca78:ret=0x204000;calls.append('mutex create')
            elif at==0x202000:
                assert bytes(uc.mem_read(uc.reg_read(UC_ARM64_REG_X0),16))==uuid.UUID('93a824b1-f77c-4880-ad95-e7bc634f9051').bytes_le
                calls.append('Locate ULog')
                ret=0x800000000000000e if variant=='missing' else 0
                if ret==0:putq(uc.reg_read(UC_ARM64_REG_X2),0x200000)
            elif at==0x203000:
                calls.append('ULog RealTimeInit')
                uc.mem_write(uc.reg_read(UC_ARM64_REG_X0),struct.pack('<I',14 if variant=='service-error' else 0))
                if variant!='service-error':putq(uc.reg_read(UC_ARM64_REG_X1),0x205000)
                ret=0
            if ret is not None:
                uc.reg_write(UC_ARM64_REG_X0,ret);uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_X30))
        u.hook_add(UC_HOOK_CODE,hook);u.emu_start(0x2724,0x20f000,count=2000)
        success=variant in ['available','cached']
        assert stop==[0x28c8 if success else 0x1b00],(variant,stop)
        if not success:assert u.reg_read(UC_ARM64_REG_X1)==0
        assert ('ULog RealTimeInit' in calls)==(variant!='missing')
        assert ('Locate ULog' in calls)==(variant!='cached')
        cases.append(dict(variant=variant,calls=calls,reaches_memory_pool_initialization=success,
                          null_format_error_path=not success))
    a.out.mkdir(parents=True,exist_ok=False)
    result=dict(passed=True,pe_sha256=digest,cases=cases,external_services_modeled=True,hardware_verified=False,
                scope='npa_init through logging check, not full NPA initialization')
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
