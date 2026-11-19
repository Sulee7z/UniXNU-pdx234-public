#!/usr/bin/env python3
"""Exercise original ARM64 cable-attach control flow, modeling hardware services."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pe',type=Path,required=True)
    p.add_argument('--python-tools',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();sys.path.insert(0,str(a.python_tools))
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
    from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X19,UC_ARM64_REG_X30,UC_ARM64_REG_PC,UC_ARM64_REG_SP
    raw=a.pe.read_bytes();digest=hashlib.sha256(raw).hexdigest()
    if digest!='93b10001f468edfc6c8e2455674ef9099ae8c119e80c7ecf1ae6b32fcc0b6714':raise ValueError('Unknown Sony USBFN PE')
    results=[]
    for name,port,query_error,core_error in [('SDP',0,False,False),('CDP',1,False,False),
            ('DCP',2,False,False),('invalid',7,False,False),('unknown-timeout',8,False,False),
            ('query-failure',8,True,False),('core-failure',0,False,True)]:
        u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0,0x20000);u.mem_write(0,raw)
        u.mem_map(0x100000,0x20000);u.mem_map(0x200000,0x10000)
        def q(at,v):u.mem_write(at,struct.pack('<Q',v))
        dev=0x200000;cfg=0x204000;bs=0x205000;stall=0x206000;end=0x207000
        q(dev+0xa8,cfg);q(dev+0x1e0,0xa600000);q(dev+0x1e8,0xa6f8800)
        q(0x17500,bs);q(bs+0xf8,stall)
        u.reg_write(UC_ARM64_REG_SP,0x10f000);u.reg_write(UC_ARM64_REG_X30,end)
        u.reg_write(UC_ARM64_REG_X0,dev);u.reg_write(UC_ARM64_REG_X1,1)
        calls=[];queries=[];writes=[]
        def hook(uc,at,size,ctx):
            if at==end:uc.emu_stop();return
            ret=None
            if at==0xc1b0:ret=0
            elif at==0xec7c:
                queries.append(1);uc.mem_write(uc.reg_read(UC_ARM64_REG_X1),struct.pack('<I',port))
                ret=0x8000000000000007 if query_error else 0
            elif at==stall:
                assert uc.reg_read(UC_ARM64_REG_X0)==10000;ret=0
            elif at==0xec0c:
                assert uc.reg_read(UC_ARM64_REG_X0)==0
                assert uc.reg_read(UC_ARM64_REG_X1)==0xa6f8800
                calls.append('QSCRATCH connect');ret=0
            elif at==0x3880:
                assert uc.reg_read(UC_ARM64_REG_X0)==dev
                calls.append('core init');ret=0x8000000000000007 if core_error else 0
            elif at==0xc0c4:
                assert uc.reg_read(UC_ARM64_REG_X0)==0xa60c704
                calls.append('read DCTL');ret=0x10f00000
            elif at==0xc138:
                writes.append((uc.reg_read(UC_ARM64_REG_X0),uc.reg_read(UC_ARM64_REG_X1)))
                ret=0
            if ret is not None:
                uc.reg_write(UC_ARM64_REG_X0,ret);uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_X30))
        u.hook_add(UC_HOOK_CODE,hook);u.emu_start(0x6180,end+4,count=30000)
        if u.reg_read(UC_ARM64_REG_PC)!=end:raise ValueError('Attach did not return '+name)
        should_init=port in (0,1,8)
        assert ('core init' in calls)==should_init
        assert bool(writes)==(should_init and not core_error)
        if writes:assert writes==[(0xa60c704,0x90f00000)]
        assert len(queries)==(101 if name=='unknown-timeout' else 1)
        results.append(dict(case=name,charger_queries=len(queries),calls=calls,writes=[(hex(x),hex(y)) for x,y in writes],
                            software_attached_flag=int(u.mem_read(dev+0x181,1)[0])))
    a.out.mkdir(parents=True,exist_ok=False)
    report=dict(passed=True,pe_sha256=digest,cases=results,hardware_services_modeled=True,hardware_verified=False,
                limits='Tests only cable-attach branch/error flow. Core init, PMIC and MMIO effects modeled; no shutdown cause established.')
    (a.out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

if __name__=='__main__':main()
