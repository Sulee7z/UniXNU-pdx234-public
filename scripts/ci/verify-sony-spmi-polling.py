#!/usr/bin/env python3
"""Execute original/patched ARM64 SpmiBus_Init with controlled dependencies."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build',type=Path,required=True)
    p.add_argument('--python-tools',type=Path,required=True)
    a=p.parse_args();sys.path.insert(0,str(a.python_tools))
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn.arm64_const import UC_ARM64_REG_PC,UC_ARM64_REG_SP,UC_ARM64_REG_X0,UC_ARM64_REG_X30
    receipt=json.loads((a.build/'result.json').read_text())
    results=[]
    for variant in ('original','polling'):
        data=(a.build/('SPMI.'+variant+'.efi')).read_bytes()
        expected=receipt['spmi_original_sha256' if variant=='original' else 'spmi_patched_sha256']
        if hashlib.sha256(data).hexdigest()!=expected:raise ValueError('SPMI identity mismatch')
        pe=struct.unpack_from('<I',data,0x3c)[0];opt=pe+24
        image_size=struct.unpack_from('<I',data,opt+56)[0]
        section=opt+struct.unpack_from('<H',data,pe+20)[0]
        for fail in ('none','os','arb','already'):
            u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0,(image_size+4095)&~4095)
            for i in range(struct.unpack_from('<H',data,pe+6)[0]):
                at=section+40*i;_,va,n,off=struct.unpack_from('<4I',data,at+8)
                if n:u.mem_write(va,data[off:off+n])
            u.mem_map(0x100000,0x10000);u.reg_write(UC_ARM64_REG_SP,0x10f000)
            u.reg_write(UC_ARM64_REG_X30,0x100000)
            u.mem_write(0x82d8,bytes([fail=='already']))
            info=0x102000;devices=0x103000
            u.mem_write(0x8648,struct.pack('<Q',info))
            u.mem_write(info+0x12,b'\x02');u.mem_write(info+0x18,struct.pack('<Q',devices))
            calls=[]
            def hook(uc,address,size,user):
                if address==0x100000:uc.emu_stop();return
                targets={0x3bfc:'os',0x3070:'arb',0x30a4:'cache',0x2eac:'pic',0x1f54:'lock'}
                if address not in targets:return
                name=targets[address];calls.append(name)
                if name=='pic':uc.emu_stop();return
                value=7 if fail==name else 0
                if name=='os':uc.mem_write(0x8648,struct.pack('<Q',info))
                uc.reg_write(UC_ARM64_REG_X0,value)
                uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_X30))
            u.hook_add(UC_HOOK_CODE,hook);u.emu_start(0x26c0,0x100004,count=2000)
            result=u.reg_read(UC_ARM64_REG_X0);initialized=u.mem_read(0x82d8,1)[0]
            if fail=='none':
                if variant=='original':assert calls==['os','arb','pic'] and not initialized
                else:assert calls==['os','arb','lock'] and initialized and result==0
            elif fail=='already':assert calls==['cache'] and result==0
            else:assert calls==(['os'] if fail=='os' else ['os','arb']) and result==7 and not initialized
            results.append(dict(variant=variant,case=fail,calls=calls,return_value=result,initialized=initialized))
    report=dict(passed=True,checks=results,actual_arm64_init_executed=True,
                dependency_calls_modeled=True,mmio_hardware_verified=False)
    (a.build/'emulation.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS original reaches PIC takeover; patched polling init retains OS/bus/cache/lock/error behavior (8 cases)')


if __name__=='__main__':main()
