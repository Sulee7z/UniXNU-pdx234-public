#!/usr/bin/env python3
"""Run Sony's actual ARM64 descriptor parser with the CDC client's arrays."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pe',type=Path,required=True)
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--python-tools',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();sys.path.insert(0,str(a.python_tools))
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
    from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X30,UC_ARM64_REG_PC,UC_ARM64_REG_SP
    raw=a.pe.read_bytes();digest=hashlib.sha256(raw).hexdigest()
    if digest!='825189eeb95c4198c95bc9391daf2ffea4e8eea5461b63119aeffb14dbac5121':raise ValueError('Unknown Sony USB device binary')
    text=a.source.read_text();arrays={}
    for name in ['mDeviceHs','mDeviceSs','mQualifier','mConfigHs','mConfigSs','mBos','mLanguage']:
        match=re.search(r'STATIC UINT8 '+name+r'\[\]\s*=\s*\{([^}]+)\}',text,re.S)
        arrays[name]=bytes(int(t.strip(),0) for t in match[1].split(',') if t.strip())
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0,0x20000);u.mem_write(0,raw)
    # usb_shared_is_eud_active reads the EUD enable register. Model disabled
    # EUD for this descriptor test; this is not a hardware register capture.
    u.mem_map(0x088e0000,0x10000)
    u.mem_map(0x100000,0x20000);u.mem_map(0x200000,0x100000)
    alloc=0x200000;blocks=[];protected=[]
    def q(at,v):u.mem_write(at,struct.pack('<Q',v))
    def getq(at):return struct.unpack('<Q',u.mem_read(at,8))[0]
    def put(data):
        nonlocal alloc
        at=alloc;alloc+=(len(data)+63)&~63;blocks.append((at,len(data)))
        u.mem_write(at,data);return at
    addr={name:put(data) for name,data in arrays.items()}
    for name,data in arrays.items():protected.append((addr[name],len(data)))
    hs=put(struct.pack('<Q',addr['mConfigHs']));ss=put(struct.pack('<Q',addr['mConfigSs']))
    strings=[addr['mLanguage']]
    for value in ['UniXNU','PDX234 UEFI log','PDX234UEFI01']:
        data=value.encode('utf-16le');strings.append(put(bytes([len(data)+2,3])+data))
    strings=put(struct.pack('<4Q',*strings))
    desc=put(struct.pack('<6QB7xQ',addr['mDeviceHs'],hs,addr['mDeviceSs'],ss,addr['mQualifier'],addr['mBos'],4,strings))
    device=put(bytes(16));superdevice=put(bytes(24));descriptors=put(bytes(0x60))
    q(0xb498,0x110000);q(0x110000+0x160,0x111000)
    u.reg_write(UC_ARM64_REG_SP,0x10e000);u.reg_write(UC_ARM64_REG_X30,0x112000)
    for reg,val in [(UC_ARM64_REG_X0,desc),(UC_ARM64_REG_X1,device),(UC_ARM64_REG_X2,superdevice),(UC_ARM64_REG_X3,descriptors)]:u.reg_write(reg,val)
    touched=[]
    def code(uc,at,size,ctx):
        if at==0x112000:uc.emu_stop();return
        ret=None
        if at==0x46c8:
            n=uc.reg_read(UC_ARM64_REG_X0)
            if n>65536:raise ValueError('Excessive allocation')
            ret=put(bytes(n))
        elif at in [0x111000,0x49cc]:
            dst=uc.reg_read(UC_ARM64_REG_X0);src=uc.reg_read(UC_ARM64_REG_X1);n=uc.reg_read(UC_ARM64_REG_X2)
            if n>65536:raise ValueError('Excessive copy')
            uc.mem_write(dst,bytes(uc.mem_read(src,n)));ret=dst
        elif at==0x47a0:ret=0
        elif at==0x4734:ret=0
        if ret is not None:
            touched.append(hex(at));uc.reg_write(UC_ARM64_REG_X0,ret);uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_X30))
    def memory(uc,access,at,size,value,ctx):
        if 0x200000<=at<0x300000 and not any(start<=at and at+size<=start+n for start,n in blocks):
            raise ValueError('Parser heap overrun '+hex(at))
    u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,memory)
    try:u.emu_start(0x3d0c,0x112004,count=1000000)
    except Exception:
        print('Emulation fault PC',hex(u.reg_read(UC_ARM64_REG_PC)),'LR',hex(u.reg_read(UC_ARM64_REG_X30)),
              'X0..3',[hex(u.reg_read(reg)) for reg in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3]])
        raise
    if u.reg_read(UC_ARM64_REG_PC)!=0x112000 or u.reg_read(UC_ARM64_REG_X0)!=0:raise ValueError('Parser did not succeed')
    results=[]
    for label,info,ssmode in [('HS',device,False),('SS',superdevice,True)]:
        cfg=getq(getq(info+8));cfgdesc=getq(cfg);ifaces=getq(cfg+8)
        assert u.mem_read(cfgdesc+4,1)==b'\x02'
        rows=[]
        for i,expected in enumerate([[0x81],[2,0x83]]):
            iface=getq(ifaces+8*i);idesc=getq(iface);eps=getq(iface+8)
            assert u.mem_read(idesc+2,1)==bytes([i])
            assert u.mem_read(idesc+4,1)==bytes([len(expected)])
            for j,ep in enumerate(expected):
                entry=getq(eps+8*j);epdesc=getq(entry) if ssmode else entry
                assert u.mem_read(epdesc+2,1)==bytes([ep])
                packet=struct.unpack('<H',u.mem_read(epdesc+4,2))[0]
                assert packet==(16 if ep==0x81 else 1024 if ssmode else 512)
                if ssmode:assert u.mem_read(getq(entry+8),2)==bytes([6,0x30])
            rows.append(expected)
        results.append(dict(speed=label,interfaces=rows))
    a.out.mkdir(exist_ok=False,parents=True)
    report=dict(passed=True,pe_sha256=digest,source_sha256=hashlib.sha256(a.source.read_bytes()).hexdigest(),results=results,
                scope='Real Sony descriptor parser; allocation/copy/debug modeled, no controller or DMA test',hardware_verified=False)
    (a.out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
    # Retain exact parsed structures for the separate original USBFN core test.
    (a.out/'descriptor-memory.bin').write_bytes(bytes(u.mem_read(0x200000,0x100000)))
    (a.out/'descriptor-addresses.json').write_text(json.dumps(dict(base=0x200000,device=device,
        superdevice=superdevice,blocks=blocks,parser_pe_sha256=digest),indent=2)+'\n')

if __name__=='__main__':main()
