#!/usr/bin/env python3
"""Execute original USBFN core init up to first SETUP using modeled MMIO."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pe',type=Path,required=True)
    p.add_argument('--descriptors',type=Path,required=True)
    p.add_argument('--python-tools',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--photo049-state',action='store_true',help='Use measured049 ID/GHWPARAMS1/DCTL/DSTS inputs; other hardware responses remain modeled')
    p.add_argument('--fix-core-errors',action='store_true',help='Apply qualified DWC-to-EFI failure propagation correction')
    p.add_argument('--through-attach',action='store_true',help='Execute real attach caller too and check RUN_STOP after injected core failures')
    p.add_argument('--trace-core',action='store_true',help='Execute diagnostic wrappers with deliberately clobbered debug-call arguments')
    a=p.parse_args();sys.path.insert(0,str(a.python_tools))
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
    from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X30,UC_ARM64_REG_PC,UC_ARM64_REG_SP
    raw=a.pe.read_bytes();digest=hashlib.sha256(raw).hexdigest()
    if digest!='93b10001f468edfc6c8e2455674ef9099ae8c119e80c7ecf1ae6b32fcc0b6714':raise ValueError('Unknown USBFN PE')
    if a.fix_core_errors:
        sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'ci'))
        from sony_usb_core_errors import adapt_pe
        raw=adapt_pe(raw)
    if a.trace_core:
        if not a.fix_core_errors or not a.through_attach:p.error('--trace-core requires error fix and attach caller')
        from sony_usb_core_trace import adapt_pe as trace_pe
        raw=trace_pe(a.pe.read_bytes())
    desc=json.loads((a.descriptors/'descriptor-addresses.json').read_text())
    results=[]
    dwc_failures=['event-array-failure','startcfg-failure','event-config-failure','ep-command-failure','ep-resource-failure','ep-config-failure']
    for scenario in ['ready','reset-stuck','allocation-failure']+dwc_failures:
        u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0,0x20000);u.mem_write(0,raw)
        u.mem_map(0x100000,0x20000);u.mem_map(0x200000,0x100000)
        u.mem_write(0x200000,(a.descriptors/'descriptor-memory.bin').read_bytes())
        u.mem_map(0x400000,0x20000);u.mem_map(0x800000,0x100000)
        obj=0x400000;bs=0x410000;rt=0x411000;end=0x412000
        stall=0x413000;getvar=0x413010;heap=0x800000
        regs={0xa60c120:0x33313130,0xa60c144:1<<15,0xa60c300:0x200}
        if a.photo049_state:regs.update({0xa60c144:0x01092486,0xa60c704:0x00f00000,0xa60c70c:0x00d2059c,0xa60c40c:0})
        writes=[];allocations=[];calls=[];logs=[];trace_events=[];stop=[];wait_usec=0
        def q(at,v):u.mem_write(at,struct.pack('<Q',v))
        q(obj+0x1a8,desc['device']);q(obj+0x1b0,desc['superdevice'])
        q(obj+0x1e0,0xa600000);q(obj+0x1e8,0xa6f8800)
        q(obj+0xa8,0x409000)
        u.reg_write(UC_ARM64_REG_X1,1)
        q(0x17500,bs);q(bs+0xf8,stall);q(0x174e8,rt);q(rt+0x48,getvar)
        # Model the already-created software URB pool and SETUP storage; execute
        # the real prepare/update/submit code and command polling below.
        urb=0x406000;sg=0x407000;setup=0x408000
        q(urb+0x450,sg);q(obj+0xdd0,setup)
        q(obj+0x7b8,obj+0x7b8);q(obj+0x7c0,obj+0x7b8)
        u.reg_write(UC_ARM64_REG_X0,obj);u.reg_write(UC_ARM64_REG_SP,0x10f000);u.reg_write(UC_ARM64_REG_X30,end)
        def string(at):
            data=bytes(u.mem_read(at,256));return data.split(b'\0')[0].decode(errors='replace')
        def hook(uc,at,size,ctx):
            nonlocal heap,wait_usec
            if at==end:stop.append('returned');uc.emu_stop();return
            ret=None;x0=uc.reg_read(UC_ARM64_REG_X0);x1=uc.reg_read(UC_ARM64_REG_X1);x2=uc.reg_read(UC_ARM64_REG_X2)
            caller=uc.reg_read(UC_ARM64_REG_X30)
            if a.trace_core and 0x16600<=caller<0x16f00:
                caller=struct.unpack('<Q',bytes(uc.mem_read(uc.reg_read(UC_ARM64_REG_SP)+224,8)))[0]
            if at==0xec7c:
                uc.mem_write(x1,struct.pack('<I',0));ret=0 # SDP
            elif at==0xec0c and not a.trace_core:ret=0 # original comparison models QSCRATCH
            elif ((scenario=='startcfg-failure' and at==0x92cc) or
                (scenario=='event-config-failure' and at==0x8cec) or
                (scenario=='ep-command-failure' and at==0x92cc and caller==0x3e10) or
                (scenario=='ep-resource-failure' and at==0x92cc and caller==0x3e64) or
                (scenario=='ep-config-failure' and at==0x8e64)):
                calls.append(('injected DWC failure',hex(at)));ret=0x80000006
            elif at==0xc0c4:
                if not 0xa600000<=x0<0xa700000:raise ValueError('Unexpected USB MMIO '+hex(x0))
                ret=regs.get(x0,0)
            elif at==0xc138:
                if not 0xa600000<=x0<0xa700000:raise ValueError('Unexpected USB MMIO '+hex(x0))
                value=x1&0xffffffff;writes.append((x0,value));regs[x0]=value
                if x0==0xa60c704 and scenario!='reset-stuck':regs[x0]&=~(1<<30)
                if 0xa60c80c<=x0<0xa60ca00 and (x0-0xa60c80c)%16==0:regs[x0]&=~(1<<10)
                ret=value
            elif at in [0xd170,0xebc8]:
                n=x0;align=max(16,x1) if at==0xebc8 else 16
                if n>65536 or align>65536:raise ValueError('Invalid allocation')
                calls.append(('allocate',n,align))
                if (scenario=='allocation-failure' and at==0xebc8) or (scenario=='event-array-failure' and at==0xd170):ret=0
                else:
                    heap=(heap+align-1)&~(align-1);ret=heap;heap+=(n+15)&~15
                    if heap>=0x900000:raise ValueError('Heap exhausted')
                    allocations.append((ret,n));uc.mem_write(ret,bytes(n))
            elif at==0xc378:uc.mem_write(x0,bytes(x1));ret=x0
            elif at==0xc41c:uc.mem_write(x0,bytes(uc.mem_read(x1,x2)));ret=x0
            elif at==getvar:ret=0x800000000000000e # no UsbfnMaxSpeed override
            elif at==stall:wait_usec+=x0;ret=0
            elif at==0xc09c:ret=0 # CPU memory fence, no host side effect
            elif at==0x54a4:
                calls.append(('get existing URB',));q(x1,urb);ret=0
            elif at==0x2118:
                calls.append(('queue attached notification',));ret=0
            elif at==0xc1b0:
                fmt=string(x1);logs.append(fmt);ret=0
                if fmt.startswith('PDX core '):
                    from unicorn import arm64_const
                    trace_events.append(dict(format=fmt,site=x2,values=[uc.reg_read(getattr(arm64_const,'UC_ARM64_REG_X'+str(i))) for i in range(3,7)]))
                if a.trace_core:
                    from unicorn import arm64_const
                    for index in range(1,18):uc.reg_write(getattr(arm64_const,'UC_ARM64_REG_X'+str(index)),0xaabbccdd)
                    for index in range(8):uc.reg_write(getattr(arm64_const,'UC_ARM64_REG_Q'+str(index)),0x123456789abcdef)
            if ret is not None:
                uc.reg_write(UC_ARM64_REG_X0,ret);uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_X30))
        def memory(uc,access,at,size,value,ctx):
            if 0x800000<=at<0x900000 and not any(start<=at and at+size<=start+n for start,n in allocations):
                raise ValueError('Core heap overrun '+hex(at))
        u.hook_add(UC_HOOK_CODE,hook);u.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,memory)
        core_returns=[]
        def core_return(uc,at,size,ctx):
            if at==0x6348:core_returns.append(uc.reg_read(UC_ARM64_REG_X0))
        if a.through_attach:u.hook_add(UC_HOOK_CODE,core_return)
        try:u.emu_start(0x6180 if a.through_attach else 0x3880,end+4,count=3000000)
        except Exception:
            print('Core emulator PC/LR',hex(u.reg_read(UC_ARM64_REG_PC)),hex(u.reg_read(UC_ARM64_REG_X30)),'calls',calls[-5:]);raise
        returned=core_returns[0] if a.through_attach else u.reg_read(UC_ARM64_REG_X0)
        if a.through_attach:
            assert len(core_returns)==1
            assert bool(regs.get(0xa60c704,0)&(1<<31))==(returned==0)
        if a.trace_core:
            assert [item for item in writes if item[0] in (0xa6f8810,0xa6f8830)]==[
                (0xa6f8810,1<<20),(0xa6f8810,(1<<20)|(1<<28)),(0xa6f8830,1<<24)]
            # Nested wrappers produce a stack of enter/return records. Verify
            # ordering and logged return values, not just that strings exist.
            stack=[]
            for event in trace_events:
                if ' enter ' in event['format']:stack.append(event['site'])
                elif ' return ' in event['format']:
                    assert stack and stack.pop()==event['site']
            assert not stack
            if scenario=='ready':
                seen={event['site'] for event in trace_events}
                assert {0xec1c,0xec24,0xec28,0xec30,0xec34,0xec3c,0x38dc,0x38f0,0x3a4c,0x3d34,0x3d5c,0x3e9c,0x3ed8,0x3f04,0x637c}<=seen
        if scenario=='ready':
            assert stop==['returned'] and returned==0,(stop,hex(returned))
            assert regs[0xa60c720]==3
            event_addr=regs.get(0xa60c400,0)|(regs.get(0xa60c404,0)<<32)
            assert (event_addr,4096) in allocations
            assert sum(n==80 for _,n in allocations)==2
            setup_commands=[value for at,value in writes if at==0xa60c80c and value&15==6]
            assert len(setup_commands)==1,setup_commands
            trb_address=regs[0xa60c804]|(regs[0xa60c808]<<32)
            trb=bytes(u.mem_read(trb_address,16));buffer_lo,buffer_hi,length,control=struct.unpack('<4I',trb)
            assert buffer_lo|(buffer_hi<<32)==setup and length&0xffffff==8
            assert (control>>4)&0x3f==2 # control SETUP TRB
        elif scenario in dwc_failures:
            expected=0x8000000000000007 if a.fix_core_errors else (0x800000000000000e if scenario=='startcfg-failure' else 0)
            assert stop==['returned'] and returned==expected,(scenario,stop,hex(returned))
            if scenario!='event-array-failure':assert any(c[0]=='injected DWC failure' for c in calls),scenario
        else:
            assert stop==['returned'] and returned!=0,(scenario,stop)
        results.append(dict(scenario=scenario,stop=stop,return_register=hex(returned),
            mmio_writes=[(hex(at),hex(value)) for at,value in writes],allocations=[(hex(at),n) for at,n in allocations],
            delay_usec=wait_usec,logs=logs,trace_events=trace_events))
    a.out.mkdir(parents=True,exist_ok=False)
    report=dict(passed=True,pe_sha256=digest,cases=results,hardware_verified=False,
        tested_pe_sha256=hashlib.sha256(raw).hexdigest(),core_errors_fixed=a.fix_core_errors,
        trace_wrappers=a.trace_core,
        real_attach_caller=a.through_attach,
        measured_initial_state_used=a.photo049_state,
        limits='Real core/SETUP prepare-update-submit and descriptor traversal; MMIO responses, allocation, software URB acquisition, variable/debug services modeled. No actual DMA or board power behavior.')
    if a.trace_core:
        from sony_usb_core_trace import SITES,TAIL_SITES,BASE
        report['trace_sites']=[dict(site=site,target=target,wrapper=BASE+index*12,tail=site in TAIL_SITES) for index,(site,_,target) in enumerate(SITES)]
        report['trace_region_sha256']=hashlib.sha256(raw[0x16600:0x16f00]).hexdigest()
        report['qscratch_entry_bytes']=raw[0xec0c:0xec10].hex()
    (a.out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS original USBFN core initialization paths:',[(r['scenario'],r['stop'],len(r['mmio_writes'])) for r in results])

if __name__=='__main__':main()
