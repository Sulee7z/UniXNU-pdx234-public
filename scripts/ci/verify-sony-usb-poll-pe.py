#!/usr/bin/env python3
"""Execute original EventHandler/poll/attach ARM64 with qualified error fixes.

Actual DwcInitialize allocation failure and actual core reset-error tail run;
other core return statuses are injected at the core boundary. Hardware, debug
and allocation services are modeled. This is not hardware/DMA qualification.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import subprocess
import tempfile

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pe', type=Path, required=True)
    p.add_argument('--python-tools', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--trace-core', action='store_true',
                   help='Run the combined poll/error/trace PE through EventHandler')
    a = p.parse_args()
    sys.path.insert(0, str(a.python_tools))
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'ci'))
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn import arm64_const as arm
    from sony_usb_core_errors import adapt_pe as core_fix
    from sony_usb_poll_errors import adapt_pe, change_ranges, BASE, payload
    # Only this Linux qualification step uses a compiler. The shipped adapter
    # and Windows byte verifier use the fixed byte table without subprocesses.
    blob, symbols = payload()
    with tempfile.TemporaryDirectory(prefix='sony-poll-assembly-') as directory:
        work=Path(directory)
        assembly=Path(__file__).resolve().parents[2]/'ci/sony_usb_poll_errors.S'
        subprocess.run(['clang','--target=aarch64-none-elf','-c',str(assembly),'-o',str(work/'p.o')],check=True)
        subprocess.run(['ld.lld','-Ttext='+hex(BASE),'-e','CableFailure',
                        '--defsym=DebugPrint=0xc1b0','--defsym=FailureFormat=0x124b7',
                        '--defsym=CableName=0x123eb',str(work/'p.o'),'-o',str(work/'p.elf')],check=True)
        subprocess.run(['llvm-objcopy','--only-section=.text','-O','binary',str(work/'p.elf'),str(work/'p.bin')],check=True)
        assert (work/'p.bin').read_bytes()==blob, 'Fixed payload differs from assembly'
        actual={line.split()[2]:int(line.split()[0],16) for line in
                subprocess.check_output(['llvm-nm','--defined-only',str(work/'p.elf')],text=True).splitlines()
                if len(line.split())==3}
        assert actual==symbols, (actual,symbols)
    original = a.pe.read_bytes()
    core = core_fix(original)
    patched = adapt_pe(original)
    assert patched == adapt_pe(core)
    ranges = change_ranges()
    assert all(any(lo<=i<hi for lo,hi in ranges) for i,(x,y) in enumerate(zip(core,patched)) if x!=y)
    assert len(core)==len(patched)
    # Neither live globals/relocations nor the main-owned trace cave change.
    assert core[0x17000:] == patched[0x17000:]
    assert core[0x16600:0x16f10] == patched[0x16600:0x16f10]
    for at in [0x6344,0x6348,0xec0c,0x637c]:
        assert core[at:at+4]==patched[at:at+4]
    for at in [0x2fa0, BASE, 0x17500]:
        bad = bytearray(core);bad[at] ^= 1
        try: adapt_pe(bytes(bad))
        except ValueError: pass
        else: raise AssertionError('Accepted unknown executable')
    poll_patched = patched
    sources = [Path(__file__), assembly.with_suffix('.py'), assembly]
    if a.trace_core:
        from sony_usb_core_trace import adapt_pe as trace_pe, SITES
        patched = trace_pe(original)
        trace_ranges = [(site,site+4) for site,_,_ in SITES] + [(0xec0c,0xec10),(0x16600,0x16f00)]
        assert len(patched)==len(poll_patched)
        assert all(any(lo<=i<hi for lo,hi in trace_ranges)
                   for i,(x,y) in enumerate(zip(poll_patched,patched)) if x!=y)
        assert patched[0x6348:0x634c]==poll_patched[0x6348:0x634c]
        assert patched[BASE:0x17000]==poll_patched[BASE:0x17000]
        sources += [assembly.with_name('sony_usb_core_trace.py'),assembly.with_name('sony_usb_core_trace.S')]
    results = []
    error = 1 << 63
    scenarios = [('success',0), ('device-error',error|7),
                 ('out-of-resources',error|9), ('timeout',error|18),
                 ('vendor-error',error|0x1234), ('event-array-oom',error|7),
                 ('reset-stuck',0xffffffff80000009), ('no-cable',0),
                 ('disconnect',0), ('invalid-argument',error|2),
                 ('queued-message',0), ('queued-small',error|5),
                 ('queued-none',error|7), ('dcp',0), ('unknown-charger',0),
                 ('disabled',error|6), ('halted',0), ('running',0)]
    for image_name, raw in [('core-only',core), ('poll-fixed-traced' if a.trace_core else 'poll-fixed',patched)]:
      for name, expected in scenarios:
        fixed=image_name!='core-only'
        traced=fixed and a.trace_core
        u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        # Run at a nonzero load base as well: all additions are PC relative.
        load=0x1000000
        u.mem_map(load,0x20000);u.mem_write(load,raw)
        u.mem_map(0x400000,0x100000)
        obj=0x400000;cfg=0x404000;msg=0x405000;size=msg+8;data=msg+16
        end=0x410000;conn=0x410010;stack=0x4ff000
        def q(at,v):u.mem_write(at,struct.pack('<Q',v))
        def w(at,v):u.mem_write(at,struct.pack('<I',v))
        def byte(at,v):u.mem_write(at,bytes([v]))
        def x(n):return u.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
        q(obj,0x66627375);q(obj+0xa8,cfg);byte(obj+0x180,1)
        q(obj+0x1e0,0xa600000);q(obj+0x1e8,0xa6f8800)
        for at in [obj+0x1b8,obj+0x1c8]:q(at,at);q(at+8,at)
        q(cfg+0x30,conn)
        if name=='disabled':byte(obj+0x180,0)
        if name in ['halted','running']:byte(obj+0x181,1)
        if name=='disconnect':byte(obj+0x181,1)
        if name.startswith('queued'):
            node=0x406000;head=obj+0x1b8
            q(head,node);q(head+8,node);q(node,head);q(node+8,head)
            w(node+16,0 if name=='queued-none' else 2);u.mem_write(node+24,bytes(range(32)))
        calls=[];writes=[];reads=[];returned=[];core_calls=0
        core_returns=[];trace_returns=[];trace_debug_calls=0
        regs={0xa60c120:0x33313130,0xa60c144:0x01092486,0xa60c704:0x00f00000}
        if name=='running':regs[0xa60c704]|=1<<31
        def hook(uc,at,n,context):
            nonlocal core_calls,trace_debug_calls
            if at==end:returned.append(x(0));uc.emu_stop();return
            ret=None
            if at==conn:
                byte(x(2),0 if name in ['no-cable','disconnect'] else 1);ret=0
            else:
                rva=at-load
                if rva==0x6348:core_returns.append(x(0))
                elif rva==0x3880:
                    core_calls+=1
                    if name not in ['event-array-oom','reset-stuck']:ret=expected
                elif rva==0xd170:
                    calls.append(('allocate',x(0)))
                    ret=0 if name=='event-array-oom' else 0x408000
                elif rva==0xab2c:
                    assert name=='reset-stuck';ret=0x80000009
                elif rva==0xec7c:w(x(1),2 if name=='dcp' else 6 if name=='unknown-charger' else 0);ret=0
                elif rva==0xec0c and not traced:ret=0
                elif rva in [0xec44,0x4b28]:ret=0
                elif rva==0x4eb0:ret=0xdeadbeef # VOID event processor return is irrelevant
                elif rva==0xc0c4:reads.append(x(0));ret=regs.get(x(0),0)
                elif rva==0xc138:
                    writes.append((x(0),x(1)&0xffffffff));regs[x(0)]=x(1)&0xffffffff;ret=x(1)
                elif rva==0xc1b0:
                    if traced and load+0x16600<=x(30)<load+0x16f00:
                        trace_debug_calls+=1
                        fmt=bytes(uc.mem_read(x(1),64)).split(b'\0')[0]
                        if fmt==b'PDX core %x return %lx\n':
                            trace_returns.append((x(2),x(3)))
                    # Diagnostic calls may overwrite every caller-saved GPR.
                    for i in range(18):uc.reg_write(getattr(arm,'UC_ARM64_REG_X'+str(i)),0xfeed0000+i)
                    for i in range(8):uc.reg_write(getattr(arm,'UC_ARM64_REG_Q'+str(i)),0x123456789abcdef)
                    ret=0xfeed0000
                elif rva==0xc298:raise AssertionError('Vendor assertion reached')
            if ret is not None:
                uc.reg_write(arm.UC_ARM64_REG_X0,ret)
                uc.reg_write(arm.UC_ARM64_REG_PC,x(30))
        u.hook_add(UC_HOOK_CODE,hook)
        saved={i:0x12340000+i for i in range(19,30)}
        def invoke():
            q(size,1 if name=='queued-small' else 32)
            w(msg,0xdeadbeef)
            for i,v in saved.items():u.reg_write(getattr(arm,'UC_ARM64_REG_X'+str(i)),v)
            for i,v in enumerate([0 if name=='invalid-argument' else obj+8,msg,size,data]):
                u.reg_write(getattr(arm,'UC_ARM64_REG_X'+str(i)),v)
            u.reg_write(arm.UC_ARM64_REG_SP,stack);u.reg_write(arm.UC_ARM64_REG_X30,end)
            count=len(returned)
            u.emu_start(load+0x2ed8,end+4,count=200000)
            assert len(returned)==count+1,(name,hex(u.reg_read(arm.UC_ARM64_REG_PC)))
            assert u.reg_read(arm.UC_ARM64_REG_SP)==stack
            assert all(x(i)==v for i,v in saved.items()),name
            return returned[-1]
        first=invoke()
        is_core_failure=name in ['device-error','out-of-resources','timeout','vendor-error','event-array-oom','reset-stuck','queued-none']
        want=0 if image_name=='core-only' and (is_core_failure or name=='disabled') else expected
        assert first==want,(image_name,name,hex(first),hex(want))
        assert not is_core_failure or not any(v&(1<<31) for at,v in writes if at==0xa60c704)
        if name=='success':assert regs[0xa60c704]&(1<<31)
        if core_calls:
            assert core_returns==[expected],(name,core_returns,expected)
            if traced:
                assert (0x6344,expected) in trace_returns,(name,trace_returns)
                assert trace_debug_calls>0
                assert [(at,v) for at,v in writes if at in [0xa6f8810,0xa6f8830]]==[
                    (0xa6f8810,0x100000),(0xa6f8810,0x10100000),(0xa6f8830,0x1000000)]
        if name=='event-array-oom':
            assert calls==[('allocate',432)]
            assert not [at for at,_ in writes if at not in [0xa6f8810,0xa6f8830]]
        if name in ['queued-message','queued-small']:
            assert core_calls==0 and int.from_bytes(u.mem_read(msg,4),'little')==2
            if name=='queued-message':assert bytes(u.mem_read(data,32))==bytes(range(32))
        if name=='queued-none':
            assert int.from_bytes(u.mem_read(msg,4),'little')==0
            assert int.from_bytes(u.mem_read(size,8),'little')==0
        if is_core_failure:
            before=core_calls;before_writes=len(writes);before_reads=len(reads);before_returns=len(core_returns)
            second=invoke()
            assert core_calls==before and len(writes)==before_writes
            assert len(core_returns)==before_returns
            if fixed:assert len(reads)==before_reads
            assert second==(error|6 if fixed else 0)
            assert bytes(u.mem_read(obj+0x181,1))==b'\1' # preserve shutdown ownership
            assert bytes(u.mem_read(obj+0x180,1))==(b'\0' if fixed else b'\1')
        results.append(dict(image=image_name,scenario=name,status=hex(first),core_calls=core_calls,
                            core_returns=[hex(v) for v in core_returns],trace_debug_calls=trace_debug_calls,
                            trace_returns=[(hex(site),hex(v)) for site,v in trace_returns],
                            writes=[(hex(at),hex(v)) for at,v in writes]))
    a.out.mkdir(exist_ok=False,parents=True)
    report=dict(passed=True,original_sha256=hashlib.sha256(original).hexdigest(),
                patched_sha256=hashlib.sha256(patched).hexdigest(),
                trace_core=a.trace_core,poll_fixed_sha256=hashlib.sha256(poll_patched).hexdigest(),
                changes_over_core_fix=[(hex(lo),hex(hi)) for lo,hi in ranges],cases=results,
                source_sha256={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in sources},
                hardware_verified=False)
    (a.out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS',len(results),'original ARM64 EventHandler cases; no retry, ABI/stack preserved; mutation refused')
    print(json.dumps({k:report[k] for k in ['patched_sha256','changes_over_core_fix']},indent=2))

if __name__=='__main__':main()
