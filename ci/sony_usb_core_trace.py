"""Add bounded call-boundary diagnostics to the qualified core-error PE."""
import hashlib
from pathlib import Path
import struct
import subprocess
import tempfile
from sony_usb_core_errors import adapt_pe as fix_errors, ORIGINAL_SHA
from sony_usb_poll_errors import adapt_pe as fix_poll

BASE=0x16600
SITES=[(0x633c,'TraceConnect',0xec0c),(0x38b4,'TraceInitialize',0x8a60),
       (0x38dc,'TraceResetWrite',0xc138),(0x38f0,'TraceResetWait',0xab2c),
       (0x3d34,'TraceEventAllocate',0xebc8),(0x3d5c,'TraceEventConfigure',0x8cec),
       (0x3f04,'TraceSetup',0x6bb8)]
# Trace every existing direct MMIO operation in core init, not newly introduced
# hardware reads. Include FIFO accesses, EP commands/waits and TRB allocation.
CORE_CALLS={
    0xc0c4:[0x38d0,0x38fc,0x3910,0x3930,0x394c,0x3964,0x3970,0x397c,0x3988,
            0x399c,0x39b8,0x39cc,0x39dc,0x39f0,0x3a0c,0x3a14,0x3a3c,0x3a58,
            0x3ba4,0x3bac,0x3bc8,0x3bdc,0x3bf4,0x3c0c,0x3c1c,0x3c94,0x3cb0,0x635c],
    0xc138:[0x3908,0x3920,0x393c,0x395c,0x39a8,0x39c4,0x39e8,0x3a4c,
            0x3bd4,0x3bec,0x3c04,0x3c28,0x3ca8,0x3cc0,0x3efc],
    0x92cc:[0x3cf4,0x3e0c,0x3e60],0xab2c:[0x3d14,0x3e28,0x3e78],
    0xebc8:[0x3e9c],0x8e64:[0x3ed8],0x3880:[0x6344],0xd170:[0x8ac8]}
for target,sites in CORE_CALLS.items():
    SITES.extend((site,'Trace_'+hex(site)[2:],target) for site in sites)
SITES.append((0x637c,'TraceRunStop',0xc138))
TAIL_SITES={0x637c}
TARGETS={'VendorConnect':0xec0c,'VendorRead':0xc0c4,'VendorInitialize':0x8a60,'VendorWrite':0xc138,
         'VendorWait':0xab2c,'VendorAllocate':0xebc8,'VendorEventConfigure':0x8cec,
         'VendorSetup':0x6bb8,'VendorDebugPrint':0xc1b0}

def adapt_pe(original):
    if hashlib.sha256(original).hexdigest()!=ORIGINAL_SHA:raise ValueError('Unknown USBFN trace input')
    raw=fix_poll(original)
    with tempfile.TemporaryDirectory(prefix='sony-core-trace-') as directory:
        work=Path(directory)
        template=Path(__file__).with_suffix('.S').read_text()
        marker='// Generated call-site wrappers precede CoreTrace in the assembly input.'
        wrappers='\n'.join('WRAPPER '+name+', '+hex(site)+', Target_'+hex(target)[2:] for site,name,target in SITES)
        template=template.replace(marker,wrappers+'\n'+marker)
        (work/'trace.S').write_text(template)
        subprocess.run(['clang','--target=aarch64-none-elf','-c',str(work/'trace.S'),'-o',str(work/'trace.o')],check=True)
        cmd=['ld.lld','-Ttext='+hex(BASE),'-e','TraceConnect',str(work/'trace.o'),'-o',str(work/'trace.elf')]
        for name,address in TARGETS.items():cmd+=['--defsym='+name+'='+hex(address)]
        for target in sorted({target for _,_,target in SITES}):cmd+=['--defsym=Target_'+hex(target)[2:]+'='+hex(target)]
        subprocess.run(cmd,check=True)
        subprocess.run(['llvm-objcopy','--only-section=.text','-O','binary',str(work/'trace.elf'),str(work/'trace.bin')],check=True)
        blob=(work/'trace.bin').read_bytes()
        symbols={line.split()[2]:int(line.split()[0],16) for line in subprocess.check_output(['llvm-nm','--defined-only',str(work/'trace.elf')],text=True).splitlines() if len(line.split())==3}
    if BASE+len(blob)>0x16f00 or raw[BASE:BASE+len(blob)]!=bytes(len(blob)):
        raise ValueError('Trace overlaps code or error-return stub')
    result=bytearray(raw);result[BASE:BASE+len(blob)]=blob
    if raw[0xec0c:0xec10]!=bytes.fromhex('40000034'):raise ValueError('Unknown QSCRATCH entry')
    struct.pack_into('<I',result,0xec0c,0x14000000|(((symbols['TraceConnectBody']-0xec0c)//4)&0x3ffffff))
    for site,name,target in SITES:
        opcode=0x14000000 if site in TAIL_SITES else 0x94000000
        expected=opcode|(((target-site)//4)&0x3ffffff)
        if struct.unpack_from('<I',raw,site)[0]!=expected:raise ValueError('Unknown trace call site')
        struct.pack_into('<I',result,site,opcode|(((symbols[name]-site)//4)&0x3ffffff))
    return bytes(result)
