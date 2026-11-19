"""Hash-qualified UsbfnDwcCoreInitImpl DWC error propagation correction.

Sony DWC_ERR_CHK logs DwcStatus and jumps to ON_EXIT without assigning the
EFI_STATUS variable. Four compiled error tails consequently return stale status
after DwcInitialize, STARTCFG, event-buffer or EP configuration failures.
Map these tails to EFI_DEVICE_ERROR; keep the original diagnostic
and all normal paths. This is not evidence of the handset shutdown cause.
"""
import hashlib
import struct

ORIGINAL_SHA='93b10001f468edfc6c8e2455674ef9099ae8c119e80c7ecf1ae6b32fcc0b6714'
TAILS={0x3b2c:bytes.fromhex('f5031faa'),0x3f58:bytes.fromhex('2b000014'),
       0x3fb8:bytes.fromhex('13000014'),0x3fe8:bytes.fromhex('07000014')}
CAVE=0x16f00

def branch(source,target):
    delta=target-source
    if delta%4 or not -(1<<27)<=delta<(1<<27):raise ValueError('Invalid branch')
    return struct.pack('<I',0x14000000|((delta//4)&0x3ffffff))

def adapt_pe(raw):
    if hashlib.sha256(raw).hexdigest()!=ORIGINAL_SHA:raise ValueError('Unknown Sony USBFN executable')
    nt=struct.unpack_from('<I',raw,60)[0]
    section=nt+24+struct.unpack_from('<H',raw,nt+20)[0]
    if raw[section:section+8]!=b'.text\0\0\0' or struct.unpack_from('<4I',raw,section+8)!=(0x16000,0x1000,0x16000,0x1000):
        raise ValueError('Unexpected USBFN executable mapping')
    if not struct.unpack_from('<I',raw,section+36)[0]&0x20000000:raise ValueError('Non-executable cave')
    # mov x21,#7; movk x21,#0x8000,lsl#48; b original common epilogue.
    stub=struct.pack('<II',0xd28000f5,0xf2f00015)+branch(CAVE+8,0x4004)
    if raw[CAVE:CAVE+len(stub)]!=bytes(len(stub)):raise ValueError('USB error cave occupied')
    result=bytearray(raw)
    for offset,expected in TAILS.items():
        if raw[offset:offset+4]!=expected:raise ValueError('USB error tail changed')
        result[offset:offset+4]=branch(offset,CAVE)
    result[CAVE:CAVE+len(stub)]=stub
    return bytes(result)
