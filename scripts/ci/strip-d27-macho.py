#!/usr/bin/env python3
"""Strip using LLVM23 and reject the LINKEDIT misalignment reproduced in055."""
import os
from pathlib import Path
import struct
import subprocess
import sys

def check(path):
    data=Path(path).read_bytes()
    if len(data)<32 or struct.unpack_from('<I',data)[0]!=0xfeedfacf:
        raise ValueError('Expected thin64-bit Mach-O: '+str(path))
    at=32;end=32+struct.unpack_from('<I',data,20)[0];linkedit=None;tables=[]
    if end>len(data):raise ValueError('Load commands exceed file')
    for _ in range(struct.unpack_from('<I',data,16)[0]):
        cmd,size=struct.unpack_from('<II',data,at)
        if size<8 or size%8 or at+size>end:raise ValueError('Invalid load command')
        if cmd==0x19 and data[at+8:at+24].rstrip(b'\0')==b'__LINKEDIT':
            fileoff,filesize=struct.unpack_from('<QQ',data,at+40);linkedit=(fileoff,fileoff+filesize)
        if cmd==2:
            if size!=24:raise ValueError('Invalid LC_SYMTAB')
            symoff,nsyms,stroff,strsize=struct.unpack_from('<4I',data,at+8)
            if symoff%8 or stroff%8:raise ValueError('Misaligned64-bit symbol/string table')
            tables=[(symoff,nsyms*16),(stroff,strsize)]
        at+=size
    if at!=end or linkedit is None or not tables:raise ValueError('Missing LINKEDIT/symbol tables')
    for offset,size in tables:
        if not linkedit[0]<=offset<=offset+size<=min(linkedit[1],len(data)):
            raise ValueError('Symbol/string table outside LINKEDIT')

def main():
    args=sys.argv[1:]
    if len(args)!=2 or args[0]!='-x':raise SystemExit('Supported invocation: strip-d27-macho.py -x FILE')
    tool=os.environ.get('PDX_MACHO_STRIP','/usr/lib/llvm-23/bin/llvm-strip')
    check(args[1])
    subprocess.run([tool,*args],check=True)
    check(args[1])

if __name__=='__main__':main()
