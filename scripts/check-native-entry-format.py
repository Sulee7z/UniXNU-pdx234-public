#!/usr/bin/env python3
"""Refuse a fileset-prelink input as a standalone arm64e boot executable."""
import argparse
import json
from pathlib import Path
import struct


def inspect(data):
    if len(data)<32:raise ValueError('Truncated Mach-O header')
    magic,cpu,subtype,kind,count,size=struct.unpack_from('<6I',data)
    if magic!=0xfeedfacf or cpu!=0x100000c:raise ValueError('Expected AArch64 Mach-O')
    if count>4096 or 32+size>len(data):raise ValueError('Invalid load-command extent')
    if kind==12:return {'format':'fileset','standalone_native_only':False}
    if kind!=2:raise ValueError('Expected MH_EXECUTE or MH_FILESET')
    offset=32
    chained=threaded=False
    for _ in range(count):
        if offset+8>32+size:raise ValueError('Truncated load command')
        command,length=struct.unpack_from('<II',data,offset)
        if length<8 or offset+length>32+size:raise ValueError('Invalid load command')
        chained|=command==0x80000034
        if command==0x19:
            if length<72:raise ValueError('Truncated segment command')
            nsects=struct.unpack_from('<I',data,offset+64)[0]
            if 72+80*nsects>length:raise ValueError('Truncated section table')
            for index in range(nsects):
                start=offset+72+80*index
                name=data[start:start+16].rstrip(b'\0')
                segment=data[start+16:start+32].rstrip(b'\0')
                threaded|=(name,segment)==(b'__thread_starts',b'__TEXT')
        offset+=length
    if offset!=32+size:raise ValueError('Load-command size mismatch')
    if subtype&0xff==2 and (chained or not threaded):
        raise ValueError('Standalone arm64e needs __TEXT,__thread_starts. Chained input belongs to fileset prelink.')
    return {'format':'standalone-threaded' if threaded else 'standalone-arm64',
            'standalone_native_only':True,'original_kexts_added':False,'springboard_verified':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kernel',type=Path)
    args=parser.parse_args()
    try:record=inspect(args.kernel.read_bytes())
    except (OSError,ValueError,struct.error) as error:parser.exit(1,str(error)+'\n')
    print(json.dumps(record,indent=2))


if __name__=='__main__':main()
