#!/usr/bin/env python3
"""Replace only the source-built DarwinBoot PE in the retained Sony firmware."""
import hashlib
import importlib.util
import json
import lzma
from pathlib import Path
import struct
import uuid
import argparse

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
GUID='1b64af87-8415-4b57-9b16-680d70913b9f'


def files(data):
    at=(struct.unpack_from('<H',data,48)[0]+7)&-8
    while at+24<len(data) and data[at:at+24]!=b'\xff'*24:
        size=int.from_bytes(data[at+20:at+23],'little')
        assert size>=24 and at+size<=len(data)
        yield at,size,str(uuid.UUID(bytes_le=bytes(data[at:at+16])))
        at=(at+size+7)&-8


def checksum(blob):
    blob[16]=0
    blob[17]=(-sum(blob[24:]))&255 if blob[19]&0x40 else 0xaa
    header=bytearray(blob[:24]);header[17]=header[23]=0
    blob[16]=(-sum(header))&255


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build',type=Path,default=BASE/'firmware-high-memory-002')
    build=parser.parse_args().build
    spec=importlib.util.spec_from_file_location('fv',Path(__file__).resolve().parents[1]/'check-firmware-services.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    original=(BASE/'firmware-retained-010.fd').read_bytes()
    built=(build/'SILICIUM_UEFI.fd').read_bytes()
    before=m.volume_files(original);new=m.volume_files(built)
    pe=next(body for kind,body in new[GUID] if kind==0x10)
    outer=next((at,n) for at,n,g in files(original) if original[at+18]==0x0b)
    at,n=outer;ffs=original[at:at+n];sec=ffs[24:];assert sec[3]==2
    inner=bytearray(lzma.decompress(sec[24:],format=lzma.FORMAT_ALONE))
    pos=0
    while inner[pos+3]!=0x17:pos=(pos+int.from_bytes(inner[pos:pos+3],'little')+3)&-4
    fv_start=pos+4;fv=inner[fv_start:]
    foff,flen=next((a,n) for a,n,g in files(fv) if g==GUID)
    changed=bytearray(fv[foff:foff+flen]);s=24
    while changed[s+3]!=0x10:s=(s+int.from_bytes(changed[s:s+3],'little')+3)&-4
    size=int.from_bytes(changed[s:s+3],'little');assert size-4==len(pe)
    changed[s+4:s+size]=pe;checksum(changed)
    inner[fv_start+foff:fv_start+foff+flen]=changed
    packed=bytearray(lzma.compress(inner,format=lzma.FORMAT_ALONE,preset=6));packed[5:13]=struct.pack('<Q',len(inner))
    newsec=bytearray(sec[:24]);newsec[:3]=(24+len(packed)).to_bytes(3,'little');newsec+=packed
    replacement=bytearray(ffs[:24])+newsec;replacement[20:23]=len(replacement).to_bytes(3,'little');checksum(replacement)
    assert not any(x!=255 for x in original[(at+n+7)&-8:])
    result=original[:at]+replacement+bytes([255])*(len(original)-at-len(replacement))
    after=m.volume_files(result);assert before.keys()==after.keys()
    changed_guids=[g for g in before if before[g]!=after[g]]
    assert set(changed_guids)=={GUID,'9e21fd93-9c72-4c15-8c4b-e77f1db2d792'}
    assert m.inspect_firmware(result)['passed']
    out=build/'SILICIUM_RETAINED.fd';out.write_bytes(result)
    receipt=dict(fd=str(out),sha256=hashlib.sha256(result).hexdigest(),changed_modules=['DarwinBoot'],
                 entry_base=0x980000000,entry_bytes=0x180000000,retained_other_modules=True,hardware_verified=False)
    (out.parent/'retained-result.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt,indent=2))


if __name__=='__main__':main()
