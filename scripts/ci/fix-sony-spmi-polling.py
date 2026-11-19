#!/usr/bin/env python3
"""Apply the source-qualified polling-only init delta to the exact Sony SPMI PE.

The vendor library is statically linked into the retained PE. One branch skips
the PIC takeover loop after hasInterruptSupport=FALSE, retaining real bus init,
cache update, lock setup and all transaction/error paths. No exception bypass.
"""
import argparse
import hashlib
import importlib.util
import json
import lzma
from pathlib import Path
import struct

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
GUID='2a7b4bef-80cd-49e1-b473-374ba4d673fc'
ORIGINAL='b5e82b75c9f9da5188aee8cc702d8ac9b48eb2f7576aa2136c08c155c0ea34ed'


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def adapt_source(text):
    start=text.index('    for(bid = 0;',text.index('Spmi_Result SpmiBus_Init()'))
    end=text.index('    InitRecursiveLock ("SpmiBus"',start)
    loop=text[start:end]
    if 'SpmiPic_Init' not in loop or 'hasInterruptSupport = FALSE;' not in text[:start]:
        raise ValueError('Unexpected SPMI init source')
    return text[:start]+'''    /* Post-ABL polling client: do not take ownership of inherited PIC
     * interrupt channels. Bus/cache initialization above remains mandatory. */
    if (spmiDrv.pSpmiInfo->hasInterruptSupport) {
'''+loop+'    }\n\n'+text[end:]


def patch_pe(data):
    if hashlib.sha256(data).hexdigest()!=ORIGINAL:raise ValueError('SPMI binary identity changed')
    # Confirm the surrounding compiled source anchors, including false flag,
    # PIC call, lock call, and initialized=true store.
    for at,expected in [(0x2718,'1f050039'),(0x271c,'882643f9'),
                        (0x273c,'dc010094'),(0x2778,'68620b39')]:
        if data[at:at+4].hex()!=expected:raise ValueError(f'SPMI anchor differs {at:x}: '+data[at:at+4].hex())
    out=bytearray(data)
    struct.pack_into('<I',out,0x271c,0x14000000|((0x275c-0x271c)//4))
    return bytes(out)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--source',type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    source=a.source.read_text();adapted=adapt_source(source)
    (a.out/'SpmiBus.original.c').write_text(source);(a.out/'SpmiBus.polling.c').write_text(adapted)
    fv=module('fv',ROOT/'scripts/check-firmware-services.py')
    container=module('container',Path(__file__).with_name('retain-firmware-replace-loader.py'))
    original=(BASE/'firmware-usb-004/SILICIUM_UEFI.fd').read_bytes()
    before=fv.volume_files(original);pe=next(v for k,v in before[GUID] if k==0x10);fixed=patch_pe(pe)
    (a.out/'SPMI.original.efi').write_bytes(pe);(a.out/'SPMI.polling.efi').write_bytes(fixed)
    at,n=next((at,n) for at,n,g in container.files(original) if original[at+18]==0x0b)
    ffs=original[at:at+n];sec=ffs[24:];inner=bytearray(lzma.decompress(sec[24:],format=lzma.FORMAT_ALONE))
    pos=0
    while inner[pos+3]!=0x17:pos=(pos+int.from_bytes(inner[pos:pos+3],'little')+3)&-4
    begin=pos+4;off,length=next((i,n) for i,n,g in container.files(inner[begin:]) if g==GUID)
    changed=bytearray(inner[begin+off:begin+off+length]);s=24
    while changed[s+3]!=0x10:s=(s+int.from_bytes(changed[s:s+3],'little')+3)&-4
    size=int.from_bytes(changed[s:s+3],'little');assert size-4==len(fixed)
    changed[s+4:s+size]=fixed;container.checksum(changed)
    inner[begin+off:begin+off+length]=changed
    compressed=bytearray(lzma.compress(inner,format=lzma.FORMAT_ALONE,preset=6));compressed[5:13]=struct.pack('<Q',len(inner))
    newsec=bytearray(sec[:24]);newsec[:3]=(24+len(compressed)).to_bytes(3,'little');newsec+=compressed
    newffs=bytearray(ffs[:24])+newsec;newffs[20:23]=len(newffs).to_bytes(3,'little');container.checksum(newffs)
    assert all(b==255 for b in original[(at+n+7)&-8:]) and at+len(newffs)<=len(original)
    result=original[:at]+newffs+b'\xff'*(len(original)-at-len(newffs))
    after=fv.volume_files(result);assert before.keys()==after.keys()
    differences=[g for g in before if before[g]!=after[g]]
    assert set(differences)=={GUID,'9e21fd93-9c72-4c15-8c4b-e77f1db2d792'}
    assert fv.inspect_firmware(result)['passed']
    fd=a.out/'SILICIUM_UEFI.fd';fd.write_bytes(result)
    record=dict(fd=str(fd),sha256=hashlib.sha256(result).hexdigest(),source_fd_sha256=hashlib.sha256(original).hexdigest(),
        spmi_original_sha256=ORIGINAL,spmi_patched_sha256=hashlib.sha256(fixed).hexdigest(),
        patch_rva='0x271c',branch_target='0x275c',original_word=pe[0x271c:0x2720].hex(),patched_word=fixed[0x271c:0x2720].hex(),
        source_path=str(a.source),source_sha256=hashlib.sha256(a.source.read_bytes()).hexdigest(),
        changed_modules=['SPMI'],original_depex_preserved=True,other_modules_identical=True,
        hardware_verified=False)
    (a.out/'result.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
