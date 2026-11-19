#!/usr/bin/env python3
"""Bounded read-only D27 CoreBrightness slices, never executable patching."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess

ROOT=Path(__file__).resolve().parents[3]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
INDEX=BASE/'photo026-cache-002/index.json'
MAIN_SHA='21d3a213c3a1a62cf37325cebf2335f75cbf1e7a4d9548049c7cee2695903b40'
IMAGE='/System/Library/PrivateFrameworks/CoreBrightness.framework/CoreBrightness'

def sha(p):
    with Path(p).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

class Slices:
    def __init__(self,out,image):
        self.out=out;self.disk=image;self.index=json.loads(INDEX.read_text());self.batch=0;self.rows=[]
        self.root=out/'initramfs'
        shutil.copytree(BASE/'photo026-cache-002/initramfs',self.root)
        self.tools=json.loads(Path('/root/unixnu-build/venus-apfs-tools/inputs.json').read_text())
        if sha(self.tools['module'])!=self.tools['module_sha256']:raise ValueError('APFS module changed')
    def location(self,va,length):
        for h in self.index['headers']:
            for m in h['maps']:
                if m['va']<=va and va+length<=m['va']+m['size']:return h['file'],m['offset']+va-m['va']
        raise ValueError(f'Unmapped D27 cache address{va:x}+{length:x}')
    def extract(self,requests):
        self.batch+=1;folder=self.out/f'batch-{self.batch:02}';folder.mkdir()
        rows=[];cursor=0;commands=[]
        for name,va,length in requests:
            if not 0<length<=8<<20:raise ValueError('Bounded slices only')
            filename,off=self.location(va,length)
            if not filename.startswith('dyld_shared_cache_arm64e') or '/' in filename:raise ValueError('Unsafe filename')
            aligned=off&~4095;size=(off-aligned+length+4095)&~4095
            commands.append(f'dd if="$cache/{filename}" of=/dev/vdb bs=4096 skip={aligned//4096} count={size//4096} seek={cursor//4096} conv=notrunc 2>/dev/null')
            rows.append(dict(name=name,va=va,length=length,file=filename,offset=off,aligned_offset=aligned,aligned_bytes=size,output_offset=cursor));cursor+=size
        if cursor>32<<20:raise ValueError('Oversized extraction')
        raw=folder/'slices.raw'
        with raw.open('xb') as stream:stream.truncate(cursor)
        init='''#!/bin/busybox sh
/bin/busybox --install -s /bin
set -eu
trap 'echo SONY_CB_FAIL; poweroff -f' EXIT
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
insmod /mods/00.ko
insmod /mods/01.ko
mount -t apfs -o ro /dev/vda /mnt/os
cache=/mnt/os/System/Library/Caches/com.apple.dyld
echo 'MAIN_SHA  '"$cache/dyld_shared_cache_arm64e" | sha256sum -c -
'''.replace('MAIN_SHA',MAIN_SHA)+'\n'.join(commands)+'''
sync
umount /mnt/os
trap - EXIT
echo SONY_CB_PASS
poweroff -f
'''
        (self.root/'init').write_text(init)
        packed=folder/'initramfs.cpio'
        names=b'.\0'+b''.join(str(p.relative_to(self.root)).encode()+b'\0' for p in sorted(self.root.rglob('*')))
        with packed.open('xb') as stream:subprocess.run(['cpio','--null','-o','--format=newc'],input=names,cwd=self.root,stdout=stream,stderr=subprocess.PIPE,check=True)
        command=['qemu-system-x86_64','-accel','tcg','-cpu','max','-m','512','-smp','1',
                 '-kernel',self.tools['kernel'],'-initrd',str(packed),'-append','console=ttyS0 quiet rdinit=/init panic=-1',
                 '-nographic','-monitor','none','-no-reboot','-nic','none',
                 '-drive',f'file={self.disk},format=raw,if=virtio,readonly=on',
                 '-drive',f'file={raw},format=raw,if=virtio']
        (folder/'command.json').write_text(json.dumps(command,indent=2)+'\n')
        with (folder/'guest.log').open('x') as stream:subprocess.run(command,stdout=stream,stderr=subprocess.STDOUT,check=True,timeout=45)
        log=(folder/'guest.log').read_text()
        if 'SONY_CB_PASS' not in log or 'SONY_CB_FAIL' in log:raise ValueError('Read-only APFS extraction failed')
        data=raw.read_bytes();answer=[]
        for row in rows:
            at=row['output_offset']+row['offset']-row['aligned_offset'];chunk=data[at:at+row['length']]
            if len(chunk)!=row['length']:raise ValueError('Short slice')
            row['sha256']=hashlib.sha256(chunk).hexdigest();answer.append(chunk)
        (folder/'receipt.json').write_text(json.dumps(rows,indent=2)+'\n');self.rows.extend(rows)
        return answer

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',required=True,type=Path)
    parser.add_argument('--systemos',type=Path,default=Path('/mnt/sony-oled-host-e/UniXNU-Port-artifacts/qemu-systemos-recovery-20261117-001/043-69730-712.dmg'))
    a=parser.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    mountpoint=Path('/mnt/sony-oled-host-e')
    if not a.systemos.exists() and str(a.systemos).startswith(str(mountpoint)+'/'):
        mountpoint.mkdir(exist_ok=True)
        if not os.path.ismount(mountpoint):subprocess.run(['mount','-t','drvfs','E:',str(mountpoint),'-o','ro'],check=True)
    if not a.systemos.is_file():raise ValueError('Read-only original SystemOS image unavailable')
    slices=Slices(a.out,a.systemos)
    row=next(r for r in slices.index['images'] if r['path']==IMAGE)
    header=slices.extract([('CoreBrightness.header',row['va'],16384)])[0]
    if struct.unpack_from('<I',header)[0]!=0xfeedfacf:raise ValueError('Original D27 image header differs')
    at=32;segments=[];sections=[];identity=None;uuid=None
    for _ in range(struct.unpack_from('<I',header,16)[0]):
        kind,size=struct.unpack_from('<II',header,at)
        if size<8 or at+size>len(header):raise ValueError('Invalid MachO load commands')
        if kind==0x19:
            name=header[at+8:at+24].split(b'\0')[0].decode();va,length,off,fs=struct.unpack_from('<4Q',header,at+24)
            segments.append(dict(name=name,va=va,size=length,fileoff=off,filesize=fs))
            for i in range(struct.unpack_from('<I',header,at+64)[0]):
                pos=at+72+i*80;sect=header[pos:pos+16].split(b'\0')[0].decode();seg=header[pos+16:pos+32].split(b'\0')[0].decode()
                addr,n=struct.unpack_from('<QQ',header,pos+32);sections.append(dict(segment=seg,name=sect,va=addr,size=n))
        elif kind==0x1b:uuid=header[at+8:at+24].hex()
        elif kind==0xd:
            pos=at+struct.unpack_from('<I',header,at+8)[0];identity=header[pos:header.index(0,pos)].decode()
        at+=size
    if identity!=IMAGE:raise ValueError('Original install-name differs')
    selected=[s for s in segments if s['filesize'] and s['name']!='__LINKEDIT']
    chunks=slices.extract([(s['name'],s['va'],s['filesize']) for s in selected])
    for segment,data in zip(selected,chunks):
        p=a.out/(segment['name']+'.bin');p.write_bytes(data);segment['copy']=str(p);segment['sha256']=sha(p)
    record=dict(image=IMAGE,uuid=uuid,index=str(INDEX),index_sha256=sha(INDEX),cache_main_sha256=MAIN_SHA,
                systemos=str(a.systemos),systemos_bytes=a.systemos.stat().st_size,segments=selected,sections=sections,
                slices=slices.rows,extraction_readonly=True,guest_deadline_seconds=45,executable_modified=False,
                objc_abi_qualified=False)
    (a.out/'image.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))

if __name__=='__main__':main()
