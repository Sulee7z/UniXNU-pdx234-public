#!/usr/bin/env python3
"""Apply exact official Skip Setup preferences to a private2GiB D27 RAM seed.

The original seed/OS/phone stay unchanged. Short APFS utility guests edit only
the new host copy with a hard45-second deadline each; no iOS/XNU guest boot.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
TOOLS=Path('/root/unixnu-build/venus-apfs-tools')
OFFICIAL=Path('/mnt/f/UniXNU-Port-artifacts/platform069-20261118/UniXNU/scripts/seed-data-skip-setup.py')
sys.path.insert(0,str(ROOT/'ci'))
from platform069.skip_setup import official_values,encode_preferences,PREFERENCES,BUILD,OFFICIAL_SHA
from platform067.integration import sha


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seed',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--official-tool',type=Path,default=OFFICIAL)
    parser.add_argument('--no-auto-dim',action='store_true',help='Explicit optional official setting; never enabled by default')
    args=parser.parse_args()
    if sha(args.seed)!='31ee5019fa0f94f09de1f450a85421d6bd5945b57ac9830897fc291e837fa480':
        raise ValueError('Exact pristine2GiB D27 seed required; no live/persistent user Data editing')
    args.out.mkdir(parents=True,exist_ok=False);out=args.out.resolve()
    values=official_values(args.official_tool,no_auto_dim=args.no_auto_dim)
    sys.path.insert(0,str(BASE/'sources/UniXNU/drivers/DarwinBoot/Test'));import packed_ramdisk
    logical,extents=packed_ramdisk.regions(args.seed.read_bytes())
    if logical!=2*1024**3:raise ValueError('Expected2GiB volatile seed')
    raw=out/'Data.raw'
    with raw.open('xb') as stream:
        stream.truncate(logical)
        for offset,data in extents:stream.seek(offset);stream.write(data)
    original_header=raw.open('rb').read(4096)
    container_uuid=str(uuid.UUID(bytes=original_header[72:88]))
    volume_uuids={bytes(data[i+240:i+256]) for _,data in extents
                  for i in range(0,len(data),4096) if data[i+32:i+36]==b'APSB'}
    if len(volume_uuids)!=1:raise ValueError('Ambiguous original seed volume identity')
    volume_uuid=str(uuid.UUID(bytes=volume_uuids.pop()))
    inputs=json.loads((TOOLS/'inputs.json').read_text())
    if sha(inputs['module'])!=inputs['module_sha256']:raise ValueError('Pinned APFS tool module differs')
    guest=out/'initramfs'
    for name in ('bin','mods','dev','proc','sys','tmp','mnt/data','payload'):(guest/name).mkdir(parents=True,exist_ok=True)
    for name in ('bin/busybox','mods/00.ko','mods/01.ko'):shutil.copyfile(TOOLS/'seed-attempt-1/initramfs'/name,guest/name)
    (guest/'bin/busybox').chmod(0o755)
    timings={}
    def utility(body,label,writable):
        text='''#!/bin/busybox sh
/bin/busybox --install -s /bin
set -eu
trap 'echo SONY_SKIP_SETUP_FAIL; poweroff -f' EXIT
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
insmod /mods/00.ko
insmod /mods/01.ko
mount -t apfs -o MODE,cknodes /dev/vda /mnt/data
'''.replace('MODE','readwrite' if writable else 'ro')+body+'''
cd /
sync
umount /mnt/data
echo SONY_SKIP_SETUP_PASS
trap - EXIT
poweroff -f
'''
        (guest/'init').write_text(text);(guest/'init').chmod(0o755)
        names=b'.\0'+b''.join(str(p.relative_to(guest)).encode()+b'\0' for p in sorted(guest.rglob('*')))
        cpio=out/(label+'.cpio')
        with cpio.open('xb') as stream:subprocess.run(['cpio','--null','-o','--format=newc'],input=names,cwd=guest,stdout=stream,stderr=subprocess.PIPE,check=True,timeout=15)
        cmd=['qemu-system-x86_64','-accel','tcg','-cpu','max','-m','512','-smp','1','-kernel',inputs['kernel'],
             '-initrd',str(cpio),'-append','console=ttyS0 quiet rdinit=/init panic=-1','-display','none','-monitor','none',
             '-serial','stdio','-nic','none','-no-reboot','-drive',f'file={raw},format=raw,if=virtio'+('' if writable else ',readonly=on')]
        (out/(label+'-command.json')).write_text(json.dumps(cmd,indent=2)+'\n');started=time.monotonic()
        with (out/(label+'.log')).open('x') as stream:d=subprocess.run(cmd,stdout=stream,stderr=subprocess.STDOUT,timeout=45)
        timings[label]=time.monotonic()-started;log=(out/(label+'.log')).read_text()
        if d.returncode or 'SONY_SKIP_SETUP_PASS' not in log or 'SONY_SKIP_SETUP_FAIL' in log:raise RuntimeError(log[-10000:])
        return log
    read='''test -d /mnt/data/mobile
cd /mnt/data
find . -type f -exec sha256sum '{}' ';' | sort > /tmp/source.sha
echo SOURCE_HASHES_BEGIN
cat /tmp/source.sha
echo SOURCE_HASHES_END
'''
    for name in PREFERENCES:
        read+=f'echo PREF_BEGIN_{name}\nif [ -f mobile/Library/Preferences/{name}.plist ]; then base64 mobile/Library/Preferences/{name}.plist; fi\necho PREF_END_{name}\n'
    before=utility(read,'read-original',False);existing={}
    for name in PREFERENCES:
        encoded=before.split('PREF_BEGIN_'+name+'\n',1)[1].split('PREF_END_'+name,1)[0].strip()
        existing[name]=plistlib.loads(base64.b64decode(encoded)) if encoded else {}
        if not isinstance(existing[name],dict):raise ValueError('Source preference is not a dictionary')
    blobs=encode_preferences(existing,values)
    for name,data in blobs.items():(guest/'payload'/(name+'.plist')).write_bytes(data)
    write='''cd /mnt/data
mkdir -p mobile/Library/Preferences
'''
    for name in PREFERENCES:
        write+=f'cp /payload/{name}.plist mobile/Library/Preferences/{name}.plist\nchown 501:501 mobile/Library/Preferences/{name}.plist\nchmod 600 mobile/Library/Preferences/{name}.plist\ncmp /payload/{name}.plist mobile/Library/Preferences/{name}.plist\n'
        write+=f'echo TARGET_PREF_BEGIN_{name}\nbase64 mobile/Library/Preferences/{name}.plist\necho TARGET_PREF_END_{name}\nstat -c "%u:%g:%a" mobile/Library/Preferences/{name}.plist\n'
    write+='''chown 501:501 mobile/Library/Preferences
for sub in Bundle Data/System Shared/SystemGroup Temp; do mkdir -p "containers/$sub"; chmod 755 "containers/$sub"; done
find . -type f -exec sha256sum '{}' ';' | sort > /tmp/target.sha
echo TARGET_HASHES_BEGIN
cat /tmp/target.sha
echo TARGET_HASHES_END
'''
    after=utility(write,'write-verified',True)
    def file_hashes(text,start,end):
        rows=text.split(start+'\n',1)[1].split(end,1)[0].strip().splitlines();result={}
        for row in rows:
            digest,path=row.split('  ',1)
            if len(digest)!=64 or not path.startswith('./') or path in result:raise ValueError('Invalid file manifest')
            result[path]=digest
        return result
    old=file_hashes(before,'SOURCE_HASHES_BEGIN','SOURCE_HASHES_END');new=file_hashes(after,'TARGET_HASHES_BEGIN','TARGET_HASHES_END')
    allowed={'./mobile/Library/Preferences/'+name+'.plist' for name in PREFERENCES}
    changed={path for path in old.keys()|new.keys() if old.get(path)!=new.get(path)}
    if not changed<=allowed or not old.keys()<=new.keys():raise ValueError('Unrelated seed file changed')
    for name,data in blobs.items():
        encoded=after.split('TARGET_PREF_BEGIN_'+name+'\n',1)[1].split('TARGET_PREF_END_'+name,1)[0].strip()
        if base64.b64decode(encoded)!=data:raise ValueError('Preference readback differs')
        target=plistlib.loads(data)
        for key,value in values[name].items():
            if target.get(key)!=value:raise ValueError('Official preference value differs')
    with (out/'apfsck.log').open('x') as stream:subprocess.run([inputs['apfsck'],str(raw)],stdout=stream,stderr=subprocess.STDOUT,check=True,timeout=20)
    seed=out/'scratch-data-skip-setup.img';metadata=packed_ramdisk.pack(raw,seed)
    if sha(args.seed)!='31ee5019fa0f94f09de1f450a85421d6bd5945b57ac9830897fc291e837fa480' or metadata['bytes']!=logical:
        raise ValueError('Original seed or logical capacity changed')
    _,encoded_extents=packed_ramdisk.regions(seed.read_bytes());uuids={bytes(data[i+240:i+256]) for _,data in encoded_extents for i in range(0,len(data),4096) if data[i+32:i+36]==b'APSB'}
    if uuids!={uuid.UUID(volume_uuid).bytes} or raw.open('rb').read(4096)[72:88]!=uuid.UUID(container_uuid).bytes:
        raise ValueError('Seed volume/container UUID changed')
    record=dict(passed=True,skip_setup=True,seed=str(seed),sha256=sha(seed),source_seed=str(args.seed),source_seed_sha256=sha(args.seed),
        logical_bytes=logical,encoded_bytes=seed.stat().st_size,build=BUILD,no_auto_dim=args.no_auto_dim,
        official_tool=str(args.official_tool),official_tool_sha256=OFFICIAL_SHA,official_preferences=values,source_preferences=existing,
        changed_files=sorted(changed),unrelated_file_bytes_preserved=True,uid_gid_mode_verified=True,
        volume_uuid=volume_uuid,container_uuid=container_uuid,uuid_preserved=True,apfsck_passed=True,
        guest_deadline_seconds=45,guest_elapsed_seconds=timings,original_source_unchanged=True,
        activation_record_or_server_modified=False,device_operations=False,hardware_verified=False)
    (out/'result.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
