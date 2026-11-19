#!/usr/bin/env python3
"""Inspect the captured Data copy with a separate read-only Linux APFS guest."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--raw',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    tools=Path('/root/unixnu-build/venus-apfs-tools')
    inputs=json.loads((tools/'inputs.json').read_text())
    if sha(inputs['module'])!=inputs['module_sha256']:raise ValueError('Retained APFS inspection module differs')
    a.out.mkdir(parents=True,exist_ok=False)
    ramfs=a.out/'initramfs'
    for name in ('bin','mods','proc','sys','dev','tmp','mnt/data'):(ramfs/name).mkdir(parents=True,exist_ok=True)
    for name in ('bin/busybox','mods/00.ko','mods/01.ko'):shutil.copyfile(tools/'seed-attempt-1/initramfs'/name,ramfs/name)
    (ramfs/'bin/busybox').chmod(0o755)
    body='''#!/bin/busybox sh
/bin/busybox --install -s /bin
set -eu
trap 'echo D27_DATA_INSPECTION_FAIL; poweroff -f' EXIT
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
insmod /mods/00.ko
insmod /mods/01.ko
mount -t apfs -o ro,cknodes /dev/vda /mnt/data
echo D27_DATA_INSPECTION_BEGIN
df -k /mnt/data
find /mnt/data -maxdepth 8 -iname '*launchservices*' -exec ls -ldn '{}' ';'
find /mnt/data -maxdepth 8 -iname '*lsd*' -exec ls -ldn '{}' ';'
find /mnt/data -maxdepth 8 -iname '*csstore*' -exec ls -ldn '{}' ';'
find /mnt/data/containers /mnt/data/db -maxdepth 5 -name '*.plist' -exec ls -ln '{}' ';' 2>/dev/null | head -n 160
du -k /mnt/data/mobile/Library/Caches /mnt/data/mobile/Library/Logs /mnt/data/containers /mnt/data/db 2>/dev/null | sort -n | tail -n 70
echo D27_DATA_INSPECTION_END
umount /mnt/data
echo D27_DATA_INSPECTION_PASS
trap - EXIT
poweroff -f
'''
    (ramfs/'init').write_text(body);(ramfs/'init').chmod(0o755)
    packed=a.out/'initramfs.cpio'
    names=b'.\0'+b''.join(str(path.relative_to(ramfs)).encode()+b'\0' for path in sorted(ramfs.rglob('*')))
    with packed.open('xb') as stream:
        subprocess.run(['cpio','--null','-o','--format=newc'],input=names,cwd=ramfs,stdout=stream,stderr=subprocess.PIPE,check=True)
    command=['qemu-system-x86_64','-accel','tcg','-cpu','max','-m','1024','-smp','2',
        '-kernel',inputs['kernel'],'-initrd',str(packed),'-append','console=ttyS0 quiet rdinit=/init panic=-1',
        '-display','none','-monitor','none','-serial','stdio','-nic','none','-no-reboot',
        '-drive',f'file={a.raw},format=raw,if=virtio,readonly=on']
    before=sha(a.raw)
    with (a.out/'guest.log').open('x') as stream:
        done=subprocess.run(command,stdout=stream,stderr=subprocess.STDOUT,timeout=120,env=dict(os.environ,TMPDIR=str(a.out)))
    log=(a.out/'guest.log').read_text()
    passed=done.returncode==0 and 'D27_DATA_INSPECTION_PASS' in log and 'D27_DATA_INSPECTION_FAIL' not in log
    result=dict(command=command,read_only=True,raw_sha256=before,raw_unchanged=sha(a.raw)==before,
        passed=passed,original_d27_apfs_qualification=False,device_operations=False)
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(log[log.find('D27_DATA_INSPECTION_BEGIN'):][-20000:])
    if not passed:raise SystemExit(1)


if __name__=='__main__':main()
