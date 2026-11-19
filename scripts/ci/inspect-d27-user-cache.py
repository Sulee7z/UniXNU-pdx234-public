#!/usr/bin/env python3
"""Export bounded original D27 cache metadata/slices in a read-only Linux guest."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

TOOLS=Path('/root/unixnu-build/venus-apfs-tools')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--slices',type=Path);a=p.parse_args();out=a.out;out.mkdir(parents=True,exist_ok=False)
    inputs=json.loads((TOOLS/'inputs.json').read_text())
    assert hashlib.sha256(Path(inputs['module']).read_bytes()).hexdigest()==inputs['module_sha256']
    root=out/'initramfs';root.mkdir()
    for name in ('bin','mods'):
        shutil.copytree(TOOLS/'seed-attempt-1/initramfs'/name,root/name,symlinks=True)
    for name in ('dev','proc','sys','tmp','mnt/os'):(root/name).mkdir(parents=True,exist_ok=True)
    extra=''
    if a.slices:
        for i,item in enumerate(json.loads(a.slices.read_text())):
            name=item['file'];offset=item['offset'];size=item['bytes']
            assert name.startswith('dyld_shared_cache_arm64e') and all(c.isalnum() or c in '._' for c in name)
            assert offset>=0 and offset%4096==0 and 0<size<=2**20 and size%4096==0
            extra+=f'dd if="$cache/{name}" of=/tmp/export/slice-{i:03d}.bin bs=4096 skip={offset//4096} count={size//4096} 2>/dev/null\n'
    init='''#!/bin/busybox sh
/bin/busybox --install -s /bin
set -eu
trap 'echo INSPECT_FAIL; poweroff -f' EXIT
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
insmod /mods/00.ko
insmod /mods/01.ko
mount -t apfs -o ro /dev/vda /mnt/os
mkdir -p /tmp/export
cache=/mnt/os/System/Library/Caches/com.apple.dyld
test "$(stat -c %s "$cache/dyld_shared_cache_arm64e")" -le 1048576
cp "$cache/dyld_shared_cache_arm64e" /tmp/export/main.bin
for file in "$cache"/dyld_shared_cache_arm64e*; do
 stat -c '%n %s' "$file" >> /tmp/export/files.txt
 dd if="$file" of="/tmp/export/$(basename "$file").header" bs=4096 count=1 2>/dev/null
done
''' + extra + '''
find /mnt/os/System/Library/Extensions -maxdepth 2 -name '*AGX*' > /tmp/export/extensions.txt 2>/dev/null || true
cd /tmp/export
tar cf /dev/vdb .
sync
cd /
umount /mnt/os
trap - EXIT
echo INSPECT_PASS
poweroff -f
'''
    (root/'init').write_text(init);(root/'init').chmod(0o755)
    packed=out/'initramfs.cpio';names=b'.\0'+b''.join(str(x.relative_to(root)).encode()+b'\0' for x in sorted(root.rglob('*')))
    with packed.open('wb') as f:subprocess.run(['cpio','--null','-o','--format=newc'],input=names,cwd=root,stdout=f,stderr=subprocess.PIPE,check=True)
    disk=out/'export.raw'
    with disk.open('xb') as f:f.truncate(32<<20)
    source='/mnt/g/UniXNU-Port/tmp/pdx234-root-work-20261110/plain/043-69730-712.dmg'
    cmd=['qemu-system-x86_64','-accel','tcg','-cpu','max','-m','768','-smp','1','-kernel',inputs['kernel'],'-initrd',str(packed),
         '-append','console=ttyS0 quiet rdinit=/init panic=-1','-nographic','-no-reboot','-nic','none',
         '-drive',f'file={source},format=raw,if=virtio,readonly=on','-drive',f'file={disk},format=raw,if=virtio']
    with (out/'guest.log').open('w') as f:q=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=180)
    assert q.returncode==0 and 'INSPECT_PASS' in (out/'guest.log').read_text()
    with tarfile.open(disk) as tar:tar.extractall(out/'export',filter='data')
    print('PASS original cache export',out)


if __name__=='__main__':main()
