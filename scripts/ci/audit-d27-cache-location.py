#!/usr/bin/env python3
"""Observe both original D27 disks in an isolated, read-only Linux APFS guest."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

DEVICE = Path(__file__).resolve().parents[2]
TOOLS = Path('/root/unixnu-build/venus-apfs-tools')


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    out = args.out.resolve()
    tools = json.loads((TOOLS/'inputs.json').read_text())
    module = Path(tools['module'])
    if sha(module) != tools['module_sha256']:
        raise ValueError('Prepared APFS module identity changed')
    policies = json.loads((DEVICE/'out/d27-owner-policies-001/report.json').read_text())
    disks = []
    for component in ('OS', 'SystemOS'):
        rows = [row for row in policies['policies'] if row['component'] == component]
        if len(rows) != 1:
            raise ValueError('Ambiguous D27 disk: '+component)
        row = rows[0]
        image = Path(row['image'])
        if (not row['verification']['real_c_signature_and_block_verification'] or
                image.stat().st_size != row['verification']['image_bytes']):
            raise ValueError('Original verified image unavailable: '+component)
        with image.open('rb') as stream:
            fingerprint = hashlib.sha256(stream.read(512)).hexdigest()
        disks.append(dict(component=component, image=str(image),
                          volume_uuid=row['verification']['volume_uuid'],
                          first_sector_sha256=fingerprint, full_image_rehashed=False))
    root = out/'initramfs'
    shutil.copytree(DEVICE/'out/d27-systemos-cache-inventory-002/initramfs', root)
    init = '''#!/bin/busybox sh
/bin/busybox --install -s /bin
set -eu
set -o pipefail
trap 'echo CACHE_AUDIT_FAIL; poweroff -f' EXIT
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
insmod /mods/00.ko
insmod /mods/01.ko
for spec in OS:vda SystemOS:vdb; do
    role=${spec%:*}
    disk=${spec#*:}
    echo "DISK_BEGIN $role /dev/$disk"
    dd if=/dev/$disk bs=512 count=1 2>/dev/null | sha256sum
    mount -t apfs -o ro /dev/$disk /mnt/os
    cat /proc/mounts
    cache=/mnt/os/System/Library/Caches/com.apple.dyld
    if [ -f "$cache/dyld_shared_cache_arm64e" ]; then
        echo "CACHE_LOCATION $role PRESENT"
        ls -l "$cache"
        dd if="$cache/dyld_shared_cache_arm64e" bs=512 count=1 2>/dev/null | sha256sum
    else
        echo "CACHE_LOCATION $role MISSING"
        ls -ld "$cache" 2>/dev/null || true
    fi
    umount /mnt/os
    echo "DISK_END $role"
done
trap - EXIT
echo CACHE_AUDIT_PASS
poweroff -f
'''
    (root/'init').write_text(init)
    (root/'init').chmod(0o755)
    names = b'.\0'+b''.join(str(path.relative_to(root)).encode()+b'\0' for path in sorted(root.rglob('*')))
    packed = out/'initramfs.cpio'
    with packed.open('xb') as stream:
        subprocess.run(['cpio', '--null', '-o', '--format=newc'], input=names, cwd=root,
                       stdout=stream, stderr=subprocess.PIPE, check=True)
    command = ['qemu-system-x86_64', '-accel', 'tcg', '-cpu', 'max', '-m', '512', '-smp', '1',
               '-kernel', tools['kernel'], '-initrd', str(packed), '-append',
               'console=ttyS0 quiet rdinit=/init panic=-1', '-nographic', '-no-reboot', '-nic', 'none']
    for disk in disks:
        command += ['-drive', 'file='+disk['image']+',format=raw,if=virtio,readonly=on']
    (out/'command.json').write_text(json.dumps(command, indent=2)+'\n')
    with (out/'guest.log').open('x') as stream:
        done = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=120,
                              env=dict(os.environ, TMPDIR=str(out)))
    log = (out/'guest.log').read_text()
    passed = done.returncode == 0 and 'CACHE_AUDIT_PASS' in log and 'CACHE_AUDIT_FAIL' not in log
    for disk in disks:
        role = disk['component']
        segment = log.split('DISK_BEGIN '+role+' ', 1)[-1].split('DISK_END '+role, 1)[0]
        disk['guest_first_sector_matches'] = disk['first_sector_sha256']+'  -' in segment
        disk['cache_present'] = 'CACHE_LOCATION '+role+' PRESENT' in segment
        passed = passed and disk['guest_first_sector_matches']
    report = dict(passed=passed, disks=disks, guest='isolated Linux APFS; not XNU runtime acceptance',
                  original_disks_readonly=True, kernel_sha256=sha(Path(tools['kernel'])),
                  module_sha256=sha(module), device_operations=False)
    (out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if passed else 1)


if __name__ == '__main__':
    main()
