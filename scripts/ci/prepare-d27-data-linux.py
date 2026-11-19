#!/usr/bin/env python3
"""Create an isolated experimental APFS Data seed from the actual D27 OS.

The documented macOS seed builder remains the reference. This local Linux
guest path preserves and verifies original file bytes, metadata and symlinks;
the resulting filesystem still requires original XNU/APFS runtime acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid

DEVICE = Path(__file__).resolve().parents[2]
TOOLS = Path('/root/unixnu-build/venus-apfs-tools')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    out = args.out.resolve()
    policies = json.loads((DEVICE/'out/d27-owner-policies-001/report.json').read_text())
    policy = next(row for row in policies['policies'] if row['component'] == 'OS')
    image = Path(policy['image'])
    if not policy['verification']['real_c_signature_and_block_verification']:
        raise ValueError('OS input is not verified')
    # Read the exact prepared tools, not another installation's seed or data.
    tool_inputs = json.loads((TOOLS/'inputs.json').read_text())
    module = Path(tool_inputs['module'])
    if hashlib.sha256(module.read_bytes()).hexdigest() != tool_inputs['module_sha256']:
        raise ValueError('APFS tool identity differs')
    raw = out/'Data.raw'
    with raw.open('xb') as stream:
        stream.truncate(1 << 30)
    container_uuid, volume_uuid = str(uuid.uuid4()).upper(), str(uuid.uuid4()).upper()
    command = [tool_inputs['mkapfs'], '-L', 'D27 Data', '-U', container_uuid, '-u', volume_uuid, str(raw)]
    with (out/'format.log').open('w') as log:
        subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT)
    initramfs = out/'initramfs'
    for name in ('bin', 'mods', 'dev', 'proc', 'sys', 'tmp', 'mnt/os', 'mnt/data'):
        (initramfs/name).mkdir(parents=True, exist_ok=True)
    base = TOOLS/'seed-attempt-1/initramfs'
    for name in ('bin/busybox', 'mods/00.ko', 'mods/01.ko'):
        shutil.copyfile(base/name, initramfs/name)
    (initramfs/'bin/busybox').chmod(0o755)
    init = '''#!/bin/busybox sh
/bin/busybox --install -s /bin
set -eu
trap 'echo D27_DATA_FAIL; poweroff -f' EXIT
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
insmod /mods/00.ko
insmod /mods/01.ko
mount -t apfs -o ro,cknodes /dev/vdb /mnt/os
mount -t apfs -o readwrite,cknodes /dev/vda /mnt/data
test -f /mnt/os/sbin/launchd
test -d /mnt/os/private/var
echo D27_DATA_SOURCE_BEGIN
sha256sum /mnt/os/sbin/launchd
cd /mnt/os/private/var
find . -path './staged_system_apps' -prune -o -type f -exec sha256sum '{}' ';' | sort > /tmp/source.sha
find . -path './staged_system_apps' -prune -o -mindepth 1 -exec stat -c '%u:%g:%a:%F:%n' '{}' ';' | sort > /tmp/source.meta
find . -path './staged_system_apps' -prune -o -type l -exec sh -c 'for x; do printf "%s:%s\\n" "$x" "$(readlink "$x")"; done' sh '{}' ';' | sort > /tmp/source.links
for x in * .[!.]* ..?*; do
  [ -e "$x" ] || [ -L "$x" ] || continue
  [ "$x" != staged_system_apps ] || continue
  cp -a "$x" /mnt/data/
done
cd /mnt/data
find . -mindepth 1 -exec stat -c '%u:%g:%a:%F:%n' '{}' ';' | sort > /tmp/target.meta
find . -type l -exec sh -c 'for x; do printf "%s:%s\\n" "$x" "$(readlink "$x")"; done' sh '{}' ';' | sort > /tmp/target.links
cmp /tmp/source.meta /tmp/target.meta
cmp /tmp/source.links /tmp/target.links
sha256sum -c /tmp/source.sha
echo D27_DATA_COPIED_AND_VERIFIED
for name in keybags tmp run containers/Bundle containers/Data/System containers/Shared/SystemGroup containers/Temp; do
  [ -e "$name" ] || mkdir -p "$name"
done
[ -e mobile/tmp ] || { mkdir -p mobile/tmp; chown 501:501 mobile/tmp; }
chmod 1777 tmp
echo "D27_DATA_SOURCE_FILES=$(wc -l < /tmp/source.sha)"
echo "D27_DATA_SOURCE_NODES=$(wc -l < /tmp/source.meta)"
sync
cd /
umount /mnt/data
umount /mnt/os
echo D27_DATA_UNMOUNTED
trap - EXIT
poweroff -f
'''
    (initramfs/'init').write_text(init)
    (initramfs/'init').chmod(0o755)
    packed = out/'initramfs.cpio'
    # cpio reads NUL-separated names, with no shell interpolation.
    names = b'.\0'+b''.join(str(path.relative_to(initramfs)).encode()+b'\0'
                             for path in sorted(initramfs.rglob('*')))
    with packed.open('wb') as stream:
        subprocess.run(['cpio', '--null', '-o', '--format=newc'], input=names, cwd=initramfs,
                       stdout=stream, stderr=subprocess.PIPE, check=True)
    command = ['qemu-system-x86_64', '-accel', 'tcg', '-cpu', 'max', '-m', '1536', '-smp', '2',
               '-kernel', tool_inputs['kernel'], '-initrd', str(packed), '-append',
               'console=ttyS0 quiet rdinit=/init panic=-1', '-nographic', '-no-reboot', '-nic', 'none',
               '-drive', f'file={raw},format=raw,if=virtio',
               '-drive', f'file={image},format=raw,if=virtio,readonly=on']
    (out/'qemu-command.json').write_text(json.dumps(command, indent=2)+'\n')
    with (out/'guest.log').open('w') as log:
        done = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=600,
                              env=dict(os.environ, TMPDIR=str(out)))
    log = (out/'guest.log').read_text()
    passed = done.returncode == 0 and 'D27_DATA_COPIED_AND_VERIFIED' in log and 'D27_DATA_UNMOUNTED' in log and 'D27_DATA_FAIL' not in log
    if passed:
        with (out/'apfsck.log').open('w') as stream:
            done = subprocess.run([tool_inputs['apfsck'], str(raw)], stdout=stream, stderr=subprocess.STDOUT)
        passed = done.returncode == 0
    report = dict(image=str(raw), bytes=raw.stat().st_size, volume_uuid=volume_uuid, container_uuid=container_uuid,
                  os_image=str(image), os_sha256=policy['verification']['image_sha256'],
                  linux_copy_and_apfsck_passed=passed, populated=passed, source='D27/24A446 original private/var',
                  excluded='staged_system_apps, same as official seed recipe',
                  original_source_mounted_readonly=True, uid_gid_mode_symlinks_and_file_sha_verified=passed,
                  original_xnu_apfs_mount_verified=False, experimental_linux_equivalent=True,
                  device_operations=False, reused_installation_seed=False)
    (out/'seed.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    if not passed:
        print(log[-6000:])
        raise SystemExit(1)


if __name__ == '__main__':
    main()
