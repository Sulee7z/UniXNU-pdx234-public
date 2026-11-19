#!/usr/bin/env python3
"""Copy the exact pristine RAM Data seed into a larger, isolated APFS container.

No handset I/O and no persistence changes. A filesystem utility guest has a
45-second deadline; there is no XNU/UI emulation or automatic TCG fallback.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
TOOLS = Path('/root/unixnu-build/venus-apfs-tools')
SEED_SHA = '23cd7aa2db7b26eae5d30b956d840f475c45017893077005a8b8ce87e44b584d'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def install_dynamic(binary, root):
    """Stage a host executable and its resolved libraries, never the host FS."""
    paths = {Path(binary)}
    text = subprocess.check_output(['ldd', str(binary)], text=True)
    for line in text.splitlines():
        match = re.search(r'(?:=>\s*)?(/\S+)', line)
        if match:
            paths.add(Path(match.group(1)))
    for path in paths:
        target = root / str(path).lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        target.chmod(path.stat().st_mode & 0o777)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seed', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--mib', type=int, default=2048, choices=(1536, 2048))
    parser.add_argument('--accel', choices=('kvm', 'tcg'), default='kvm',
                        help='Explicit utility backend, no automatic fallback; hard deadline 45s')
    args = parser.parse_args()
    if sha(args.seed) != SEED_SHA:
        raise ValueError('Require exact original D27 volatile seed, not live user Data')
    if args.accel == 'kvm':
        with open('/dev/kvm', 'rb') as stream:
            if fcntl.ioctl(stream, 0xAE00) != 12:
                raise ValueError('KVM API unavailable; no automatic TCG fallback')
    args.out.mkdir(parents=True, exist_ok=False)
    out = args.out.resolve()
    sys.path.insert(0, str(BASE / 'sources/UniXNU/drivers/DarwinBoot/Test'))
    import packed_ramdisk
    logical, extents = packed_ramdisk.regions(args.seed.read_bytes())
    if logical != 1 << 30:
        raise ValueError('Expected the measured 1GiB source seed')
    source, target = out / 'Source.raw', out / 'Data.raw'
    with source.open('xb') as stream:
        stream.truncate(logical)
        for offset, data in extents:
            stream.seek(offset)
            stream.write(data)
    if sha(source) != packed_ramdisk.inspect(args.seed)[0]['sha256']:
        raise ValueError('Source seed unpack differs')
    headers = [bytes(data[i:i+4096]) for _, data in extents
               for i in range(0, len(data), 4096) if data[i+32:i+36] == b'APSB']
    identities = {block[0xf0:0x100] for block in headers}
    if len(identities) != 1:
        raise ValueError('Ambiguous source Data volume identity')
    volume_uuid = str(uuid.UUID(bytes=identities.pop())).upper()
    container_uuid = str(uuid.UUID(bytes=bytes(extents[0][1][0x48:0x58]))).upper()
    with target.open('xb') as stream:
        stream.truncate(args.mib * 1024**2)
    inputs = json.loads((TOOLS / 'inputs.json').read_text())
    if sha(inputs['module']) != inputs['module_sha256']:
        raise ValueError('Pinned APFS module differs')
    with (out / 'format.log').open('x') as log:
        subprocess.run([inputs['mkapfs'], '-L', 'D27 Data', '-U', container_uuid,
                        '-u', volume_uuid, str(target)], check=True, stdout=log, stderr=subprocess.STDOUT, timeout=15)
    guest = out / 'initramfs'
    for name in ('bin', 'mods', 'proc', 'sys', 'dev', 'tmp', 'mnt/source', 'mnt/data'):
        (guest / name).mkdir(parents=True, exist_ok=True)
    for name in ('bin/busybox', 'mods/00.ko', 'mods/01.ko'):
        shutil.copyfile(TOOLS / 'seed-attempt-1/initramfs' / name, guest / name)
    (guest / 'bin/busybox').chmod(0o755)
    install_dynamic('/usr/bin/cp', guest)
    verifier = ROOT / 'ci/platform067/data/verify-tree.c'
    subprocess.run(['gcc', '-static', '-O2', '-Wall', '-Wextra', '-Werror', str(verifier),
                    '-o', str(guest / 'bin/verify-tree')], check=True, timeout=30)
    init = '''#!/bin/busybox sh
/bin/busybox --install -s /bin
set -eu
trap 'echo D27_SEED_GROW_FAIL; poweroff -f' EXIT
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
insmod /mods/00.ko
insmod /mods/01.ko
mount -t apfs -o ro,cknodes /dev/vdb /mnt/source
mount -t apfs -o readwrite,cknodes /dev/vda /mnt/data
/usr/bin/cp -a --preserve=all --reflink=never /mnt/source/. /mnt/data/
/bin/verify-tree /mnt/source /mnt/data
df -k /mnt/data
sync
umount /mnt/data
umount /mnt/source
echo D27_SEED_GROW_PASS
trap - EXIT
poweroff -f
'''
    (guest / 'init').write_text(init)
    (guest / 'init').chmod(0o755)
    names = b'.\0' + b''.join(str(p.relative_to(guest)).encode() + b'\0' for p in sorted(guest.rglob('*')))
    cpio = out / 'initramfs.cpio'
    with cpio.open('xb') as stream:
        subprocess.run(['cpio', '--null', '-o', '--format=newc'], cwd=guest, input=names,
                        stdout=stream, stderr=subprocess.PIPE, check=True, timeout=15)
    command = ['qemu-system-x86_64', '-accel', args.accel, '-cpu', 'host' if args.accel == 'kvm' else 'max', '-m', '768', '-smp', '2',
               '-kernel', inputs['kernel'], '-initrd', str(cpio), '-append',
               'console=ttyS0 quiet rdinit=/init panic=-1', '-display', 'none', '-monitor', 'none',
               '-serial', 'stdio', '-no-reboot', '-nic', 'none',
               '-drive', f'file={target},format=raw,if=virtio',
               '-drive', f'file={source},format=raw,if=virtio,readonly=on']
    (out / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
    started = time.monotonic()
    with (out / 'guest.log').open('x') as log:
        done = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=45, check=False)
    seconds = time.monotonic() - started
    log = (out / 'guest.log').read_text()
    if done.returncode or 'D27_SEED_GROW_PASS' not in log or 'D27_SEED_GROW_FAIL' in log or 'SEED_TREE_PASS' not in log:
        raise RuntimeError(log[-9000:])
    with (out / 'apfsck.log').open('x') as stream:
        subprocess.run([inputs['apfsck'], str(target)], stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=15)
    packed = out / 'scratch-data.img'
    metadata = packed_ramdisk.pack(target, packed)
    if metadata['bytes'] != args.mib * 1024**2 or sha(args.seed) != SEED_SHA:
        raise ValueError('Capacity or unchanged source identity differs')
    record = dict(passed=True, seed=str(packed), seed_sha256=sha(packed), source_seed=str(args.seed),
                  source_seed_sha256=SEED_SHA, source_logical_bytes=logical,
                  logical_bytes=metadata['bytes'], encoded_bytes=metadata['encoded_bytes'],
                  volume_uuid=volume_uuid, container_uuid=container_uuid,
                  nodes_bytes_uid_gid_modes_mtime_symlinks_xattrs_verified=True,
                  native_ram_sparse_limit_respected=True, persistence_mode=0,
                  original_source_unchanged=True, guest_accel=args.accel, guest_deadline_seconds=45, guest_elapsed_seconds=seconds,
                  apfsck_passed=True, verifier_sha256=sha(verifier), device_operations=False,
                  hardware_verified=False, runtime_enospc_resolved=False)
    (out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
