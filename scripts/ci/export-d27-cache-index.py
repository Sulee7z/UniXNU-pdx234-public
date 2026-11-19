#!/usr/bin/env python3
"""Read only the original SystemOS cache index and 4K mapping headers in a Linux guest."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess

DEVICE = Path(__file__).resolve().parents[2]
TOOLS = Path('/root/unixnu-build/venus-apfs-tools')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--slice-file')
    parser.add_argument('--slice-offset', type=lambda value: int(value, 0), default=0)
    parser.add_argument('--slice-bytes', type=lambda value: int(value, 0), default=4096)
    args = parser.parse_args()
    if args.slice_file:
        safe_name = (args.slice_file.startswith('dyld_shared_cache_arm64e') and
                     len(args.slice_file) <= 96 and
                     all(c.isalnum() or c in '._' for c in args.slice_file))
        if (not safe_name or args.slice_offset < 0 or args.slice_offset % 4096 or
                not 0 < args.slice_bytes <= 65536 or args.slice_bytes % 4096):
            parser.error('Require a cache basename, aligned offset and 4K..64K slice')
    args.out.mkdir(parents=True, exist_ok=False)
    out = args.out.resolve()
    tools = json.loads((TOOLS/'inputs.json').read_text())
    module = Path(tools['module'])
    if hashlib.sha256(module.read_bytes()).hexdigest() != tools['module_sha256']:
        raise ValueError('Prepared Linux APFS module identity changed')
    policies = json.loads((DEVICE/'out/d27-owner-policies-001/report.json').read_text())
    row = next(row for row in policies['policies'] if row['component']=='SystemOS')
    source = Path(row['image'])
    if (not row['verification']['real_c_signature_and_block_verification'] or
            source.stat().st_size != row['verification']['image_bytes']):
        raise ValueError('Original verified SystemOS image unavailable')
    root = out/'initramfs'
    shutil.copytree(DEVICE/'out/d27-systemos-cache-inventory-002/initramfs', root)
    init = '''#!/bin/busybox sh
/bin/busybox --install -s /bin
set -eu
trap 'echo CACHE_INDEX_FAIL; poweroff -f' EXIT
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
insmod /mods/00.ko
insmod /mods/01.ko
mount -t apfs -o ro /dev/vda /mnt/os
cache=/mnt/os/System/Library/Caches/com.apple.dyld
main=$cache/dyld_shared_cache_arm64e
test "$(stat -c %s "$main")" -le 1048576
echo "MAIN_BYTES $(stat -c %s "$main")"
sha256sum "$main"
dd if="$main" of=/dev/vdb bs=4096 seek=0 conv=notrunc 2>/dev/null
i=0
for file in "$cache"/dyld_shared_cache_arm64e*; do
    case "$file" in *.symbols|*.atlas) continue ;; esac
    echo "HEADER $i $(basename "$file") $(stat -c %s "$file")"
    dd if="$file" of=/dev/vdb bs=4096 count=1 seek=$((256+i)) conv=notrunc 2>/dev/null
    i=$((i+1))
done
sync
umount /mnt/os
trap - EXIT
echo CACHE_INDEX_PASS
poweroff -f
'''
    if args.slice_file:
        command = 'dd if=$cache/{} of=/dev/vdb bs=4096 skip={} count={} seek=512 conv=notrunc 2>/dev/null\n'
        command = command.format(args.slice_file, args.slice_offset//4096, args.slice_bytes//4096)
        limit = args.slice_offset+args.slice_bytes
        command = 'test $(stat -c %s $cache/{}) -ge {}\n'.format(args.slice_file, limit)+command
        init = init.replace('sync\n', command+'sync\n')
    (root/'init').write_text(init)
    (root/'init').chmod(0o755)
    raw = out/'export.raw'
    with raw.open('xb') as stream:
        stream.truncate(4 << 20)
    packed = out/'initramfs.cpio'
    names = b'.\0'+b''.join(str(path.relative_to(root)).encode()+b'\0' for path in sorted(root.rglob('*')))
    with packed.open('xb') as stream:
        subprocess.run(['cpio','--null','-o','--format=newc'],input=names,cwd=root,
                       stdout=stream,stderr=subprocess.PIPE,check=True)
    command = ['qemu-system-x86_64','-accel','tcg','-cpu','max','-m','512','-smp','1',
               '-kernel',tools['kernel'],'-initrd',str(packed),'-append',
               'console=ttyS0 quiet rdinit=/init panic=-1','-nographic','-no-reboot','-nic','none',
               '-drive',f'file={source},format=raw,if=virtio,readonly=on',
               '-drive',f'file={raw},format=raw,if=virtio']
    (out/'command.json').write_text(json.dumps(command,indent=2)+'\n')
    with (out/'guest.log').open('x') as stream:
        result = subprocess.run(command,stdout=stream,stderr=subprocess.STDOUT,timeout=120,
                                env=dict(os.environ,TMPDIR=str(out)))
    log = (out/'guest.log').read_text()
    if result.returncode or 'CACHE_INDEX_PASS' not in log or 'CACHE_INDEX_FAIL' in log:
        raise RuntimeError('Read-only cache index export failed; see guest.log')
    size = int(re.search(r'MAIN_BYTES (\d+)',log)[1])
    if not 512 <= size <= 1 << 20:
        raise ValueError('Main cache does not fit the bounded metadata export')
    data = raw.read_bytes()
    main = data[:size]
    digest = hashlib.sha256(main).hexdigest()
    if digest+'  /mnt/os/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e' not in log:
        raise ValueError('Original main cache bytes did not survive export')
    (out/'dyld_shared_cache_arm64e').write_bytes(main)
    # Reuse the upstream audit-target-display-query Apple cache ABI fields.
    offset, count = struct.unpack_from('<2Q',main,136)
    if count > 16384 or offset+count*32 > len(main):
        raise ValueError('Original imagesText index extent is invalid')
    images = []
    for index in range(count):
        identity, address, length, path_offset = struct.unpack_from('<16sQ2I',main,offset+index*32)
        end = main.find(b'\0',path_offset)
        if not 0 < path_offset < end < len(main):
            raise ValueError('Original cache image path extent is invalid')
        images.append(dict(address=hex(address),text_bytes=length,path=main[path_offset:end].decode()))
    headers = []
    for index, name, file_bytes in re.findall(r'HEADER (\d+) (dyld_shared_cache_arm64e\S*) (\d+)',log):
        header = data[(256+int(index))*4096:(257+int(index))*4096]
        if not header[:16].rstrip(b'\0').endswith(b'arm64e'):
            raise ValueError('Wrong original cache architecture')
        at, mappings_count = struct.unpack_from('<2I',header,16)
        if mappings_count > 16 or at+mappings_count*32 > len(header):
            raise ValueError('Mapping index does not fit its bounded header')
        mappings = [dict(zip(('address','size','file_offset','maxprot','initprot'),
                    struct.unpack_from('<3Q2I',header,at+i*32))) for i in range(mappings_count)]
        headers.append(dict(file=name,file_bytes=int(file_bytes),mappings=mappings))
    report = dict(main_cache_sha256=digest,images=images,headers=headers,
                  format_reference='upstream audit-target-display-query.py; bounded original cache fields',
                  original_systemos_readonly=True,module_sha256=tools['module_sha256'],
                  guest_os='isolated Linux APFS',device_operations=False)
    if args.slice_file:
        chunk = data[2097152:2097152+args.slice_bytes]
        (out/'cache-slice.bin').write_bytes(chunk)
        report['slice'] = dict(file=args.slice_file,offset=args.slice_offset,bytes=len(chunk),
                               sha256=hashlib.sha256(chunk).hexdigest())
    (out/'index.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(main_cache_sha256=digest,images=len(images),cache_headers=len(headers)),indent=2))


if __name__ == '__main__':
    main()
