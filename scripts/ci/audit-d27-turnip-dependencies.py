#!/usr/bin/env python3
"""Bounded original-SystemOS cache extraction and Mach-O export/reexport audit."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess

BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cstr(data, at):
    return data[at:data.index(0, at)].decode()


def macho(data):
    assert struct.unpack_from('<I', data)[0] == 0xfeedfacf
    result = dict(dependencies=[], reexports=[], segments=[])
    at = 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        cmd, size = struct.unpack_from('<II', data, at)
        assert size >= 8 and at + size <= len(data)
        if cmd in (0xc, 0xd, 0x80000018, 0x8000001f, 0x80000023):
            off, _, current, compatibility = struct.unpack_from('<4I', data, at+8)
            row = dict(path=cstr(data, at+off), current=current, compatibility=compatibility, command=cmd)
            if cmd == 0xd:
                result['identity'] = row
            else:
                result['dependencies'].append(row)
                if cmd == 0x8000001f:
                    result['reexports'].append(row['path'])
        elif cmd == 0x19:
            vm, length, off, size_ = struct.unpack_from('<4Q', data, at+24)
            result['segments'].append(dict(name=data[at+8:at+24].split(b'\0')[0].decode(), va=vm, size=length, offset=off, file_size=size_))
        elif cmd == 0x80000022:
            result['export_offset'], result['export_size'] = struct.unpack_from('<2I', data, at+40)
        elif cmd == 0x80000033:
            result['export_offset'], result['export_size'] = struct.unpack_from('<2I', data, at+8)
        elif cmd == 2:
            result['symtab'] = struct.unpack_from('<4I', data, at+8)
        at += size
    if result.get('export_size'):
        off = result['export_offset']
        seg = next(s for s in result['segments'] if s['name'] == '__LINKEDIT')
        result['export_va'] = seg['va'] + off - seg['offset']
    return result


def exports(data):
    def uleb(at):
        value, shift = 0, 0
        while True:
            byte = data[at]; at += 1
            value |= (byte & 127) << shift; shift += 7
            assert shift <= 70
            if byte < 128:
                return value, at
    found = {}
    def walk(at, prefix, ancestors):
        assert at not in ancestors and len(ancestors) < 256
        terminal, pos = uleb(at)
        end = pos + terminal
        if terminal:
            flags, value_at = uleb(pos)
            item = dict(flags=flags)
            if flags & 8:
                item['ordinal'], value_at = uleb(value_at)
                item['import_name'] = cstr(data, value_at)
            else:
                item['address'], value_at = uleb(value_at)
            found[prefix] = item
        count = data[end]; pos = end+1
        for _ in range(count):
            edge = cstr(data, pos); pos += len(edge.encode())+1
            child, pos = uleb(pos)
            walk(child, prefix+edge, ancestors | {at})
    if data:
        walk(0, '', set())
    return found


class Audit:
    def __init__(self, args):
        self.args = args
        # drvfs mounts disappear when the distro stops between invocations.
        # This private read-only mount neither reuses nor remounts another job's.
        mountpoint = Path('/mnt/d27-dependency-host-e')
        if not args.systemos.exists() and str(args.systemos).startswith(str(mountpoint)+'/'):
            mountpoint.mkdir(exist_ok=True)
            if not os.path.ismount(mountpoint):
                subprocess.run(['mount','-t','drvfs','E:',str(mountpoint),'-o','ro'],check=True)
        assert args.systemos.is_file(), args.systemos
        self.out = args.out
        self.out.mkdir(parents=True, exist_ok=False)
        self.index = json.loads((BASE/'photo026-cache-002/index.json').read_text())
        self.images = {r['path']: r for r in self.index['images']}
        self.loaded = {}
        self.batch = 0
        self.receipts = []
        if args.resume:
            self.loaded = json.loads((args.resume/'images.json').read_text())
            for receipt in sorted(args.resume.glob('batch-*/receipt.json')):
                rows = json.loads(receipt.read_text())
                raw = receipt.with_name('slices.raw').read_bytes()
                for row in rows:
                    at = row['output_offset']+row['offset']-row['aligned_offset']
                    assert hashlib.sha256(raw[at:at+row['length']]).hexdigest() == row['sha256']
                self.receipts.extend(rows)
        tools = json.loads(Path('/root/unixnu-build/venus-apfs-tools/inputs.json').read_text())
        self.kernel = tools['kernel']
        assert sha(Path(tools['module'])) == tools['module_sha256']
        self.initroot = self.out/'initramfs'
        shutil.copytree(BASE/'photo026-cache-002/initramfs', self.initroot)
        self.system_identity = dict(path=str(args.systemos), size=args.systemos.stat().st_size,
                                    first_mib_sha256=hashlib.sha256(args.systemos.open('rb').read(1<<20)).hexdigest())

    def location(self, va, length):
        for h in self.index['headers']:
            for m in h['maps']:
                if m['va'] <= va and va+length <= m['va']+m['size']:
                    return h['file'], m['offset']+va-m['va']
        raise ValueError(f'Unmapped range {va:x}+{length:x}')

    def extract(self, requests):
        if not requests:
            return []
        self.batch += 1
        assert self.batch <= 40
        folder = self.out/f'batch-{self.batch:02d}'; folder.mkdir()
        rows = []
        cursor = 0
        commands = []
        for name, va, length in requests:
            assert 0 < length <= 8 << 20
            filename, off = self.location(va, length)
            assert filename.startswith('dyld_shared_cache_arm64e') and '/' not in filename
            aligned = off & ~4095
            size = (off-aligned+length+4095) & ~4095
            commands += [f'test "$(stat -c %s "$cache/{filename}")" -ge {aligned+size}']
            commands += [f'dd if="$cache/{filename}" of=/dev/vdb bs=4096 skip={aligned//4096} count={size//4096} seek={cursor//4096} conv=notrunc 2>/dev/null']
            rows.append(dict(name=name, va=va, length=length, file=filename, offset=off,
                             aligned_offset=aligned, aligned_bytes=size, output_offset=cursor))
            cursor += size
        assert cursor <= 64 << 20
        raw = folder/'slices.raw'
        with raw.open('xb') as stream:
            stream.truncate(cursor)
        init = '''#!/bin/busybox sh
/bin/busybox --install -s /bin
set -eu
trap 'echo D27_DEP_FAIL; poweroff -f' EXIT
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
insmod /mods/00.ko
insmod /mods/01.ko
mount -t apfs -o ro /dev/vda /mnt/os
cache=/mnt/os/System/Library/Caches/com.apple.dyld
echo '21d3a213c3a1a62cf37325cebf2335f75cbf1e7a4d9548049c7cee2695903b40  '"$cache/dyld_shared_cache_arm64e" | sha256sum -c -
''' + '\n'.join(commands) + '''
sync
umount /mnt/os
trap - EXIT
echo D27_DEP_PASS
poweroff -f
'''
        (self.initroot/'init').write_text(init)
        packed = folder/'initramfs.cpio'
        names = b'.\0'+b''.join(str(p.relative_to(self.initroot)).encode()+b'\0' for p in sorted(self.initroot.rglob('*')))
        with packed.open('xb') as stream:
            subprocess.run(['cpio','--null','-o','--format=newc'],input=names,cwd=self.initroot,stdout=stream,stderr=subprocess.PIPE,check=True)
        cmd = ['qemu-system-x86_64','-accel','tcg','-cpu','max','-m','512','-smp','1','-kernel',self.kernel,
               '-initrd',str(packed),'-append','console=ttyS0 quiet rdinit=/init panic=-1','-nographic',
               '-monitor','none','-no-reboot','-nic','none','-drive',f'file={self.args.systemos},format=raw,if=virtio,readonly=on',
               '-drive',f'file={raw},format=raw,if=virtio']
        (folder/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        (folder/'requests.json').write_text(json.dumps(rows,indent=2)+'\n')
        print(f'Extract batch {self.batch}: {len(rows)} ranges, {cursor} bytes',flush=True)
        with (folder/'guest.log').open('w') as log:
            subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT,timeout=180,check=True)
        log = (folder/'guest.log').read_text()
        assert 'D27_DEP_PASS' in log and 'D27_DEP_FAIL' not in log
        data = raw.read_bytes(); result=[]
        for row in rows:
            at=row['output_offset']+row['offset']-row['aligned_offset']
            chunk=data[at:at+row['length']]
            assert len(chunk)==row['length']
            row['sha256']=hashlib.sha256(chunk).hexdigest()
            result.append(chunk)
        (folder/'receipt.json').write_text(json.dumps(rows,indent=2)+'\n')
        self.receipts.extend(rows)
        return result

    def load(self, paths):
        paths = sorted(set(paths)-self.loaded.keys())
        for path in paths:
            assert path in self.images, f'No original cache image {path}'
        headers=self.extract([(p,self.images[p]['va'],8192) for p in paths])
        metadata=[macho(h) for h in headers]
        requests=[(p,m['export_va'],m['export_size']) for p,m in zip(paths,metadata) if m.get('export_size')]
        tries=iter(self.extract(requests))
        for p,m in zip(paths,metadata):
            m['exports']=exports(next(tries)) if m.get('export_size') else {}
            self.loaded[p]=m
        (self.out/'images.json').write_text(json.dumps(self.loaded,indent=2)+'\n')

    def resolve(self, path, symbol, seen=()):
        if (path,symbol) in seen:
            return None
        if path not in self.loaded:
            raise KeyError(path)
        m=self.loaded[path];row=m['exports'].get(symbol);chain=seen+((path,symbol),)
        if row is not None:
            if row['flags']&8:
                ordinal=row['ordinal'];assert 1<=ordinal<=len(m['dependencies'])
                return self.resolve(m['dependencies'][ordinal-1]['path'],row['import_name'] or symbol,chain)
            return dict(provider=path,symbol=symbol,chain=chain,flags=row['flags'])
        for other in m['reexports']:
            result=self.resolve(other,symbol,chain)
            if result:
                return result
        return None

    def run(self):
        data=self.args.library.read_bytes();m=macho(data);sym,count,stro,_=m['symtab'];strong=[];weak=0
        for i in range(count):
            ix,typ,_,desc,_=struct.unpack_from('<IBBHQ',data,sym+i*16)
            if typ&14:
                continue
            if desc&0x40:
                weak+=1;continue
            ordinal=desc>>8
            assert 1<=ordinal<=len(m['dependencies'])
            strong.append(dict(symbol=cstr(data,stro+ix),library=m['dependencies'][ordinal-1]['path']))
        self.load([r['path'] for r in m['dependencies']])
        # Load whole-library reexports in breadth-first batches. Waiting for
        # the first missing provider per symbol serializes libSystem's list.
        for _ in range(16):
            pending = {p for image in self.loaded.values() for p in image['reexports']} - self.loaded.keys()
            if not pending:
                break
            self.load(pending)
        else:
            raise ValueError('Reexport graph exceeds bounded traversal')
        versions=[]
        for dep in m['dependencies']:
            actual=self.loaded[dep['path']]['identity']
            versions.append(dict(path=dep['path'],required=dep['compatibility'],actual_current=actual['current'],
                                 actual_compatibility=actual['compatibility'],satisfies=actual['current']>=dep['compatibility']))
        while True:
            needed=set();resolved=[];missing=[]
            for row in strong:
                try:
                    result=self.resolve(row['library'],row['symbol'])
                    (resolved if result else missing).append(dict(**row, resolution=result))
                except KeyError as error:
                    needed.add(error.args[0])
            if not needed:
                break
            self.load(needed)
        result=dict(library=str(self.args.library),library_sha256=hashlib.sha256(data).hexdigest(),
                    source=self.system_identity,original_cache_index_sha256=sha(BASE/'photo026-cache-002/index.json'),
                    strong_count=len(strong),weak_count=weak,resolved_count=len(resolved),missing=missing,
                    versions=versions,resolved=resolved,images_loaded=list(self.loaded),
                    extracted_bytes=sum(r['length'] for r in self.receipts),batches=self.batch,
                    scope='offline original-cache export/version resolution, not dyld execution or hardware',
                    source_readonly=True,device_operations=False)
        result['resumed_from'] = str(self.args.resume) if self.args.resume else None
        (self.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps({k:v for k,v in result.items() if k!='resolved'},indent=2),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--resume',type=Path)
    parser.add_argument('--systemos',type=Path,default=Path('/mnt/d27-dependency-host-e/UniXNU-Port-artifacts/qemu-systemos-recovery-20261117-001/043-69730-712.dmg'))
    parser.add_argument('--library',type=Path,default=BASE/'metal-d27-startup-003/plugin/NativeAdrenoMetal.bundle/libvulkan_freedreno.dylib')
    Audit(parser.parse_args()).run()
