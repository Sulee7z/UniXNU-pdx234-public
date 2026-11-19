#!/usr/bin/env python3
"""Fetch verified iPhone14 OS inputs and decrypt AEA with the pinned Linux ipsw tool.

All files are host-side build inputs. No partitions are queried or modified.
Stored ZIP members support resume; CRC, SHA256 and SHA384 are recorded.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
from types import SimpleNamespace
import tomllib
import zipfile
import zlib

DEVICE = Path('/mnt/g/UniXNU-Port/ports/UniXNU-pdx234')
MAINLINE = Path('/mnt/g/UniXNU-Port/sources/UniXNU-main-20261109')

TOOL = Path('/root/unixnu-build/pdx234-tools/ipsw-3.1.743/ipsw')
MANIFEST_SHA = '1e116653d2d73f00566ca7f83daf006c846e14c3474777904afe359dc94e5742'
CHUNK = 8 << 20


def digest_file(path: Path) -> tuple[str, str, int]:
    sha256, sha384, crc = hashlib.sha256(), hashlib.sha384(), 0
    with path.open('rb') as source:
        while data := source.read(CHUNK):
            sha256.update(data)
            sha384.update(data)
            crc = zlib.crc32(data, crc)
    return sha256.hexdigest(), sha384.hexdigest(), crc


def extract(source: Ipsw, component: str, destination: Path) -> dict:
    name, size, compressed = source.info(component)
    entry = source.zip.getinfo(name)
    expected = dict(component=component, member=name, size=size, compressed_bytes=compressed,
                    crc32=f'{entry.CRC:08x}', url=source.spec, product='iPhone14,7', build='24A446')
    record = destination.with_suffix(destination.suffix + '.origin.json')
    if record.exists() and json.loads(record.read_text())['identity'] != expected:
        raise RuntimeError('Existing input identity differs; preserve it')
    if not record.exists():
        if destination.exists() or destination.with_suffix(destination.suffix + '.partial').exists():
            raise RuntimeError('Unidentified existing input; preserve it')
        record.write_text(json.dumps(dict(identity=expected, completed=False), indent=2))
    if destination.is_file():
        a, b, crc = digest_file(destination)
        if destination.stat().st_size != size or crc != entry.CRC:
            raise RuntimeError('Existing completed input failed size/CRC')
        return dict(**expected, sha256=a, sha384=b, path=str(destination), zip_crc_verified=True)
    partial = destination.with_suffix(destination.suffix + '.partial')
    start = partial.stat().st_size if partial.exists() else 0
    if start > size:
        raise RuntimeError('Partial member is larger than its declared size')
    sha256, sha384, crc = hashlib.sha256(), hashlib.sha384(), 0
    if start:
        with partial.open('rb') as old:
            while data := old.read(CHUNK):
                sha256.update(data); sha384.update(data); crc = zlib.crc32(data, crc)
    print(f'{component}: {start}/{size} bytes', flush=True)
    if entry.compress_type == zipfile.ZIP_STORED:
        source.stream.seek(entry.header_offset)
        header = source.stream.read(30)
        if len(header) != 30 or header[:4] != b'PK\x03\x04':
            raise RuntimeError('Invalid local ZIP header')
        namesize, extrasize = struct.unpack_from('<HH', header, 26)
        payload = entry.header_offset + 30 + namesize + extrasize
        if start:
            check = min(start, 65536)
            source.stream.seek(payload)
            remote = source.stream.read(check)
            with partial.open('rb') as old:
                if old.read(check) != remote:
                    raise RuntimeError('Partial prefix differs from the pinned member')
        source.stream.seek(payload + start)
        stream = source.stream
    else:
        if start:
            raise RuntimeError('Resume is only supported for stored ZIP members')
        stream = source.zip.open(name)
    try:
        with partial.open('ab') as output:
            done = start
            while done < size:
                data = stream.read(min(CHUNK, size - done))
                if not data:
                    raise RuntimeError('Short ZIP member stream')
                output.write(data)
                sha256.update(data); sha384.update(data); crc = zlib.crc32(data, crc)
                done += len(data)
                if done % (256 << 20) == 0 or done == size:
                    print(f'{component}: {done}/{size} bytes', flush=True)
    finally:
        if stream is not source.stream:
            stream.close()
    if crc != entry.CRC or partial.stat().st_size != size:
        raise RuntimeError('Member CRC/size verification failed; partial preserved')
    partial.rename(destination)
    result = dict(**expected, sha256=sha256.hexdigest(), sha384=sha384.hexdigest(),
                  path=str(destination), zip_crc_verified=True)
    record.write_text(json.dumps(dict(identity=expected, completed=True, result=result), indent=2))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--attempt', required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--mainline', type=Path, default=MAINLINE,
                        help='Use the official unixnu.ipsw range reader from this checkout')
    parser.add_argument('--ipsw-tool', type=Path, default=TOOL,
                        help='Upstream blacktop/ipsw with its Linux AEA decoder')
    parser.add_argument('--inspect-only', action='store_true',
                        help='Validate BuildManifest and list members without downloading disk images')
    parser.add_argument('--component', action='append', choices=['OS', 'Cryptex1,SystemOS', 'Cryptex1,AppOS'])
    args = parser.parse_args()
    if not args.attempt.isalnum():
        raise RuntimeError('Use a fresh alphanumeric attempt')
    out = DEVICE / 'out' / ('iphone14-root-' + args.attempt)
    out.mkdir()
    if not args.ipsw_tool.is_file():
        raise RuntimeError('Pinned Linux ipsw tool is missing')
    args.work.mkdir(parents=True, exist_ok=True)
    marker = args.work / 'OWNER.json'
    identity = dict(owner='PDX234 iPhone14 iOS27 host build inputs', product='iPhone14,7', build='24A446')
    if marker.exists():
        if json.loads(marker.read_text()) != identity:
            raise RuntimeError('Work directory belongs to a different input context')
    elif any(args.work.iterdir()):
        raise RuntimeError('Unidentified nonempty work directory; preserve it')
    else:
        marker.write_text(json.dumps(identity, indent=2))
    # WSL's virtual ext4 capacity is not the available space on the host G drive.
    if not args.inspect_only and min(shutil.disk_usage(args.work).free,
                                    shutil.disk_usage('/mnt/g').free) < 24 << 30:
        raise RuntimeError('Need 24 GiB free for encrypted and decrypted root inputs')
    encrypted, plain = args.work / 'encrypted', args.work / 'plain'
    encrypted.mkdir(exist_ok=True); plain.mkdir(exist_ok=True)
    profile = tomllib.loads((DEVICE / 'profiles/ios-27.0.1-24A446-iphone14/profile.toml').read_text())
    sys.path.insert(0, str(args.mainline.resolve() / 'scripts'))
    from unixnu.ipsw import Ipsw
    context = SimpleNamespace(board=profile, out_root=args.work,
                              option_text=lambda *unused: None)
    source = Ipsw(context)
    raw_manifest = source.zip.read('BuildManifest.plist')
    if hashlib.sha256(raw_manifest).hexdigest() != MANIFEST_SHA:
        raise RuntimeError('Original BuildManifest changed')
    (out / 'BuildManifest.plist').write_bytes(raw_manifest)
    report = dict(product='iPhone14,7', device_class='d27ap', build='24A446',
                  manifest_sha256=MANIFEST_SHA, tool=str(args.ipsw_tool), inputs=[],
                  device_operations=False, github_actions_invoked=False,
                  decryption_route='Manual upstream ipsw Linux AEA; not UniXNU macOS decrypt_aea')
    try:
        for component in args.component or ['Cryptex1,AppOS', 'Cryptex1,SystemOS', 'OS']:
            name = Path(source.member(component)).name
            if args.inspect_only:
                _, size, compressed = source.info(component)
                report['inputs'].append(dict(component=component, member=name,
                                             bytes=size, compressed_bytes=compressed))
                (out / 'inputs.json').write_text(json.dumps(report, indent=2))
                print(component, name, size, flush=True)
                continue
            item = extract(source, component, encrypted / name)
            item['build_manifest_digest'] = source.identity['Manifest'][component].get('Digest', b'').hex()
            if name.endswith('.aea'):
                decoded = plain / name.removesuffix('.aea')
                if not decoded.exists():
                    log = out / (component.replace(',', '-') + '-aea.log')
                    with log.open('xb') as output:
                        subprocess.run([str(args.ipsw_tool), 'fw', 'aea', str(encrypted / name),
                                        '--output', str(plain)], stdout=output,
                                       stderr=subprocess.STDOUT, check=True)
                a, b, _ = digest_file(decoded)
                item['decoded'] = dict(path=str(decoded), bytes=decoded.stat().st_size,
                                       sha256=a, sha384=b, decoder='ipsw pure-Go AEA')
                item['manifest_digest_matches'] = item['build_manifest_digest'] in (item['sha384'], b)
                if not item['manifest_digest_matches']:
                    raise RuntimeError('Disk input does not match the BuildManifest digest; preserve it for inspection')
            else:
                item['decoded'] = dict(path=str(encrypted / name), bytes=item['size'],
                                       sha256=item['sha256'], sha384=item['sha384'])
            report['inputs'].append(item)
            (out / 'inputs.json').write_text(json.dumps(report, indent=2))
            print(component, 'ready', item['decoded'], flush=True)
    finally:
        source.zip.close(); source.stream.close()


if __name__ == '__main__':
    main()
