#!/usr/bin/env python3
"""Use pinned VerifiedRoot tools to sign and fully C-verify the actual D27 raw disks.

Only builds host policy inputs. No kernel integration or guest root mount is implied.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib
import uuid

DEVICE = Path(__file__).resolve().parents[1]
REVISION = '974f043d0c71ba2e60331483a41c6c6d35274ee3'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kit', required=True, type=Path)
    parser.add_argument('--disks', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    kit = args.kit.resolve()
    revision = subprocess.check_output(['git', '-C', str(kit), 'rev-parse', 'HEAD'], text=True).strip()
    dirty = subprocess.check_output(['git', '-C', str(kit), 'status', '--porcelain'], text=True).strip()
    if revision != REVISION or dirty:
        parser.error('Require clean pinned VerifiedRoot source')
    disks = json.loads(args.disks.read_text())
    if (disks.get('product'), disks.get('build')) != ('iPhone14,7', '24A446'):
        parser.error('Require original D27/24A446 disk identities')
    expected = tomllib.loads((DEVICE / 'profiles/ios-27.0.1-24A446-iphone14/profile.toml').read_text())['root']
    selected = []
    for component, label, prefix in (('OS', 'OS', 'os'), ('Cryptex1,SystemOS', 'SystemOS', 'systemos')):
        matches = [d for d in disks['disks'] if d['component'] == component]
        if len(matches) != 1 or matches[0]['sha256'] != expected[prefix+'_image_sha256']:
            parser.error(f'{label}: expected target disk digest')
        source = Path(matches[0]['path'])
        if not source.is_file() or source.stat().st_size != matches[0]['bytes']:
            parser.error(f'{label}: exact original image unavailable')
        selected.append((label, source, expected[prefix+'_image_sha256'], expected[prefix+'_volume_uuid']))
    args.out.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, TMPDIR=str(args.out.resolve()), PYTHONDONTWRITEBYTECODE='1')
    library = args.out / 'verified-root.so'
    command = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
               '-I', str(kit/'include'), str(kit/'src/verified_root.c'),
               str(kit/'tests/openssl_provider.c'), '-lcrypto', '-o', str(library)]
    subprocess.run(command, env=env, check=True)
    (args.out/'host-library-command.json').write_text(json.dumps(command,indent=2)+'\n')
    keys = args.out/'keys'
    keys.mkdir(mode=0o700)
    key, public = keys/'owner.pem', keys/'owner-public.pem'
    with key.open('xb'):
        pass
    os.chmod(key,0o600)
    subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:3072',
                    '-out',str(key)],env=env,check=True,capture_output=True)
    subprocess.run(['openssl','pkey','-in',str(key),'-pubout','-out',str(public)],
                   env=env,check=True,capture_output=True)
    manifest = load('official_manifest', kit/'tools/manifest.py')
    inspector = load('d27_apfs_identity', DEVICE/'scripts/inspect-apfs-volumes.py')
    reports = []
    for label, source, digest, identity in selected:
        out = args.out/label
        out.mkdir()
        apfs = inspector.Container(source)
        try:
            media = apfs.inspect()
        finally:
            apfs.file.close()
        if identity not in [v['volume_uuid'] for v in media['volumes']]:
            raise ValueError(f'{label}: original APFS volume UUID differs')
        (out/'apfs-identity.json').write_text(json.dumps(media,indent=2)+'\n')
        print(f'{label}: sign all actual image blocks',flush=True)
        with source.open('rb') as stream:
            record = manifest.make(stream,source.stat().st_size,key,public,uuid.UUID(identity),1,out)
        if record['image_sha256'] != digest:
            raise ValueError(f'{label}: actual disk SHA256 differs from profile')
        command = ['python3','-B',str(kit/'tools/verify_image.py'),'--library',str(library),
                   '--manifest',str(out/'manifest.bin'),'--trusted-key',str(out/'trusted-key.bin'),
                   '--image',str(source),'--volume-uuid',identity,'--minimum-generation','1',
                   '--output',str(out/'verification.json')]
        print(f'{label}: verify RSA and every actual block through original C implementation',flush=True)
        with (out/'verify.log').open('w') as log:
            result = subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError((out/'verify.log').read_text())
        verification = json.loads((out/'verification.json').read_text())
        if not verification['real_c_signature_and_block_verification']:
            raise ValueError('Incomplete real image verification')
        (out/'manifest.header.bin').write_bytes((out/'manifest.bin').read_bytes()[:544])
        reports.append(dict(component=label,image=str(source),verification=verification,
                            manifest_sha256=hashlib.sha256((out/'manifest.bin').read_bytes()).hexdigest()))
        print(f'{label}: all {verification["blocks_verified"]} blocks verified',flush=True)
    if len({r['verification']['trusted_key_sha256'] for r in reports}) != 1:
        raise ValueError('Policies do not share the independently built owner anchor')
    record=dict(target='iPhone14,7 / D27AP / 24A446',kit_revision=revision,
                library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),policies=reports,
                host_policy_inputs_complete=True,kernel_integrated=False,
                actual_guest_reads_verified=False,root_mounted=False,device_operations=False)
    (args.out/'report.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2),flush=True)


if __name__=='__main__':
    main()
