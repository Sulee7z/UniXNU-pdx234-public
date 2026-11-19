#!/usr/bin/env python3
"""Build the pinned official D27 Bluetooth runtime in an isolated069 directory."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
FRESH=Path('/mnt/f/UniXNU-Port-artifacts/platform069-20261118')
COMPONENT=BASE/'sony-wcn-067-002/components/QcaBluetooth'
SDK=BASE/'user-sdk-002/repository/iPhoneOS27.0.sdk'
CC=BASE/'metal-runtime-001/host-bin/clang'
sys.path.insert(0,str(ROOT/'ci'))
from platform069.integration import sha
from platform069.codesign import inspect


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True);a=parser.parse_args()
    a.out.mkdir(parents=True,exist_ok=False);out=a.out.resolve();sources=out/'source';sources.mkdir();stage=out/'runtime'
    for name in ('bluetooth-bin','bluetooth-lib'):(stage/name).mkdir(parents=True)
    for name in ('BlueTool.c','Type0.c'):shutil.copyfile(COMPONENT/'userland'/name,sources/name)
    for name in ('native_ios27.py','inspect-ios.py'):shutil.copyfile(COMPONENT/'tools'/name,sources/name)
    native=module('sony069_native_bluetooth',sources/'native_ios27.py')
    original=FRESH/'d27-radio-userland-original-003/files/os/usr/sbin/bluetoothd'
    image=native.NativeImage(original)
    patched=image.vendor_routing().volatile_root_keys().h4_shutdown().capability_adapter()
    daemon=stage/'bluetooth-bin/bluetoothd';daemon.write_bytes(patched.data);daemon.chmod(0o755)
    (sources/'qbt_ios27_layout.h').write_text(native.layout_header())
    commands={}
    base=[str(CC),'-target','arm64e-apple-ios27.0','-isysroot',str(SDK),'-O2','-Wall','-Wextra','-Werror','-fstack-protector-strong']
    for name,relative,extra in [('BlueTool','bluetooth-bin/BlueTool',['-fblocks']),
                              ('Type0','bluetooth-lib/QcaBTType0.dylib',['-dynamiclib','-install_name','/usr/lib/QcaBTType0.dylib','-fvisibility=hidden','-I',str(sources)])]:
        target=stage/relative;command=[*base,*extra,str(sources/(name+'.c')),'-o',str(target)]
        with (out/(name+'.compile.log')).open('x') as log:d=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,timeout=120)
        if d.returncode:raise RuntimeError((out/(name+'.compile.log')).read_text()[-10000:])
        commands[name]=command;target.chmod(0o755)
    # Preserve the original daemon entitlements semantically and let the signer
    # import its existing signature flags/identifier, as in official build-userland.
    def signature_blobs(data):
        at=32;signature=None
        for _ in range(struct.unpack_from('<I',data,16)[0]):
            kind,size=struct.unpack_from('<II',data,at)
            if kind==0x1d:
                p,n=struct.unpack_from('<II',data,at+8);signature=data[p:p+n]
            at+=size
        if signature is None:raise ValueError('Original daemon signature missing')
        magic,length,count=struct.unpack_from('>III',signature)
        if magic!=0xfade0cc0 or length>len(signature):raise ValueError('Malformed original signature')
        blobs={}
        for i in range(count):
            kind,offset=struct.unpack_from('>II',signature,12+8*i);_,size=struct.unpack_from('>II',signature,offset)
            blobs[kind]=signature[offset:offset+size]
        return blobs
    original_blobs=signature_blobs(original.read_bytes());entitlement_bytes=original_blobs[5][8:]
    original_entitlements=plistlib.loads(entitlement_bytes);entitlements=out/'bluetoothd.entitlements.plist'
    entitlements.write_bytes(plistlib.dumps(original_entitlements,fmt=plistlib.FMT_XML))
    cd=original_blobs[0];identifier_at=struct.unpack_from('>I',cd,20)[0];identifier=cd[identifier_at:cd.index(b'\0',identifier_at)].decode()
    signer=Path(json.loads((BASE/'user-signing-001/source.json').read_text())['executable'])
    blue_entitlements=out/'BlueTool.entitlements.plist';blue_entitlements.write_bytes(plistlib.dumps({'com.apple.private.security.no-container':True}))
    checks={};files=[];signed_files=[]
    for relative,identity,ent in [('bluetooth-bin/BlueTool','org.unixnu.bluetooth.BlueTool',blue_entitlements),
                                  ('bluetooth-lib/QcaBTType0.dylib','org.unixnu.bluetooth.Type0',None),
                                  ('bluetooth-bin/bluetoothd',identifier,entitlements)]:
        target=stage/relative;command=[str(signer),'sign','--digest','sha256','--binary-identifier',identity]
        if ent:command+=['--entitlements-xml-file',str(ent)]
        with (out/(target.name+'.sign.log')).open('x') as log:subprocess.run([*command,str(target)],stdout=log,stderr=subprocess.STDOUT,check=True,timeout=60)
        result=inspect(target);actual_entitlements=result.pop('entitlements')
        if relative.endswith('/bluetoothd') and plistlib.loads(actual_entitlements)!=original_entitlements:
            raise ValueError('Original D27 daemon entitlements changed')
        final=native._inspect.Image(target)
        if final.subtype!=0x80000002:raise ValueError('Userland arm64e subtype changed')
        if relative.endswith('/bluetoothd') and (final.uuid!=native.ORIGINAL_UUID or final.data.count(native.NATIVE_DYLIB+b'\0')!=1):
            raise ValueError('Original D27 UUID or capability load command changed')
        checks[relative]={**result,'entitlements_sha256':hashlib.sha256(actual_entitlements).hexdigest()}
        files.append(dict(path=relative,source=str(target),sha256=sha(target),mode=0o755))
        signed_files.append(dict(path=relative,entitlements_sha256=checks[relative]['entitlements_sha256']))
    marker=stage/'bluetooth-bin/QcaBluetooth.runtime';marker.write_text(json.dumps(dict(native_input_sha256=native.ORIGINAL_SHA256,
        files={row['path']:row['sha256'] for row in files}),sort_keys=True)+'\n')
    files.append(dict(path='bluetooth-bin/QcaBluetooth.runtime',source=str(marker),sha256=sha(marker),mode=0o644))
    record=dict(passed=True,target='arm64e-apple-ios27.0',official_adapter=str(COMPONENT/'tools/native_ios27.py'),
        native_input=str(original),native_input_sha256=sha(original),native_uuid=native.ORIGINAL_UUID,
        native_entitlements_preserved=True,native_entitlement_count=len(original_entitlements),
        commands=commands,patch=patched.report(),files=files,signed_files=signed_files,signature_checks=checks,
        inputs={str(p):sha(p) for p in [*sources.iterdir(),original,signer,CC]},
        hardware_verified=False,device_operations=False)
    (out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({k:v for k,v in record.items() if k not in ('commands','patch','inputs')},indent=2))


if __name__=='__main__':main()
