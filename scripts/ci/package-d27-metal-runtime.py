#!/usr/bin/env python3
"""Package the signed upstream iOS27 plugin and append its D27 owner trust."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import zlib

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--plugin',type=Path,default=BASE/'metal-runtime-001/build/adreno-metal-plugin27')
    a=p.parse_args()
    out=a.out;out.mkdir(parents=True,exist_ok=False)
    root=BASE/'metal-runtime-001';plugin=a.plugin.resolve()
    spec=importlib.util.spec_from_file_location('sign',Path(__file__).with_name('d27-codesign.py'))
    sign=importlib.util.module_from_spec(spec);spec.loader.exec_module(sign)
    checks={}
    for name,path in [('plugin',plugin/'NativeAdrenoMetal.bundle'),('turnip',plugin/'NativeAdrenoMetal.bundle/libvulkan_freedreno.dylib')]:
        result=sign.inspect(path);result.pop('entitlements');checks[name]=result
    trust=json.loads((plugin/'trust.json').read_text())
    assert checks['plugin']['cdhash']==trust['cdhash'] and checks['turnip']['cdhash']==trust['turnip_cdhash']
    addon=out/'kernel.macho.gpuaddon'
    subprocess.run(['python3','-B',str(root/'scripts/make-gpu-addon.py'),'--publish','--no-daemon',str(addon)],
                   env=dict(os.environ,ADRENO_PLUGIN_DIR=str(plugin)),check=True)
    raw=addon.read_bytes();assert raw[:8]==b'NGPUADD2'
    count,_,size=struct.unpack_from('<IIQ',raw,8);assert size==len(raw);offset=24;files=[]
    for _ in range(count):
        plen,mode,length,packed=struct.unpack_from('<IIQQ',raw,offset);offset+=24
        name=raw[offset:offset+plen];assert name[-1]==0;name=name[:-1].decode();offset+=(plen+7)&-8
        data=zlib.decompress(raw[offset:offset+packed]);offset+=(packed+7)&-8
        assert len(data)==length
        if name=='addons/NativeAdrenoMetal.publish':assert data==b'1\n'
        else:assert data==(plugin/name.removeprefix('addons/')).read_bytes()
        files.append(dict(path=name,mode=mode,bytes=length,sha256=hashlib.sha256(data).hexdigest()))
    assert offset==len(raw)
    original=BASE/'payload-root-004/stage/EFI/UniXNU/Payloads/kernel.macho.trustcache'
    target=out/'kernel.macho.trustcache'
    subprocess.run(['python3','-B',str(root/'scripts/trust-append-module.py'),str(original),str(target),
                    checks['plugin']['cdhash'],checks['turnip']['cdhash']],check=True)
    def modules(data):
        n=struct.unpack_from('<I',data)[0];starts=list(struct.unpack_from('<'+str(n)+'I',data,4))+[len(data)]
        result=[]
        for i in range(n):
            blob=data[starts[i]:starts[i+1]];version=struct.unpack_from('<I',blob)[0];entries=struct.unpack_from('<I',blob,20)[0]
            assert version==2 and len(blob)==24+entries*24
            hashes=[blob[24+j*24:44+j*24] for j in range(entries)];assert hashes==sorted(set(hashes))
            result.append(blob)
        return result
    before=modules(original.read_bytes());after=modules(target.read_bytes());assert after[:-1]==before
    result=dict(addon=str(addon),addon_sha256=hashlib.sha256(raw).hexdigest(),trust=str(target),
                trust_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),original_trust_modules_unchanged=True,
                signature_pages_verified=True,signature_checks=checks,files=files,daemon_packaged=False,
                target='arm64e-apple-ios27.0',plugin_source=str(plugin),
                source_adapter=json.loads((plugin.parent/'result.json').read_text()) if (plugin.parent/'result.json').exists() else None,
                rust_pac_recipe='upstream rust-pac-rewrite.py',runtime_verified=False)
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
