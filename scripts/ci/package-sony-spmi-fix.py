#!/usr/bin/env python3
"""Package the qualified SPMI polling-init delta over035, preserving payload."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT=Path(__file__).resolve().parents[2]
def sha(data):return hashlib.sha256(data).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--firmware',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    prior=ROOT/'out/d27-pac-abi-release-20261116-035'
    record=json.loads((prior/'release.json').read_text())
    raw=(prior/Path(record['image']).name).read_bytes()
    if sha(raw)!=record['sha256']:raise ValueError('035 image identity mismatch')
    fw=json.loads((a.firmware/'result.json').read_text())
    tests=json.loads((a.firmware/'emulation.json').read_text())
    fd=Path(fw['fd']).read_bytes()
    if not tests['passed'] or sha(fd)!=fw['sha256'] or len(fd)!=0x300000:
        raise ValueError('SPMI verification missing')
    if fw['source_fd_sha256']!=record['firmware_sha256']:raise ValueError('Wrong firmware baseline')
    spec=importlib.util.spec_from_file_location('fv',ROOT/'scripts/check-firmware-services.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    memory=struct.unpack_from('<Q',raw,4096+0x200000+16)[0]
    start=4096+0x200000+memory;end=start+len(fd)
    before=m.volume_files(raw[start:end]);after=m.volume_files(fd)
    changed=[g for g in before if before[g]!=after[g]]
    if before.keys()!=after.keys() or set(changed)!={'2a7b4bef-80cd-49e1-b473-374ba4d673fc','9e21fd93-9c72-4c15-8c4b-e77f1db2d792'}:
        raise ValueError('Unrelated firmware changes')
    if not m.inspect_firmware(fd)['passed']:raise ValueError('Firmware service check failed')
    packed=raw[:start]+fd+raw[end:]
    a.out.mkdir(parents=True,exist_ok=False)
    image=a.out/'boot-pdx234-pac-abi-036.img';image.write_bytes(packed)
    if image.read_bytes()!=packed:raise ValueError('Delivery readback differs')
    record.update(image=str(image),label='PAC-ABI-036',sha256=sha(packed),firmware_sha256=sha(fd),
        source_image_sha256=sha(raw),spmi_polling_fix=fw,spmi_emulation=tests,
        correction='SPMI polling initialization preserves inherited PIC interrupt state',
        hardware_boot_verified=False,usb_hardware_verified=False)
    #035's vendor byte identity refers to its pre-adaptation SPMI. Retain it as
    #baseline evidence and identify the single adapted module explicitly.
    record['vendor_usb_firmware']=dict(record['vendor_usb_firmware'],fd_sha256=sha(fd),
        adapted_modules=['SPMI'],unchanged_vendor_modules=26,original_depex_preserved=True)
    (a.out/'release.json').write_text(json.dumps(record,indent=2)+'\n')
    (a.out/'SHA256SUMS').write_text(sha(packed)+'  '+image.name+'\n')
    print(json.dumps(dict(image=str(image),sha256=sha(packed),firmware_sha256=sha(fd)),indent=2))

if __name__=='__main__':main()
