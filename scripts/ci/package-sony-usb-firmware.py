#!/usr/bin/env python3
"""Replace the verified034 firmware extent, retaining its exact kernel/payload."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

ROOT=Path(__file__).resolve().parents[2]


def digest(data):return hashlib.sha256(data).hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--firmware',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    prior=ROOT/'out/d27-pac-abi-release-20261116-034'
    record=json.loads((prior/'release.json').read_text())
    raw=(prior/Path(record['image']).name).read_bytes()
    if digest(raw)!=record['sha256']:raise ValueError('034 changed')
    fw=json.loads((a.firmware/'result.json').read_text())
    verification=json.loads((a.firmware/'usb-verification.json').read_text())
    fd=Path(fw['fd']).read_bytes()
    if len(fd)!=0x300000 or digest(fd)!=fw['sha256'] or verification['fd_sha256']!=fw['sha256']:
        raise ValueError('USB firmware verification differs')
    if verification['vendor_modules_verified']!=27 or not verification['usb_prepare_driver_embedded']:
        raise ValueError('USB integration incomplete')
    memory=struct.unpack_from('<Q',raw,4096+0x200000+16)[0]
    start=4096+0x200000+memory;end=start+len(fd)
    if digest(raw[start:end])!=record['firmware_sha256']:raise ValueError('Firmware extent mismatch')
    packed=raw[:start]+fd+raw[end:]
    a.out.mkdir(parents=True,exist_ok=False)
    image=a.out/'boot-pdx234-pac-abi-035.img';image.write_bytes(packed)
    if image.read_bytes()!=packed:raise ValueError('Image write mismatch')
    record.update(image=str(image),label='PAC-ABI-035',sha256=digest(packed),firmware_sha256=digest(fd),
        firmware_only_correction=True,screen_build_tag='PDX034 (034 kernel/config retained)',
        source_image_sha256=digest(raw),firmware_extent=[start,end],vendor_usb_firmware=verification,
        correction='Sony USB device/configuration DXE dependency chain and ReadyToBoot USBFN preparation',
        hardware_boot_verified=False,usb_hardware_verified=False)
    (a.out/'release.json').write_text(json.dumps(record,indent=2)+'\n')
    (a.out/'SHA256SUMS').write_text(record['sha256']+'  '+image.name+'\n')
    print(json.dumps(dict(image=str(image),sha256=record['sha256'],firmware_sha256=digest(fd)),indent=2))


if __name__=='__main__':main()
