#!/usr/bin/env python3
"""Replace only the030 firmware extent with the console-safe source build."""
from pathlib import Path
import hashlib,json,struct,subprocess

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')

def main():
    before=ROOT/'out/d27-pac-abi-release-20261115-030'
    out=ROOT/'out/d27-pac-abi-release-20261115-031';out.mkdir(exist_ok=False)
    record=json.loads((before/'release.json').read_text())
    raw=(before/'boot-pdx234-pac-abi-030.img').read_bytes()
    assert hashlib.sha256(raw).hexdigest()==record['sha256']
    memory=struct.unpack_from('<Q',raw,4096+0x200000+16)[0]
    start=4096+0x200000+memory;end=start+0x300000
    assert hashlib.sha256(raw[start:end]).hexdigest()==record['firmware_sha256']
    build=BASE/'firmware-high-memory-002'
    receipt=json.loads((build/'retained-result.json').read_text());fd=(build/'SILICIUM_RETAINED.fd').read_bytes()
    assert len(fd)==0x300000 and hashlib.sha256(fd).hexdigest()==receipt['sha256']
    fixed=raw[:start]+fd+raw[end:]
    assert fixed[:start]==raw[:start] and fixed[end:]==raw[end:]
    image=out/'boot-pdx234-pac-abi-031.img';image.write_bytes(fixed)
    assert image.read_bytes()==fixed
    record.update(image=str(image),label='PAC-ABI-031',sha256=hashlib.sha256(fixed).hexdigest(),
        firmware_sha256=receipt['sha256'],firmware_only_correction=True,
        screen_build_tag='PDX030 (kernel/config unchanged)',
        source_image_sha256=hashlib.sha256(raw).hexdigest(),
        correction='Restore darwinboot-dxe-log.patch: DEBUG before console connection',
        firmware_extent=[start,end])
    (out/'release.json').write_text(json.dumps(record,indent=2)+'\n')
    (out/'SHA256SUMS').write_text(record['sha256']+'  '+image.name+'\n')
    print(json.dumps(dict(image=str(image),sha256=record['sha256'],firmware_sha256=receipt['sha256']),indent=2))

if __name__=='__main__':main()
