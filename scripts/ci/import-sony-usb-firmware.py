#!/usr/bin/env python3
"""Import hash-qualified Sony USB DXE modules and platform dependencies.

Run on Windows using the pinned UEFIExtract flat-output mode. No device access.
Vendor PE images and DEPEX stay byte-identical; binary inputs remain ignored.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import uuid

DEVICE = Path(__file__).resolve().parents[2]
PROJECT = DEVICE.parents[1]
SOURCE_SHA = '47f257beb69b64632d7c5ce976f19390f2d7178528c8508c8bae7832aec52823'
MODULES = ('EnvDxe', 'SmemDxe', 'DALSys', 'HWIODxeDriver', 'ChipInfo',
           'PlatformInfoDxeDriver', 'SPMI', 'PmicDxe', 'CmdDbDxe', 'PwrUtilsDxe',
           'RpmhDxe', 'NpaDxe', 'ULogDxe', 'VcsDxe', 'ClockDxe', 'ICBDxe',
           'RscDxe', 'DALTLMM', 'HALIOMMU', 'IPCCDxe', 'GlinkDxe',
           'PmicGlinkDxe', 'UsbPwrCtrlDxe', 'UsbConfigDxe', 'UsbfnDwc3Dxe',
           'UsbDeviceDxe', 'UsbInitDxe')


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def dependencies(data):
    result = []; at = 0
    while at < len(data):
        op = data[at]; at += 1
        if op == 2:
            if at + 16 > len(data): raise ValueError('Truncated DEPEX')
            result.append(str(uuid.UUID(bytes_le=data[at:at+16]))); at += 16
        elif op not in (3,4,5,6,7,8):
            raise ValueError('Unsupported vendor DEPEX opcode')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--firmware', type=Path, default=DEVICE.parent/'uefi-pdx234')
    args = parser.parse_args()
    source = PROJECT/'evidence/Xperia-XQ-DQ72/20261107T092807Z/firmware/uefi.img'
    if sha(source) != SOURCE_SHA: raise ValueError('Sony firmware capture changed')
    tool = PROJECT/'tools/xperia-uefiextract-A76/UEFIExtract.exe'
    args.out.mkdir(parents=True, exist_ok=False)
    copy = args.out/'u.img'; shutil.copyfile(source, copy)
    result = subprocess.run([str(tool),str(copy),'unpack'],capture_output=True,timeout=120)
    (args.out/'extract.log').write_bytes(result.stdout+result.stderr)
    if result.returncode: raise RuntimeError('UEFIExtract failed')
    extracted = Path(str(copy)+'.dump')
    records = []
    for name in MODULES:
        images = list(extracted.glob('Section_PE32_image_*_'+name+'_body.bin'))
        if len(images) != 1: raise ValueError('Ambiguous module '+name)
        image = images[0]; raw = image.read_bytes()
        pe = struct.unpack_from('<I',raw,0x3c)[0]
        if raw[:2]!=b'MZ' or raw[pe:pe+4]!=b'PE\0\0' or struct.unpack_from('<H',raw,pe+4)[0]!=0xaa64:
            raise ValueError('Expected AARCH64 PE '+name)
        guid = re.fullmatch(r'Section_PE32_image_([0-9A-F-]{36})_'+name+r'_body.bin',image.name)[1]
        deps = extracted/('Section_DXE_dependency_'+guid+'_'+name+'_body.bin')
        if not deps.is_file(): raise ValueError('Missing original DEPEX '+name)
        folder = args.firmware/'Binaries/pdx234/QcomPkg/Drivers'/name
        folder.mkdir(parents=True,exist_ok=True)
        for src,ext in [(image,'efi'),(deps,'depex')]:
            target = folder/(name+'.'+ext)
            if target.exists() and target.read_bytes()!=src.read_bytes():raise ValueError('Existing vendor input differs '+str(target))
            if not target.exists():shutil.copyfile(src,target)
        inf = ('# Sony owner-extracted binary; original PE and DEPEX preserved.\n'
               '[Defines]\n  INF_VERSION = 0x00010005\n  BASE_NAME = '+name+'\n'
               '  FILE_GUID = '+guid+'\n  MODULE_TYPE = DXE_DRIVER\n  VERSION_STRING = 1.0\n'
               '[Binaries.AARCH64]\n  PE32|'+name+'.efi|*\n  DXE_DEPEX|'+name+'.depex|*\n')
        target=folder/(name+'.inf')
        if target.exists() and target.read_text()!=inf:raise ValueError('INF differs '+str(target))
        target.write_text(inf)
        records.append(dict(name=name,guid=guid.lower(),pe_sha256=sha(image),depex_sha256=sha(deps),
                            depex_requires=dependencies(deps.read_bytes()),bytes=len(raw)))
    manifest=dict(source=str(source),source_sha256=SOURCE_SHA,extractor_sha256=sha(tool),
                  modules=records,vendor_bytes_modified=False,hardware_verified=False)
    (args.out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (args.firmware/'Binaries/pdx234/usb-import.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print('Imported',len(records),'Sony modules with original DEPEX')


if __name__ == '__main__':main()
