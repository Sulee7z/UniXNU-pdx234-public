#!/usr/bin/env python3
"""Decode all Sony firmware modules without Windows path-length restrictions."""
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import urllib.request
import zipfile

PROJECT = Path('/mnt/g/UniXNU-Port')
OUT = Path('/root/unixnu-build/pdx234-vendor-extract')
TOOLS = Path('/root/unixnu-build/pdx234-tools')
URL = 'https://github.com/LongSoft/UEFITool/releases/download/A76/UEFIExtract_NE_A76_x64_linux.zip'
SHA = '1bee0a3556d47288a0cfbfb8f08ca791a35826686cf8fb998b5f2cefdc860619'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    TOOLS.mkdir(exist_ok=True)
    exe = TOOLS / 'UEFIExtract'
    if not exe.exists():
        with urllib.request.urlopen(URL, timeout=60) as response:
            raw = response.read()
        if hashlib.sha256(raw).hexdigest() != SHA:
            raise RuntimeError('Linux extractor package SHA mismatch')
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entry = next(name for name in archive.namelist() if Path(name).name in ('UEFIExtract', 'uefiextract'))
            exe.write_bytes(archive.read(entry))
        exe.chmod(0o755)
    OUT.mkdir()
    source = PROJECT / 'evidence/Xperia-XQ-DQ72/20261107T092807Z/firmware/uefi.img'
    if sha(source) != '47f257beb69b64632d7c5ce976f19390f2d7178528c8508c8bae7832aec52823':
        raise RuntimeError('Sony original firmware identity mismatch')
    image = OUT / 'uefi.img'
    shutil.copyfile(source, image)
    with (OUT / 'extract.log').open('xb') as log:
        result = subprocess.run([str(exe), str(image), 'all'], stdout=log, stderr=subprocess.STDOUT, timeout=180)
    if result.returncode:
        raise RuntimeError(f'Linux UEFI extraction failed: {result.returncode}; see {OUT}/extract.log')
    raw_config = next((OUT / 'uefi.img.dump').glob('**/2 uefiplat.cfg/1 Raw section/body.bin'))
    config = raw_config.read_bytes().rstrip(b'\0')
    exported = PROJECT / 'diagnostics/pdx234-vendor-uefiplat.cfg'
    exported.write_bytes(config)
    record = dict(source_sha256=sha(source), tool_package_sha256=SHA,
                  dump=str(OUT / 'uefi.img.dump'), info_files=sum(1 for _ in (OUT/'uefi.img.dump').rglob('info.txt')),
                  uefiplat_raw_sha256=sha(raw_config), uefiplat_export=str(exported),
                  uefiplat_export_sha256=hashlib.sha256(config).hexdigest(), device_operations=False)
    (PROJECT / 'ports/UniXNU-pdx234/evidence/sony-firmware-extraction.json').write_text(json.dumps(record, indent=2))
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
