#!/usr/bin/env python3
"""Extract captured Sony firmware volumes with a pinned upstream UEFIExtract."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import urllib.request
import zipfile

DEVICE = Path(__file__).resolve().parents[1]
PROJECT = DEVICE.parents[1]
INPUT = PROJECT / 'evidence/Xperia-XQ-DQ72/20261107T092807Z/firmware'
TOOL_DIR = PROJECT / 'tools/xperia-uefiextract-A76'
URL = 'https://github.com/LongSoft/UEFITool/releases/download/A76/UEFIExtract_NE_A76_win64.zip'
SHA = '0e723a7c57526e1d872d8caa3ff33f1220b1102844d19ec75ebbfb30fb351621'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    exe = TOOL_DIR / 'UEFIExtract.exe'
    if not exe.is_file():
        request = urllib.request.Request(URL, headers={'User-Agent': 'UniXNU-Sony-local-build'})
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read()
        if hashlib.sha256(raw).hexdigest() != SHA:
            raise RuntimeError('Upstream UEFIExtract package SHA differs')
        TOOL_DIR.mkdir(exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue
                basename = Path(member.filename).name
                with (TOOL_DIR / basename).open('xb') as output:
                    output.write(archive.read(member))
        (TOOL_DIR / 'package.json').write_text(json.dumps(dict(url=URL, sha256=SHA), indent=2))
    capture = json.loads((INPUT / 'manifest.json').read_text())
    record = dict(tool=str(exe), tool_sha256=digest(exe), package_sha256=SHA, images=[], device_operations=False)
    for name in ('uefi', 'imagefv', 'xbl', 'abl'):
        source = INPUT / (name + '.img')
        expected = next(row for row in capture['firmware'] if row['name'] == name)
        if digest(source) != expected['sha256']:
            raise RuntimeError('Firmware capture changed')
        log = INPUT / f'extract-{name}.log'
        if log.exists():
            raise RuntimeError('Preserve previous extraction run')
        print('Extracting original Sony', name, flush=True)
        with log.open('xb') as output:
            result = subprocess.run([str(exe), str(source), 'all'], stdout=output,
                                    stderr=subprocess.STDOUT, timeout=180)
        dump = Path(str(source) + '.dump')
        record['images'].append(dict(name=name, exit_code=result.returncode, dump=str(dump),
                                     files=sum(1 for _ in dump.rglob('info.txt')) if dump.exists() else 0))
        (INPUT / 'extraction.json').write_text(json.dumps(record, indent=2))
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
