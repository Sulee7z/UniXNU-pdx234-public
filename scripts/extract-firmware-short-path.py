#!/usr/bin/env python3
"""Work around MAX_PATH while extracting the same hash-qualified Sony firmware."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

DEVICE = Path(__file__).resolve().parents[1]
PROJECT = DEVICE.parents[1]
INPUT = PROJECT / 'evidence/Xperia-XQ-DQ72/20261107T092807Z/firmware'
SHORT = Path('G:/pdx234-fw')


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def main():
    SHORT.mkdir()
    original = json.loads((INPUT / 'manifest.json').read_text())
    tool = PROJECT / 'tools/xperia-uefiextract-A76/UEFIExtract.exe'
    record = dict(reason='Windows MAX_PATH, not firmware corruption', copied_from=str(INPUT), outputs=[])
    for name in ('uefi', 'abl'):
        source = INPUT / (name + '.img')
        expected = next(row for row in original['firmware'] if row['name'] == name)['sha256']
        if sha(source) != expected:
            raise RuntimeError('Firmware source changed')
        target = SHORT / (name + '.img')
        shutil.copyfile(source, target)
        if sha(target) != expected:
            raise RuntimeError('Short-path copy differs')
        with (SHORT / f'{name}-extract.log').open('xb') as log:
            result = subprocess.run([str(tool), str(target), 'all'], stdout=log,
                                    stderr=subprocess.STDOUT, timeout=180)
        record['outputs'].append(dict(name=name, sha256=expected, exit_code=result.returncode,
                                      info_files=sum(1 for _ in Path(str(target)+'.dump').rglob('info.txt'))))
        (SHORT / 'manifest.json').write_text(json.dumps(record, indent=2))
        print(record['outputs'][-1], flush=True)


if __name__ == '__main__':
    main()
