#!/usr/bin/env python3
"""Index Sony reference archive and copy selected hardware sources, never boot binaries."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

PROJECT = Path(__file__).resolve().parents[3]
SOURCE = Path('G:/67.2.A.3.141.tar_.bz2')
OUT = PROJECT / 'references/xperia-67.2.A.3.141-hardware'


def main():
    OUT.mkdir()
    with SOURCE.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    index, copied, interesting = [], [], []
    total = 0
    with tarfile.open(SOURCE, 'r|bz2') as archive:
        for member in archive:
            total += 1
            index.append({'path': member.name, 'bytes': member.size, 'type': member.type.decode('ascii', 'replace')})
            path = PurePosixPath(member.name)
            relevant = (path.suffix in ('.dts', '.dtsi') and
                        re.search('kalama|sony|pdx234|lxs|lge|lgsic|sm8550', member.name, re.I)) or (
                        re.search(r'/touchscreen/.*(?:lxs|lge|lgsic)', member.name, re.I) and
                        path.suffix in ('.c', '.h'))
            if re.search('pdx234|lxs|lgsic|somc.*kalama', member.name, re.I):
                interesting.append(member.name)
            if relevant and member.isfile() and member.size <= 8 << 20:
                if path.is_absolute() or '..' in path.parts or len(copied) >= 2500:
                    raise ValueError('Unsafe or unexpectedly broad hardware extraction')
                raw = archive.extractfile(member).read()
                name = hashlib.sha256(member.name.encode()).hexdigest()[:12] + '-' + path.name
                with (OUT / name).open('xb') as target:
                    target.write(raw)
                copied.append({'source_path': member.name, 'copy': name, 'bytes': len(raw),
                               'sha256': hashlib.sha256(raw).hexdigest()})
            if total % 20000 == 0:
                print('Archive members scanned:', total, 'Hardware files copied:', len(copied), flush=True)
    (OUT / 'archive-index.json').write_text(json.dumps(index, indent=2))
    (OUT / 'provenance.json').write_text(json.dumps(dict(source=str(SOURCE), source_bytes=SOURCE.stat().st_size,
        source_sha256=digest, reference_only=True, not_current_running_kernel_source=True,
        members=total, selected=copied, interesting_paths=interesting), indent=2))
    print(json.dumps({'members': total, 'copied_hardware_files': len(copied),
                      'reference_only': True, 'output': str(OUT)}, indent=2))


if __name__ == '__main__':
    main()
