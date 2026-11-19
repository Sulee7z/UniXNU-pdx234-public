#!/usr/bin/env python3
"""Install the pinned upstream Linux ipsw binary without changing host packages."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import urllib.request

ROOT = Path('/root/unixnu-build/pdx234-tools/ipsw-3.1.743')
URL = 'https://github.com/blacktop/ipsw/releases/download/v3.1.743/ipsw_3.1.743_linux_x86_64.tar.gz'
SHA = '56e9ba754781dfeaa3b84f733ad25e63ef8e2683214a321e06b31a0d85f95e4c'
BYTES = 33899467


def main() -> None:
    ROOT.mkdir()
    request = urllib.request.Request(URL, headers={'User-Agent': 'UniXNU-PDX234-input-builder'})
    with urllib.request.urlopen(request, timeout=120) as response:
        data = response.read()
    if len(data) != BYTES or hashlib.sha256(data).hexdigest() != SHA:
        raise RuntimeError('Pinned upstream tool archive changed')
    (ROOT / 'release.tar.gz').write_bytes(data)
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        items = [item for item in archive.getmembers() if item.isfile() and Path(item.name).name == 'ipsw']
        if len(items) != 1:
            raise RuntimeError('Expected exactly one ipsw executable')
        with archive.extractfile(items[0]) as source:
            binary = source.read()
        (ROOT / 'ipsw').write_bytes(binary)
        (ROOT / 'ipsw').chmod(0o755)
    version = subprocess.check_output([str(ROOT / 'ipsw'), 'version'], text=True)
    (ROOT / 'tool.json').write_text(json.dumps(dict(url=URL, archive_sha256=SHA,
        binary_sha256=hashlib.sha256(binary).hexdigest(), version=version), indent=2))
    print(version)


if __name__ == '__main__':
    main()
