#!/usr/bin/env python3
"""Verify the original link closure plus the incremental handoff supplement."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat


def main():
    root = Path(__file__).resolve().parent
    for manifest in ('incremental-files.json', 'native-link-inputs.json'):
        rows = json.loads((root/manifest).read_text())
        for value, row in rows.items():
            key = PurePosixPath(value)
            if manifest == 'native-link-inputs.json':
                if not key.is_absolute():
                    raise SystemExit('Expected absolute linker input: ' + value)
                key = PurePosixPath('layout')/str(key).lstrip('/')
            if key.is_absolute() or '..' in key.parts:
                raise SystemExit('Invalid supplement path: ' + str(key))
            path = root/str(key)
            if not path.is_file() or not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size != row['bytes']:
                raise SystemExit('Missing or wrong-sized input: ' + str(key))
            with path.open('rb') as file:
                if hashlib.file_digest(file, 'sha256').hexdigest() != row['sha256']:
                    raise SystemExit('Changed input: ' + str(key))
        print('Verified', len(rows), 'files from', manifest, flush=True)


if __name__ == '__main__':
    main()
