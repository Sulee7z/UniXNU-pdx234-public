#!/usr/bin/env python3
"""Enumerate recursive pinned gitlinks and compare every staged component file."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess

BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args])


def entries(root, revision):
    for raw in git(root, 'ls-tree', '-rz', revision).split(b'\0'):
        if raw:
            meta, name = raw.split(b'\t', 1)
            mode, kind, oid = meta.decode().split()
            yield mode, kind, oid, os.fsdecode(name)


def content(path):
    if path.is_symlink():
        return os.fsencode(os.readlink(path))
    return path.read_bytes() if path.is_file() else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    build = json.loads((BASE / 'native-audit-003/plan.json').read_text())
    tree = Path(build['tree'])
    targets = {
        'ArmCpu': tree / 'drivers/ArmCpu', 'ArmDTPlatform': tree / 'drivers/ArmDTPlatform',
        'RamBlock': tree / 'drivers/RamBlock',
        'ShengUfs': BASE / 'source-storage-004/device/drivers/ShengUfs',
        'GopFramebuffer': BASE / 'display-source-007/drivers/GopFramebuffer',
        'AppleKeyStoreState': BASE / 'display-source-007/drivers/AppleKeyStoreState',
        'Adreno740': BASE / 'gpu-source-004/drivers/Adreno740',
        'AdrenoMetal': BASE / 'metal-d27-qualified-001/drivers/AdrenoMetal',
        'XnuPrelink': BASE / 'strict-audit-003/XnuPrelink',
    }
    for name in ('AdrenoFirmware', 'AdrenoPM4', 'ArmSmmu4K'):
        targets[name] = BASE / 'gpu-source-004/kits' / name
    modules = []

    def scan(root, revision, prefix):
        for mode, kind, oid, relative in entries(root, revision):
            if kind != 'commit':
                continue
            repo = root / relative
            name = Path(relative).name
            staged = targets.get(name)
            row = dict(path=prefix + '/' + relative, revision=oid, repository=str(repo),
                       staged=str(staged) if staged else None, files=[], semantic_review_complete=False)
            if not (repo / '.git').exists():
                row['error'] = 'pinned submodule checkout unavailable'
                modules.append(row)
                continue
            for fmode, fkind, blob, filename in entries(repo, oid):
                if fkind != 'blob':
                    continue
                expected = git(repo, 'cat-file', 'blob', blob)
                actual = content(repo / filename)
                candidate = content(staged / filename) if staged else None
                state = ('not-mapped-to-build' if staged is None else
                         'missing' if candidate is None else 'same' if candidate == expected else 'different')
                item = dict(path=filename, mode=fmode, git_object=blob,
                            reference_sha256=hashlib.sha256(expected).hexdigest(),
                            checkout_matches=actual == expected, staged_status=state)
                if candidate is not None:
                    item['staged_sha256'] = hashlib.sha256(candidate).hexdigest()
                row['files'].append(item)
            row['counts'] = dict(Counter(f['staged_status'] for f in row['files']))
            tracked = {f['path'] for f in row['files']}
            row['staged_additions'] = []
            if staged and staged.is_dir():
                for path in sorted(staged.rglob('*')):
                    relative_path = path.relative_to(staged)
                    if '.git' in relative_path.parts or '__pycache__' in relative_path.parts:
                        continue
                    if (path.is_file() or path.is_symlink()) and relative_path.as_posix() not in tracked:
                        data = content(path)
                        row['staged_additions'].append(dict(path=relative_path.as_posix(),
                            sha256=hashlib.sha256(data).hexdigest(), bytes=len(data)))
            modules.append(row)
            scan(repo, oid, row['path'])

    for name, directory, pin in [
        ('sheng', 'sheng', '1108068537d5396edb2c63b2f8c6f5b97b0a4bbc'),
        ('core', 'UniXNU', '82b847c4ac3f68a57024b3082ffa3a03442defd9'),
        ('sm8550', 'sm8550', 'a9f45dc60c035084b95463781538380f4c3606c9'),
    ]:
        scan(BASE / 'sources' / directory, pin, name)
    report = dict(modules=modules, status='recursive file identity inventory; semantic review pending',
                  staged_build='native-audit-003', runtime_verified=False)
    (args.out / 'submodules.json').write_text(json.dumps(report, indent=2) + '\n')
    for row in modules:
        print(row['path'], row.get('counts', row.get('error')))
    print('modules', len(modules), 'files', sum(len(row['files']) for row in modules))


if __name__ == '__main__':
    main()
