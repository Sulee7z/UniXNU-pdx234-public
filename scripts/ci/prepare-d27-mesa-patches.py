#!/usr/bin/env python3
"""Resume the pinned Mesa sequence, recording Linux git new-file metadata fixes."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path('/mnt/e/UniXNU-sheng27-sony-20261113/metal-runtime-001')


def main():
    pins = json.loads((ROOT / 'scripts/data/adreno-compiler-inputs.json').read_text())
    source = ROOT / '.cache/mesa-work'
    records = []
    normalized = ROOT / 'linux-patches'
    normalized.mkdir(exist_ok=True)
    for name in pins['patches']:
        original = ROOT / name
        text = original.read_text()
        fixed = re.sub(r'(^diff --git [^\n]+\n)(--- /dev/null\n)',
                       r'\1new file mode 100644\n\2', text, flags=re.M)
        target = normalized / original.name
        target.write_text(fixed)
        records.append(dict(path=name,original_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),
                            applied_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                            metadata_only=text != fixed))
    with tempfile.TemporaryDirectory(dir=ROOT / '.cache') as tmp:
        env = dict(os.environ, GIT_INDEX_FILE=str(Path(tmp) / 'index'))
        def git(*args):
            return subprocess.check_output(['git', '-C', str(source), *args], env=env, text=True).strip()
        git('read-tree', 'HEAD')
        git('add', '-A')
        current = git('write-tree')
        git('read-tree', 'HEAD')
        states = [git('write-tree')]
        for row in records:
            git('apply', '--cached', str(normalized / Path(row['path']).name))
            states.append(git('write-tree'))
        if current not in states:
            raise ValueError('Mesa differs from every recorded patch prefix')
        prefix = states.index(current)
        for row in records[prefix:]:
            subprocess.run(['git', '-C', str(source), 'apply', str(normalized / Path(row['path']).name)], check=True)
        git('read-tree', 'HEAD');git('add', '-A')
        if git('write-tree') != states[-1]:
            raise ValueError('Final Mesa tree differs')
    # The upstream reverse validator reconstructs the base with the original
    # patches, independently of the Linux forward-application metadata.
    sys.path.insert(0, str(ROOT / 'scripts'))
    from mesa_patch_identity import validate_recorded_patches
    validate_recorded_patches(ROOT, source, pins)
    receipt = dict(base=pins['mesa']['commit'],initial_prefix=prefix,final_tree=states[-1],
                   patches=records,reverse_validation=True)
    (ROOT / 'linux-patches.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt,indent=2))


if __name__ == '__main__':main()
