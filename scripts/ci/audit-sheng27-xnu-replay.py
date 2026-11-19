#!/usr/bin/env python3
"""Reconstruct all selected XNU patches in a private index and compare source bytes."""
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')

def main():
    out=BASE/'full-sheng27-audit-002/xnu-replay';out.mkdir(exist_ok=False)
    work=BASE/'sources/UniXNU/out/pdx234/ios-27.0.1-24A446-iphone14/pdx234_sheng27_bulk'
    receipt=json.loads((work/'xnu-inputs.json').read_text());source=work/'tree/.cache/xnu-work'
    paths=set();records=[]
    with tempfile.TemporaryDirectory(dir=out) as temp:
        env=dict(os.environ,GIT_INDEX_FILE=str(Path(temp)/'index'))
        def git(*args):return subprocess.check_output(['git','-C',str(source),*args],env=env)
        git('read-tree',receipt['commit'])
        for row in receipt['patches']:
            path=Path(row['path']);data=path.read_bytes()
            assert hashlib.sha256(data).hexdigest()==row['sha256'],str(path)
            paths.update(re.findall(r'^\+\+\+ b/(.+)$',data.decode(),re.M))
            git('apply','--cached',str(path))
        for name in sorted(paths):
            expected=subprocess.run(['git','-C',str(source),'show',':'+name],env=env,capture_output=True)
            actual=source/name
            if expected.returncode:
                records.append(dict(path=name,status='deleted' if not actual.exists() else 'unexpected-present'));continue
            content=actual.read_bytes() if actual.is_file() else b''
            same=content==expected.stdout
            row=dict(path=name,same=same,expected_sha256=hashlib.sha256(expected.stdout).hexdigest(),
                     actual_sha256=hashlib.sha256(content).hexdigest())
            if not same:
                diff=''.join(difflib.unified_diff(expected.stdout.decode(errors='replace').splitlines(True),
                     content.decode(errors='replace').splitlines(True),fromfile='selected/'+name,tofile='actual/'+name))
                target=out/(name.replace('/','__')+'.diff');target.write_text(diff);row['diff']=str(target)
            records.append(row)
    result=dict(base_commit=receipt['commit'],patches_replayed=len(receipt['patches']),files=records,
                differences=[r for r in records if r.get('same') is False or r.get('status')=='unexpected-present'])
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print('Replayed',result['patches_replayed'],'patches;',len(records),'touched files;',len(result['differences']),'differences')
    print(json.dumps(result['differences'],indent=2))

if __name__=='__main__':main()
