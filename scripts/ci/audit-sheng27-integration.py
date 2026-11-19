#!/usr/bin/env python3
"""Inventory pinned sheng27 inputs against actual Sony build records; no readiness claim."""
import argparse
from collections import Counter,defaultdict
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tomllib

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
DEVICE=Path(__file__).resolve().parents[2]
PIN='1108068537d5396edb2c63b2f8c6f5b97b0a4bbc'

def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def git(root,*args):
    return subprocess.check_output(['git','-C',str(root),*args])

def write(path,data):path.write_text(json.dumps(data,indent=2)+'\n')

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--build',type=Path,default=BASE/'native-audit-003')
    parser.add_argument('--strict',type=Path,default=BASE/'strict-audit-003')
    parser.add_argument('--release',type=Path,default=DEVICE/'out/d27-pac-abi-release-20261115-031/release.json')
    options=parser.parse_args();out=options.out;out.mkdir(parents=True,exist_ok=False)
    sheng=BASE/'sources/sheng';core=BASE/'sources/UniXNU';sony=BASE/'sources/sony'
    assert git(sheng,'rev-parse','HEAD').decode().strip()==PIN
    plan=json.loads((options.build/'plan.json').read_text());tree=Path(plan['tree'])
    native=json.loads((options.build/'result.json').read_text())
    strict=json.loads((options.strict/'result.json').read_text())
    if native['native_sha256']!=strict['native_sha256']:raise ValueError('Native and strict build mismatch')
    board=tomllib.loads((sheng/'board.toml').read_text())
    release=json.loads(options.release.read_text())
    display=Path(native['display_source']['archive']).parents[2]
    screen=Path(native['boot_screen']['archive']).parent
    gpu=Path(native['gpu_source']['archive']).parents[2]
    # Enumerate every tracked upstream file, including gitlinks, rather than
    # selecting only familiar modules. MacOS/other-OS inputs are scoped explicitly.
    tracked=[]
    for record in git(sheng,'ls-tree','-rz','HEAD').split(b'\0'):
        if not record:continue
        meta,name=record.split(b'\t');mode,kind,oid=meta.decode().split();name=name.decode()
        row=dict(path=name,mode=mode,kind=kind,git_object=oid)
        if kind=='blob':
            expected=git(sheng,'cat-file','blob',oid);p=sheng/name
            actual=p.readlink().as_posix().encode() if p.is_symlink() else p.read_bytes() if p.is_file() else None
            row.update(bytes=len(expected),sha256=hashlib.sha256(expected).hexdigest(),
                       checkout_matches=actual==expected)
        tracked.append(row)
    write(out/'sheng-tracked-files.json',tracked)
    jobs=[];compiled=defaultdict(list)
    for job in plan['jobs']:
        p=Path(job['source']);actual=sha(p) if p.is_file() else None
        row=dict(group=job['group'],source=str(p),recorded_sha256=job['source_sha256'],
                 actual_sha256=actual,matches=actual==job['source_sha256'],object=str(job['output']),
                 object_exists=Path(job['output']).is_file())
        jobs.append(row);compiled[p.name].append(str(p))
    write(out/'native-build-inputs.json',jobs)
    # Display/GPU/screen recipes compile outside the batch plan; retain their
    # exact commands and artifact receipts separately.
    receipts={}
    for name in [display.name,gpu.name,screen.name,'metal-package-002','firmware-high-memory-002']:
        p=BASE/name/'result.json';receipts[name]=json.loads(p.read_text()) if p.exists() else None
    write(out/'component-receipts.json',receipts)
    package=[]
    locations=[tree/'kits/sheng',BASE/'source-storage-004/device/package',display/'kits/sheng',gpu/'kits/sheng',screen]
    for p in sorted((sheng/'package').rglob('*')):
        if not p.is_file():continue
        rel=p.relative_to(sheng/'package');copies=[]
        for dest in locations:
            candidate=dest/rel
            if candidate.is_file():copies.append(dict(path=str(candidate),sha256=sha(candidate),same=sha(candidate)==sha(p)))
        package.append(dict(path=str(rel),sha256=sha(p),copies=copies,native_compile_sources=compiled.get(p.name,[])))
    write(out/'package-copies.json',package)
    # Both shared OS and board series, in their declared order.
    patchsets=[]
    pairs=[(sheng/'patches/xnu-12377',sony/'patches/sheng27'),
           (core/'profiles/os/ipados-27.0.1-24A446/patches/xnu',core/'profiles/os/ios-27.0.1-24A446-iphone14/patches/xnu')]
    for original,adapted in pairs:
        series=original/'series'
        if not series.exists():continue
        for line in series.read_text().splitlines():
            name=line.strip()
            if not name or name.startswith('#'):continue
            if name.startswith('arch:'):
                p=(core/'profiles/arch/arm64e'/name.split(':',1)[1]).resolve()
                q=p if name in (adapted/'series').read_text().splitlines() else adapted/'MISSING'
            else:
                p=original/name;q=adapted/name
            if not p.is_file():raise ValueError('Missing selected patch '+str(p))
            patchsets.append(dict(upstream=str(p),sha256=sha(p),sony=str(q),
                exists=q.is_file(),same=q.is_file() and sha(q)==sha(p),
                touched_files=re.findall(r'^\+\+\+ b/(.+)$',p.read_text(),re.M)))
    write(out/'ordered-patches.json',patchsets)
    flags={}
    for job in plan['jobs']:
        if job['group']!='xnu':continue
        values={}
        for arg in job['command']:
            match=re.fullmatch(r'(?:-D)?(XNU_[A-Z0-9_]+|CONFIG_[A-Z0-9_]+)(?:=(.*))?',arg)
            if match:values[match[1]]=match[2] if match[2] is not None else '1'
        flags[job['source']]=values
    write(out/'actual-compile-flags.json',flags)
    desired={}
    for line in (sheng/'configs/sheng_ipados27_defconfig').read_text().splitlines():
        if line.startswith('CONFIG_'):k,v=line.split('=',1);desired[k]=v
    reference_args=board['payload']['kernel_args'];actual_args=release['kernel_args'].split()
    argmap=lambda args:{x.split('=',1)[0]:x.split('=',1)[1] if '=' in x else True for x in args}
    ref=argmap(reference_args);actual=argmap(actual_args)
    args=[dict(key=k,sheng=ref.get(k),sony=actual.get(k),same=ref.get(k)==actual.get(k)) for k in sorted(ref.keys()|actual.keys())]
    write(out/'boot-arguments.json',args)
    roots=board['os_overrides']['ipados-27.0.1-24A446']['kernel']['prelink']['roots']
    report=json.loads((options.strict/'kernel.json').read_text())
    closure=report['closure']
    write(out/'prelink-selection.json',dict(sheng_roots=roots,sony_roots=strict['selected_profile']['roots'],actual_closure=closure))
    upstream=(sheng/'package/LegacyDisplayProbe.cpp').read_text()
    staged=(display/'kits/sheng/LegacyDisplayProbe.cpp').read_text()
    probe_calls=lambda text:re.findall(r'^\s*(?:if \([^\n]+\) )?((?:sheng|native)_[a-z0-9_]+_probe)\(',text,re.M)
    write(out/'initialization.json',dict(sheng=probe_calls(upstream),sony=probe_calls(staged)))
    summary=dict(sheng_commit=PIN,core_commit=git(core,'rev-parse','HEAD').decode().strip(),
        build=str(options.build),strict=str(options.strict),release_arguments_source=str(options.release),
        candidate_is_packaged=False,
        tracked_files=len(tracked),tracked_checkout_mismatches=[x['path'] for x in tracked if x.get('checkout_matches') is False],
        native_jobs=len(jobs),native_source_identity_failures=[x for x in jobs if not x['matches']],
        packages=len(package),patches=len(patchsets),patch_differences=[x for x in patchsets if not x['same']],
        argument_differences=[x for x in args if not x['same']],reference_defconfig=desired,
        removed_initializers=sorted(set(probe_calls(upstream))-set(probe_calls(staged))),
        status='inventory completed; semantic review and repairs pending',runtime_verified=False)
    write(out/'summary.json',summary)
    print(json.dumps({k:v for k,v in summary.items() if k not in ['reference_defconfig','patch_differences','native_source_identity_failures']},indent=2))
    print('Native source identity failures:',len(summary['native_source_identity_failures']))

if __name__=='__main__':main()
