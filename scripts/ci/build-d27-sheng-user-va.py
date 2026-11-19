#!/usr/bin/env python3
"""Replay sheng27's user-VA hunks through a private Clang VFS overlay."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

DEVICE = Path(__file__).resolve().parents[2]
PATCH = DEVICE.parents[1]/'sources/UniXNU-sheng-20261109/patches/xnu-12377/zzzz-sheng-ipados27-bringup.patch'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def selected_hunks(text):
    selected = []
    for section in text.split('diff --git ')[1:]:
        lines = section.splitlines(keepends=True)
        relative = lines[0].split()[0].removeprefix('a/')
        starts = [i for i,line in enumerate(lines) if line.startswith('@@ ')]
        for number,start in enumerate(starts):
            end = starts[number+1] if number+1<len(starts) else len(lines)
            hunk = lines[start:end]
            if not any('T0SZ_USER' in line or 'TCR_EL1_KVA_ENTRY' in line for line in hunk):
                continue
            before = ''.join(line[1:] for line in hunk[1:] if line.startswith((' ', '-')))
            after = ''.join(line[1:] for line in hunk[1:] if line.startswith((' ', '+')))
            selected.append((relative,before,after))
    if not selected:
        raise ValueError('No pinned sheng27 user-VA hunks')
    return selected


def run(command, cwd, env, log):
    with log.open('x') as stream:
        done = subprocess.run(command,cwd=cwd,env=env,stdout=stream,stderr=subprocess.STDOUT)
    if done.returncode:
        raise RuntimeError(log.read_text()[-6000:])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree',type=Path,required=True)
    parser.add_argument('--mainline',type=Path,required=True)
    parser.add_argument('--native',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--strict-out',type=Path,required=True)
    parser.add_argument('--plan-only',action='store_true')
    args = parser.parse_args()
    for name in ('tree','mainline','native','out','strict_out'):
        setattr(args,name,getattr(args,name).resolve())
    args.out.mkdir(parents=True,exist_ok=False)
    out = args.out.resolve()
    work = args.tree/'.cache/xnu-work'
    objdir = args.tree/'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
    parent = args.native.resolve()
    saved = json.loads((parent/'report.json').read_text())
    if sha(parent/'native.macho') != saved['native_sha256'] or saved['carrier_enabled']:
        raise ValueError('Need the exact no-carrier native JOP parent')
    adapted, originals = {}, {}
    for relative,before,after in selected_hunks(PATCH.read_text()):
        original = work/relative
        text = adapted.get(relative,original.read_text())
        if text.count(before)!=1:
            raise ValueError('Pinned user-VA hunk does not match uniquely: '+relative)
        originals[relative] = original
        adapted[relative] = text.replace(before,after,1)
    paths, roots = {}, {}
    for relative,text in adapted.items():
        target = out/'source'/relative
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_text(text)
        original = originals[relative]
        paths[relative] = target
        roots[str(original)] = str(target)
        if original.suffix=='.h':
            exported = args.tree/'build/xnu/ios-obj/EXPORT_HDRS'/relative
            if exported.exists():
                if sha(exported)!=sha(original):
                    raise ValueError('Exported header differs from source: '+relative)
                roots[str(exported)] = str(target)
    link = json.loads((parent/'native-link.command.json').read_text())
    filelist = Path(link[link.index('-filelist')+1]).read_text().splitlines()
    units = []
    for recipe in objdir.rglob('*.json'):
        if not recipe.name.endswith(('.o.json','.cpo.json')):
            continue
        record = json.JSONDecoder().raw_decode(recipe.read_text())[0]
        arguments = record['arguments']
        old = Path(arguments[arguments.index('-o')+1])
        if not old.is_absolute():
            old = (Path(record['directory'])/old).resolve()
        if str(old) not in filelist:
            continue
        source = Path(record['file'])
        dep = old.with_suffix('.d')
        deps = dep.read_text(errors='replace') if dep.exists() else ''
        changed_source = str(source) in roots
        geometry = 'pmap_pt_geometry.h' in deps
        stripping = source.exists() and any(key in source.read_text(errors='replace') for key in
                                           ('VM_USER_STRIP','VM_KERNEL_STRIP'))
        if changed_source or geometry or stripping:
            units.append((old,record))
    if not units:
        raise ValueError('No original compile records matched the address-space closure')
    overlay = out/'overlay.json'
    overlay.write_text(json.dumps({'version':0,'use-external-names':False,'roots':[
        {'type':'file','name':name,'external-contents':target} for name,target in roots.items()]},indent=2)+'\n')
    report = dict(upstream_patch_sha256=sha(PATCH),patched_files=list(adapted),
                  original_sources={relative:sha(path) for relative,path in originals.items()},
                  original_native_sha256=saved['native_sha256'],compile_units=len(units),
                  original_object_bytes=sum(old.stat().st_size for old,_ in units),
                  compiler_include_order_retained=True,carrier_enabled=False,
                  intended_user_va_bits=47,kernel_va_and_4k_pages_retained=True,
                  runtime_qualified=False,device_operations=False)
    (out/'plan.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2),flush=True)
    if args.plan_only:
        return
    spec = importlib.util.spec_from_file_location('jop_compile',DEVICE/'scripts/ci/build-d27-native-jop-key.py')
    compiler = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(compiler)
    env = dict(os.environ,TMPDIR=str(out),PYTHONDONTWRITEBYTECODE='1')
    for number,(old,record) in enumerate(units):
        target = out/'objects'/old.relative_to(objdir)
        target.parent.mkdir(parents=True,exist_ok=True)
        command = compiler.replay(record,Path(record['file']),target)+['-ivfsoverlay',str(overlay)]
        log = out/('compile-'+str(number)+'.log')
        (out/('compile-'+str(number)+'.json')).write_text(json.dumps(command,indent=2)+'\n')
        run(command,record['directory'],env,log)
        if filelist.count(str(old))!=1:
            raise ValueError('Ambiguous original object: '+str(old))
        filelist[filelist.index(str(old))] = str(target)
    linked_list = out/'link.filelist'
    linked_list.write_text('\n'.join(filelist)+'\n')
    link[link.index('-filelist')+1] = str(linked_list)
    link[link.index('-o')+1] = str(out/'native.macho')
    env.update(CROSS_CLANG='/root/unixnu-build/pdx234-pac-toolchain/llvm/bin/clang-24',
               DARWIN_TRIPLE='arm64e-apple-ios27.0')
    env['PATH']='/root/unixnu-build/pdx234-pac-toolchain/CommandLineTools/usr/bin:'+env['PATH']
    (out/'native-link.command.json').write_text(json.dumps(link,indent=2)+'\n')
    run(link,objdir,env,out/'native-link.log')
    if any(sha(path)!=report['original_sources'][relative] for relative,path in originals.items()):
        raise ValueError('Baseline sources changed during private overlay build')
    report['native_sha256'] = sha(out/'native.macho')
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    command = [sys.executable,'-B',str(DEVICE/'scripts/ci/finish-strict5-prelink.py'),
               '--tree',str(args.tree),'--mainline',str(args.mainline),
               '--native',str(out/'native.macho'),'--output',str(args.strict_out)]
    run(command,args.tree,env,out/'strict.log')
    print((out/'strict.log').read_text()[-2500:])


if __name__=='__main__':
    main()
