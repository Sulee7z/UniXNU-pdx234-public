#!/usr/bin/env python3
"""Relink verified 055 native inputs with the tested first-frame screen archive."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
NATIVE_SHA='b55008bc37af64b4e791f8943deebb132e0b832210c4185f667fa8d48127c310'
SCREEN_SHA='034aad481f5ff83a08c2b1bad9e4ef0905d38cafbe8d043e2367827b13f04063'


def digest(path):
    with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('native','screen','tests','out'):p.add_argument('--'+key,type=Path,required=True)
    p.add_argument('--framebuffer-trace',type=Path,help='Qualified incremental native framebuffer-call trace receipt')
    a=p.parse_args()
    if a.out.exists():p.error('Require a new output directory')
    if shutil.disk_usage(ROOT).free<8*1024**3:raise RuntimeError('Workspace below8GiB')
    prior=json.loads((a.native/'result.json').read_text());screen=json.loads((a.screen/'result.json').read_text())
    if (prior['native_sha256']!=NATIVE_SHA or digest(a.native/'native.macho')!=NATIVE_SHA or
        prior['boot_screen']['sha256']!=SCREEN_SHA or digest(prior['boot_screen']['archive'])!=SCREEN_SHA):
        raise ValueError('Require exact055 native and screen007')
    if not prior['pac_authentication_retained'] or prior['auth_instruction_patches']:raise ValueError('PAC policy differs')
    sys.path.insert(0,str(ROOT/'ci'));from native_source_overlays import validate_overlays
    validate_overlays(prior,digest)
    for name,expected in prior['archive_sha256'].items():
        if digest(a.native/'archives'/name)!=expected:raise ValueError('Native archive changed: '+name)
    for key in ('gpu_source','display_source'):
        if digest(prior[key]['archive'])!=prior[key]['sha256']:raise ValueError('Driver archive changed: '+key)
    for source in screen['sources']:
        if digest(source['source'])!=source['sha256']:raise ValueError('Screen source changed')
    for key in ('diagnostic_headers','first_frame_headers'):
        for name,expected in screen[key].items():
            if digest(a.screen/name)!=expected:raise ValueError('Screen header changed: '+name)
    swift=screen.get('swift_trap_diagnostic',{})
    if (not swift.get('verified') or digest(ROOT/'ci/PdxSwiftTrapDiagnostic.h')!=swift['header_sha256'] or
        digest(a.screen/'PdxSwiftTrapDiagnostic.h')!=swift['header_sha256'] or
        digest(ROOT/'ci/swift_trap_diagnostic.py')!=swift['overlay_sha256'] or
        digest(swift['tests_receipt'])!=swift['tests_sha256']):
        raise ValueError('Swift trap-message qualification differs')
    if not json.loads(Path(swift['tests_receipt']).read_text()).get('passed'):
        raise ValueError('Swift diagnostic test did not pass')
    tests=json.loads(a.tests.read_text())
    if (not tests.get('passed') or not tests.get('native_compile_provenance_verified') or
        tests.get('native_build',{}).get('sha256')!=screen['sha256'] or
        not screen.get('first_frame_diagnostics') or digest(screen['archive'])!=screen['sha256']):
        raise ValueError('Require tested first-frame archive')
    for name,expected in tests['headers'].items():
        if digest(a.screen/name)!=expected:raise ValueError('Tested header differs: '+name)
    command=json.loads((a.native/'native-link.command.json').read_text())
    before='-Wl,-force_load,'+prior['boot_screen']['archive']
    if command.count(before)!=1:raise ValueError('Old screen archive not unique')
    command[command.index(before)]='-Wl,-force_load,'+screen['archive']
    if command[command.index('-o')+1]!=str(a.native/'native.macho'):raise ValueError('Unexpected old output')
    a.out.mkdir(parents=True)
    command[command.index('-o')+1]=str(a.out/'native.macho')
    # Validate the actual cached objects against their compile receipts, including
    # the four tail objects not listed by -filelist. Reuse never weakens prelink.
    filelist=Path(command[command.index('-filelist')+1])
    objects=[Path(line) for line in filelist.read_text().splitlines()]
    objects.extend(Path(value) for value in command if value.endswith('.o'))
    checked=[]
    for obj in objects:
        receipt=obj.with_name(obj.name+'.json');field='sha256'
        if not receipt.exists() and obj.name=='lastkernelconstructor.last.o':
            receipt=obj.with_name('lastkernelconstructor.o.json');field='archive_object_sha256'
        r=json.loads(receipt.read_text())
        if field=='archive_object_sha256' and r.get('archive_output')!=str(obj):raise ValueError('Generated tail provenance differs')
        if r['exit'] or digest(obj)!=r[field]:raise ValueError('Cached object changed: '+str(obj))
        checked.append(dict(path=str(obj),sha256=r[field]))
    framebuffer_trace=None
    if a.framebuffer_trace:
        trace_path=a.framebuffer_trace/'result.json' if a.framebuffer_trace.is_dir() else a.framebuffer_trace
        framebuffer_trace=json.loads(trace_path.read_text())
        # The exact incremental receipt is normalized after checking its source
        # adapter, PAC command, original object and bounded host verification.
        if not framebuffer_trace.get('verified'):
            raise ValueError('Framebuffer native-call trace receipt not verified')
        if (not framebuffer_trace.get('native_pac_dispatch_verified') or
            not framebuffer_trace.get('source_method_envelope_only') or
            framebuffer_trace.get('vtable_interposition') is not False or
            framebuffer_trace.get('policy_changes') is not False or
            framebuffer_trace.get('auth_instruction_patches') is not False):
            raise ValueError('Framebuffer trace changes the native dispatch contract')
        from compile_dependencies import valid as dependencies_valid
        deps=json.loads(Path(framebuffer_trace['dependency_receipt']).read_text())
        test_path=Path(framebuffer_trace['test_receipt']);trace_tests=json.loads(test_path.read_text())
        if (not dependencies_valid(deps) or digest(test_path)!=framebuffer_trace['test_receipt_sha256'] or
            not trace_tests.get('passed') or digest(framebuffer_trace['header'])!=framebuffer_trace['header_sha256'] or
            digest(ROOT/'ci/PdxFramebufferCallTrace.h')!=framebuffer_trace['header_sha256'] or
            digest(ROOT/'ci/framebuffer_call_trace.py')!=framebuffer_trace['overlay_sha256']):
            raise ValueError('Framebuffer compilation or test inputs changed')
        replacement=Path(framebuffer_trace['object'])
        original=Path(framebuffer_trace['original_object'])
        if (digest(replacement)!=framebuffer_trace['object_sha256'] or
            digest(original)!=framebuffer_trace['original_object_sha256']):
            raise ValueError('Framebuffer object identity differs')
        patch=framebuffer_trace['source_patch']
        from framebuffer_call_trace import adapt_source
        if (digest(patch['source'])!=patch['source_sha256'] or
            digest(patch['original_source'])!=patch['original_source_sha256'] or
            Path(patch['source']).read_text()!=adapt_source(Path(patch['original_source']).read_text())):
            raise ValueError('Framebuffer source overlay differs')
        if [str(obj) for obj in objects].count(str(original))!=1:raise ValueError('Original framebuffer dispatcher object not unique')
        text=filelist.read_text()
        if text.splitlines().count(str(original))!=1:raise ValueError('Original dispatcher absent from filelist')
        new_list=a.out/'link.filelist';new_list.write_text('\n'.join(str(replacement) if line==str(original) else line for line in text.splitlines())+'\n')
        command[command.index('-filelist')+1]=str(new_list)
    plan=json.loads((a.native/'plan.json').read_text())
    env=dict(os.environ,CROSS_CLANG=plan['compiler'],DARWIN_TRIPLE='arm64e-apple-ios27.0',
             CROSS_EXTRA_FLAGS=prior['pac_flag'],TMPDIR=str(a.out))
    env['PATH']=str(Path(command[0]).parent)+':'+env['PATH']
    (a.out/'native-link.command.json').write_text(json.dumps(command,indent=2)+'\n')
    with (a.out/'native-link.log').open('x') as log:
        result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=300)
    if result.returncode:raise RuntimeError((a.out/'native-link.log').read_text()[-6500:])
    record=copy.deepcopy(prior)
    record.update(native=str(a.out/'native.macho'),native_sha256=digest(a.out/'native.macho'),boot_screen=screen,
        reused_objects=len(checked),relinked_from=str(a.native.resolve()),relinked_from_sha256=NATIVE_SHA,
        first_frame_diagnostics=True,diagnostic_test_receipt=str(a.tests.resolve()),diagnostic_test_sha256=digest(a.tests),
        runtime_qualified=False,device_operations=False)
    if framebuffer_trace:
        record['framebuffer_call_trace']=framebuffer_trace
        record['native_source_patches'].append(framebuffer_trace['source_patch'])
    validate_overlays(record,digest)
    (a.out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    (a.out/'reused-object-identities.json').write_text(json.dumps(checked,indent=2)+'\n')
    print(json.dumps(dict(native=record['native'],sha256=record['native_sha256'],objects_checked=len(checked)),indent=2))


if __name__=='__main__':main()
