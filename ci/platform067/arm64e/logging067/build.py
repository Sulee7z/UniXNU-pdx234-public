#!/usr/bin/env python3
"""Stage exact official logging consumers/provider; target compile only, no link/device."""
from __future__ import annotations
import argparse
import copy
import difflib
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from audit import BASE, FRESH as SNAPSHOTS, NATIVE_SHA, REPO, sha, load, selected_inputs, read_receipt, ar_members
sys.path.insert(0, str(HERE))
import source as overlay
sys.path.insert(0, str(REPO / 'ci'))
from compile_dependencies import run_recorded, valid
from block_descriptor_abi import enabled, FLAGS


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def clean(command):
    out, i = [], 0
    while i < len(command):
        if command[i] in ('-MF', '-MT', '-MQ', '-MJ'):
            i += 2
        elif command[i] in ('-MD', '-MMD', '-MP'):
            i += 1
        else:
            out.append(command[i]); i += 1
    return out


def qualify(rec, obj):
    if sha(obj) != rec.get('object_sha256', rec.get('sha256')):
        raise ValueError('Selected object identity changed: ' + str(obj))
    if not valid(rec):
        raise ValueError('Selected compiler/dependencies changed: ' + str(obj))
    src = rec['source']
    if sha(src) != rec.get('source_sha256', rec['dependencies'].get(src)):
        raise ValueError('Selected source changed: ' + src)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=HERE / 'build-001')
    parser.add_argument('--exec-source', type=Path, default=HERE.parent / 'addon-size-compile-001/kern_exec.c')
    parser.add_argument('--compile', action='store_true')
    a = parser.parse_args()
    out = a.out.resolve()
    if not out.is_relative_to(HERE) or out == HERE or out.exists():
        raise ValueError('Require fresh output below logging067 only')
    native = BASE / 'native-sony-touch-066-002'
    baseline = load(native / 'result.json')
    if sha(native / 'native.macho') != NATIVE_SHA:
        raise ValueError('Exact066 baseline required')
    _, inputs = selected_inputs(native)
    plan = load(BASE / 'native-screen007-055-001/plan.json')
    work = Path(plan['tree']) / '.cache/xnu-work'
    exec_source = a.exec_source.resolve()
    # Accepted official addon source, not the old066 translation unit.
    if sha(exec_source) != 'f53f9ae1393621368bbba4bdcea39c35d472f154994123a288119bc071e211f6':
        raise ValueError('Exec composition requires main accepted addon-length source; pass a reviewed future adapter separately')
    out.mkdir(parents=True)
    (out / 'objects').mkdir()
    (out / 'include/kern').mkdir(parents=True)
    staged = {}
    patch_inputs = {}
    for name in overlay.PATCHES:
        p = SNAPSHOTS / 'sheng/patches/xnu-12377' / name
        patch_inputs[str(p)] = sha(p)
    for name in ['BootLog.c', 'BootLatencyFiles.h']:
        p = SNAPSHOTS / 'sheng/package' / name
        patch_inputs[str(p)] = sha(p)
    patches = []
    # Stage header first. Other unchanged header consumers are rebuilt with it,
    # even though their XNU_BOOT_PROGRESS=1 branch is text-identical.
    header_input = work / 'osfmk/kern/boot_progress.h'
    header = out / 'include/kern/boot_progress.h'
    header.write_text(overlay.adapt_header(header_input.read_text()))
    (out / 'BootLatencyFiles.h').write_bytes((SNAPSHOTS / 'sheng/package/BootLatencyFiles.h').read_bytes())
    patch_inputs[str(header_input)] = sha(header_input)
    patch_inputs[str(exec_source)] = sha(exec_source)
    jobs = []
    wanted = {'startup.o': 'osfmk/kern/startup.c', '001-bsd_init.o': 'bsd/kern/bsd_init.c',
              '008-kern_exec.o': 'bsd/kern/kern_exec.c', 'kern_exit.o': 'bsd/kern/kern_exit.c',
              'debug.o': 'osfmk/kern/debug.c'}
    blocks = {r['new_object']: (i, r) for i, r in enumerate(baseline['block_descriptor_abi']['replacements'])}
    for obj in inputs:
        if obj.endswith('.a'):
            continue
        receipt_path, rec = read_receipt(obj)
        if not rec:
            continue
        relative = wanted.get(Path(obj).name)
        header_user = any(Path(p).name == 'boot_progress.h' for p in rec.get('dependencies', {}))
        if not relative and not header_user:
            continue
        qualify(rec, obj)
        original = Path(rec['source'])
        input_source = exec_source if relative == 'bsd/kern/kern_exec.c' else original
        text = input_source.read_text()
        if relative:
            text = overlay.ADAPTERS[relative](text)
        target = out / (Path(relative).name if relative else original.name)
        if target in staged:
            raise ValueError('Source basename collision')
        target.write_text(text)
        staged[target] = str(input_source)
        delta = '\n'.join(difflib.unified_diff(input_source.read_text().splitlines(), text.splitlines(),
                                             fromfile='a/' + (relative or original.name), tofile='b/' + (relative or original.name))) + '\n'
        diffpath = out / (target.name + '.patch')
        diffpath.write_text(delta)
        patches.append({'path': str(diffpath), 'sha256': sha(diffpath), 'input': str(input_source),
                        'input_sha256': sha(input_source), 'output': str(target), 'output_sha256': sha(target),
                        'xnu_relative': relative, 'header_only_rebuild': relative is None})
        destination = out / 'objects' / Path(obj).name
        command = clean(rec['command'])
        command[command.index(str(original))] = str(target)
        command[command.index('-o') + 1] = str(destination)
        command[1:1] = ['-I', str(out / 'include')]
        command += ['-iquote', str(original.parent)]
        if not enabled(command):
            command += FLAGS
        if '-fptrauth-function-pointer-type-discrimination' not in command:
            command.append('-fptrauth-function-pointer-type-discrimination')
        if any(v.startswith('-fno-ptrauth') for v in command):
            raise ValueError('PAC disable forbidden')
        directory = rec.get('directory')
        if not directory:
            paths = [Path(p).parent for p in rec['dependencies'] if Path(p).name == 'meta_features.h']
            if len(paths) != 1:
                raise ValueError('Cannot recover compile cwd')
            directory = str(paths[0])
        row = {'old': obj, 'old_sha256': sha(obj), 'new': str(destination), 'source': str(target),
               'source_sha256': sha(target), 'compile_command': command, 'directory': directory,
               'old_receipt': str(receipt_path), 'old_receipt_sha256': sha(receipt_path),
               'input_source': str(input_source), 'input_source_sha256': sha(input_source),
               'xnu_relative': relative, 'header_user': header_user}
        if obj in blocks:
            row['block_replacement_index'] = blocks[obj][0]
        jobs.append(row)
    if len(jobs) != 10:
        raise ValueError('Expected5changed+5header-only direct objects, got ' + str(len(jobs)))
    # Only the BootLog member changes. SourceStorage, NativeUfs, RamBlock,
    # watchdog and all Sony log-window bindings remain from exact066.
    boot_obj = BASE / 'native-screen007-055-001/objects/storage/BootLog.o'
    boot_receipt_path, boot_rec = read_receipt(str(boot_obj))
    qualify(boot_rec, boot_obj)
    provider_input = Path(boot_rec['source'])
    provider = out / 'BootLog.c'
    provider.write_text(overlay.adapt_provider(provider_input.read_text()))
    for name in ['Wn8030.h', 'ShengAudioAbi.h']:
        p = provider_input.parent / name
        (out / name).write_bytes(p.read_bytes())
        patch_inputs[str(p)] = sha(p)
    diffpath = out / 'BootLog.c.patch'
    diffpath.write_text('\n'.join(difflib.unified_diff(provider_input.read_text().splitlines(), provider.read_text().splitlines(),
                                                     fromfile='a/package/BootLog.c', tofile='b/package/BootLog.c')) + '\n')
    boot_command = clean(boot_rec['command'])
    boot_command[boot_command.index(str(provider_input))] = str(provider)
    boot_destination = out / 'objects/BootLog.o'
    boot_command[boot_command.index('-o') + 1] = str(boot_destination)
    boot_command += FLAGS
    boot_command += ['-iquote', str(provider_input.parent)]
    boot_dir = boot_rec.get('directory')
    if not boot_dir:
        boot_dir = str(next(Path(p).parent for p in boot_rec['dependencies'] if Path(p).name == 'meta_features.h'))
    jobs.append({'old': str(boot_obj), 'old_sha256': sha(boot_obj), 'new': str(boot_destination),
                 'source': str(provider), 'source_sha256': sha(provider), 'compile_command': boot_command,
                 'directory': boot_dir, 'old_receipt': str(boot_receipt_path), 'old_receipt_sha256': sha(boot_receipt_path),
                 'input_source': str(provider_input), 'input_source_sha256': sha(provider_input),
                 'archive': str(BASE / 'native-screen007-055-001/archives/libShengUfs.a'), 'member': 'BootLog.o'})
    patch_inputs[str(provider_input)] = sha(provider_input)
    report = {'baseline_native_sha256': NATIVE_SHA, 'official_patch_inputs': patch_inputs,
              'source_overlay_helper': str(HERE / 'source.py'), 'source_overlay_helper_sha256': sha(HERE / 'source.py'),
              'jobs': jobs, 'patches': patches, 'header_input': str(header_input), 'header_input_sha256': sha(header_input),
              'staged_header': str(header), 'staged_header_sha256': sha(header),
              'preserved': ['Sony32MiB log window', 'existing NativeUfs/SourceStorage/RamBlock', 'data-persist=0',
                            'writer header-last ordering', 'watchdog/error returns/mount checks', 'corelinuxVM disabled'],
              'unselected_fresh_features': ['platform-sleep', 'fresh video telemetry', 'new previous-run disk reader',
                                           'watchdog policy refresh', 'whole fresh BootLog replacement'],
              'shared_source_mutation': False, 'device_operations': False, 'linked': False, 'qualified': False}
    save(out / 'plan.json', report)
    if a.compile:
        for row in jobs:
            obj = Path(row['new'])
            with Path(str(obj) + '.log').open('x') as log:
                done = run_recorded(row['compile_command'], cwd=row['directory'], stdout=log, stderr=subprocess.STDOUT, timeout=180)
            if done.returncode:
                raise RuntimeError(str(obj) + '\n' + Path(str(obj) + '.log').read_text()[-9000:])
            receipt = Path(str(obj) + '.dependencies.json')
            rec = load(receipt)
            if not valid(rec) or not enabled(rec['command']):
                raise ValueError('New dependency/BlockABI receipt invalid')
            row.update(new_sha256=sha(obj), dependency_receipt=str(receipt), dependency_sha256=sha(receipt))
            print('Compiled', obj.name, flush=True)
        report['compiled'] = True
    else:
        report['compiled'] = False
    report['source_and_object_unchanged'] = all(sha(row['old']) == row['old_sha256'] and
                                              sha(row['input_source']) == row['input_source_sha256'] for row in jobs)
    save(out / 'result.json', report)
    print(json.dumps({'out': str(out), 'objects': len(jobs), 'compiled': report['compiled'], 'linked': False}))


if __name__ == '__main__':
    main()
