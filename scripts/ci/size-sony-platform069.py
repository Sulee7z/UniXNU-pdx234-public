#!/usr/bin/env python3
"""Shrink selected069 objects without changing source, ABI, or link layout."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ci'))
from block_descriptor_abi import enabled
from compile_dependencies import run_recorded, valid
from platform069.integration import BASELINE_SHA, sha


def symbols(path):
    text = subprocess.check_output(['llvm-nm', '-g', str(path)], text=True, timeout=20)
    return {words[-1] for line in text.splitlines() if len(words := line.split()) >= 3 and words[-2] != 'U'}


def text_size(path):
    result = subprocess.check_output(['llvm-size', '--format=darwin', str(path)], text=True, timeout=20)
    match = re.search(r'^\s*Section \(__TEXT, __text\): (\d+)$', result, re.M)
    if not match:
        raise ValueError('Missing code section: ' + str(path))
    return int(match[1])


def optimize(path, selected, out):
    dep = json.loads(path.read_text()); source = Path(dep['source']); old = Path(dep['object'])
    if not valid(dep) or sha(old) != dep['object_sha256'] or source.as_posix() not in dep['dependencies']:
        raise ValueError('Invalid selected compile dependency record: ' + str(path))
    old_command = dep['command']
    if not enabled(old_command) or '-fptrauth-function-pointer-type-discrimination' not in old_command:
        raise ValueError('Both pointer authentication options are required')
    if [v for v in old_command if v.startswith('-O')] != ['-O2']:
        raise ValueError('Expected exactly one -O2 option')
    if selected != old and selected.name != source.stem + '.late.o':
        raise ValueError('Unexpected post-processing of selected object')
    cwd = dep.get('cwd') or dep.get('directory')
    if not cwd:
        parents = {str(Path(v).parent) for v in dep['dependencies'] if Path(v).name == 'meta_features.h'}
        if len(parents) != 1:
            raise ValueError('No unique recorded compile working directory')
        cwd = parents.pop()
    command = []; i = 0
    while i < len(old_command):
        value = old_command[i]; i += 1
        if value in ('-MF', '-MT', '-MQ', '-MJ'):
            i += 1
        elif value not in ('-MD', '-MMD', '-MP'):
            command.append('-Oz' if value == '-O2' else value)
    obj = out / old.name; command[command.index('-o') + 1] = str(obj)
    env = dict(os.environ, CCC_OVERRIDE_OPTIONS='# +-Wno-unused-but-set-global +-Wno-missing-designated-field-initializers')
    log = obj.with_suffix('.log')
    with log.open('x') as stream:
        done = run_recorded(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=180)
    if done.returncode:
        raise RuntimeError(log.read_text()[-7000:])
    receipt = obj.with_name(obj.name + '.dependencies.json')
    new_dep = json.loads(receipt.read_text())
    if not valid(new_dep) or new_dep['dependencies'] != dep['dependencies'] or sha(source) != dep['dependencies'][str(source)]:
        raise ValueError('Source/include identities changed during optimization')
    member = obj
    if selected != old:
        member = out / selected.name
        subprocess.run(['llvm-objcopy-23', '--remove-section=__DATA,__mod_init_func',
            '--globalize-symbol=__GLOBAL__sub_I_' + source.name, str(obj), str(member)], check=True, timeout=20)
    if symbols(member) != symbols(selected):
        raise ValueError('Externally defined symbol set changed: ' + old.name)
    before, after = text_size(selected), text_size(member)
    return dict(source=str(source), old=str(selected), new=str(member), sha256=sha(member),
        compile_receipt=str(receipt), old_code_bytes=before, new_code_bytes=after, saved_bytes=before-after)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--member', action='append', required=True)
    args = parser.parse_args(); plan = json.loads(args.plan.read_text())
    if plan.get('baseline_native_sha256') != BASELINE_SHA:
        raise ValueError('Wrong native baseline')
    for path, digest in plan['inputs'].items():
        if sha(path) != digest:
            raise ValueError('Input changed: ' + path)
    args.out.mkdir(parents=True, exist_ok=False); out = args.out.resolve()
    selection = [(row, 'object') for row in plan.get('member_replacements', [])]
    selection += [(row, 'new') for row in plan.get('object_replacements', [])]
    jobs = []
    for name in args.member:
        row, field = next((row, field) for row, field in selection if Path(row[field]).name == name)
        selected = Path(row[field]); raw = selected.with_name(name.replace('.late.o', '.o'))
        receipt = raw.with_name(raw.name + '.dependencies.json')
        if str(receipt) not in plan['compile_receipts']:
            raise ValueError('Optimization target lacks selected compile provenance: ' + name)
        if any(update['replace_selected_object'] == str(selected) for update in plan.get('block_replacement_updates', [])):
            raise ValueError('Do not reoptimize a Blocks selection without new qualification')
        jobs.append((row, field, selected, receipt))
    if len(set(args.member)) != len(jobs):
        raise ValueError('Duplicate size target')
    with ThreadPoolExecutor(max_workers=4) as pool:
        builds = list(pool.map(lambda job: optimize(job[3], job[2], out), jobs))
    for (row, field, _, receipt), build in zip(jobs, builds):
        if build['saved_bytes'] <= 0:
            continue
        row[field] = build['new']; plan['compile_receipts'].remove(str(receipt))
        plan['compile_receipts'].append(build['compile_receipt'])
        for p in (build['new'], build['compile_receipt']):
            plan['inputs'][p] = sha(p)
    report = dict(passed=True, source_plan=str(args.plan.resolve()), source_plan_sha256=sha(args.plan),
        builds=builds, saved_bytes=sum(max(row['saved_bytes'], 0) for row in builds),
        compiler_change='-O2 to -Oz', sources_unchanged=True, exported_symbols_unchanged=True,
        source_archives_unchanged=True, pac_and_blocks_flags_preserved=True, device_operations=False)
    result = out / 'result.json'; result.write_text(json.dumps(report, indent=2) + '\n')
    plan['inputs'][str(result)] = sha(result); plan['result_metadata']['platform069_size'] = report
    (out / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
