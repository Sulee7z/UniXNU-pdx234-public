#!/usr/bin/env python3
"""Add the PDX070 runtime and persistent diagnostics to a fresh 069-style plan."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ci'))
from block_descriptor_abi import enabled
from compile_dependencies import run_recorded, valid
from platform069.integration import sha
from platform069 import recovery070


def load(path):
    return json.loads(Path(path).read_text())


def save(path, data):
    with path.open('x') as file:
        file.write(json.dumps(data, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('base-plan', 'out'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    base = args.base_plan.resolve()
    out = args.out.resolve()
    plan = load(base)
    inputs = plan['inputs']
    for path, digest in inputs.items():
        if sha(path) != digest:
            raise ValueError('Input drift: ' + path)
    out.mkdir(parents=True, exist_ok=False)

    def pin(path):
        inputs[str(path)] = sha(path)
        return str(path)

    def compile_overlay(overlay, receipt_path, out_name, adapter, directory):
        dep = load(receipt_path)
        if not valid(dep) or sha(dep['object']) != dep['object_sha256'] or not enabled(dep['command']):
            raise ValueError('Invalid predecessor compile receipt: ' + receipt_path)
        original = Path(overlay['original_source']).read_text()
        source = out / Path(dep['source']).name
        source.write_text(adapter(original))
        obj = out / out_name
        command = []
        tokens = iter(dep['command'])
        for token in tokens:
            if token in ('-MF', '-MT', '-MQ', '-MJ'):
                next(tokens)
            elif token not in ('-MD', '-MMD', '-MP'):
                command.append({dep['source']: str(source), dep['object']: str(obj)}.get(token, token))
        with obj.with_suffix('.compile.log').open('x') as log:
            result = run_recorded(command, cwd=directory, stdout=log, stderr=subprocess.STDOUT, timeout=180)
        if result.returncode:
            raise RuntimeError(obj.with_suffix('.compile.log').read_text()[-5000:])
        receipt = obj.with_name(obj.name + '.dependencies.json')
        new = load(receipt)
        if (not valid(new) or not enabled(new['command']) or
                '-fptrauth-function-pointer-type-discrimination' not in new['command'] or
                {k: v for k, v in dep['dependencies'].items() if k != dep['source']} !=
                {k: v for k, v in new['dependencies'].items() if k != str(source)}):
            raise ValueError('Unexpected compiler ABI/dependency change')
        plan['compile_receipts'].remove(receipt_path)
        plan['compile_receipts'].append(pin(receipt))
        overlay.update(source=pin(source), source_sha256=sha(source))
        pin(obj)
        return obj, receipt, new

    updates = plan['source_patch_updates']
    old_update = plan['block_replacement_updates'][0]['path']
    block = load(old_update)
    row = block['replacement_row']
    exec_obj, dep_path, dep = compile_overlay(
        next(x for x in updates if x['native_source_patch'] == recovery070.PATCH_NAME),
        row['dependency_receipt'], '008-kern_exec.o', recovery070.adapt_exec, row['directory'])
    old_object = row['new_object']
    for item in plan['object_replacements']:
        if item['new'] == old_object:
            item['new'] = str(exec_obj)
            break
    else:
        raise ValueError('No selected replacement exec object')
    row.update(source=dep['source'], source_sha256=sha(dep['source']), new_object=str(exec_obj),
               new_sha256=sha(exec_obj), dependency_receipt=str(dep_path), dependency_sha256=sha(dep_path), command=dep['command'])
    update_path = out / 'blocks-exec-update.json'
    save(update_path, block)
    plan['block_replacement_updates'] = [dict(path=pin(update_path), sha256=sha(update_path))]

    bootlog = next(x for x in plan['member_replacements'] if Path(x['object']).name == 'BootLog.o')
    predecessor = bootlog['object'] + '.dependencies.json'
    old_bootlog = plan['result_metadata']['platform069_crashes']['member_objects'][0]
    if old_bootlog['member'] != 'BootLog.o':
        raise ValueError('Unexpected BootLog provenance')
    log_obj, log_receipt, _ = compile_overlay(
        next(x for x in updates if x['native_source_patch'] == 'crashes069-persistent-lines'),
        predecessor, 'BootLog.o', recovery070.adapt_boot_log, old_bootlog['directory'])
    bootlog['object'] = str(log_obj)
    # Preserve policy verification while letting the new adapter own BootLog.
    policy = ROOT / 'ci/platform069/recovery070_policy.py'
    adapter = ROOT / 'ci/platform069/recovery070.py'
    plan['source_qualifiers'] = [row for row in plan['source_qualifiers']
        if row['module'] not in ('platform069.crashes.qualify', 'platform069.display_runtime')]
    for module, path in (('platform069.recovery070', adapter), ('platform069.recovery070_policy', policy)):
        plan['source_qualifiers'].append(dict(module=module, sha256=sha(path)))
        pin(path)
    pin(base)
    pin(Path(__file__).resolve())
    plan['result_metadata']['platform069_followup070'] = dict(
        bootlog=str(log_obj), bootlog_dependencies=str(log_receipt), hardware_verified=False)
    save(out / 'plan.json', plan)
    print(out / 'plan.json')


if __name__ == '__main__':
    main()
