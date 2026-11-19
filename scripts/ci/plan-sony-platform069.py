#!/usr/bin/env python3
"""Freeze the physical 069 link inputs and rebuild the brightness exec overlay."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ci'))
from block_descriptor_abi import enabled
from compile_dependencies import run_recorded, valid
from platform069.display_runtime import PATCH_NAME, adapt_exec
from platform069.integration import BASELINE_SHA, sha

FRESH = Path('/mnt/f/UniXNU-Port-artifacts/platform069-20261118')
BASELINE = FRESH.parent / 'platform067-20261118/native-platform067-full-002'
TEMPLATE = FRESH / 'size-platform069-002/plan.json'
TEMPLATE_SHA = '3d4af068eeaf1d67215f327d7daaceefc04980344befe35577b0090519cee936'


def load(path):
    return json.loads(path.read_text())


def save(path, value):
    with path.open('x') as stream:
        stream.write(json.dumps(value, indent=2) + '\n')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('provider', 'radio-host', 'display', 'runtime', 'adt', 'out'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    require(sha(TEMPLATE) == TEMPLATE_SHA, 'Unexpected size-plan template')
    plan = load(TEMPLATE)
    baseline = load(BASELINE / 'result.json')
    require(plan['baseline_native_sha256'] == baseline['native_sha256'] == BASELINE_SHA and
            sha(BASELINE / 'native.macho') == BASELINE_SHA, 'Exact delivered 068 native required')
    provider, host, display, runtime, adt, out = (x.resolve() for x in
        (a.provider, a.radio_host, a.display, a.runtime, a.adt, a.out))
    r, h, d, rt, tree = (load(x / 'result.json') for x in (provider, host, display, runtime, adt))
    require(all(row.get('passed') is True and row.get('device_operations') is False for row in (r, h, d, tree)),
            'Passing host build/check receipts required')
    require(h['provider'] == str(provider) and h['tests']['board2']['role_vectors'] == 16 and
            h['tests']['old007_negative']['old16_magic_rejected'] is True and
            h['sources'][str(provider / 'result.json')] == sha(provider / 'result.json'),
            'Board2 receipt does not cover the selected provider')
    require(d['baseline_native_sha256'] == BASELINE_SHA, 'Display uses a different baseline')
    require(rt['signature_pages_verified'] and rt['original_trust_modules_unchanged'] and
            {'display-bin/backboardd', 'display-lib/UniXNUBacklight.dylib'} <= rt['extra_signature_checks'].keys(),
            'Missing signed brightness runtime')
    require(tree['adt']['passed'] and sha(tree['adt']['output']) == tree['adt']['output_sha256'],
            'Sony ADT readback identity differs')

    inputs = plan['inputs']
    old_radio = FRESH / 'radio-provider069-006'
    old_display = FRESH / 'display-driver-010'
    old_display_sources = plan['result_metadata']['platform069_oled']['sources']
    for path in list(inputs):
        if (Path(path).is_relative_to(old_radio) or Path(path).is_relative_to(old_display) or
                path in old_display_sources or path == str(ROOT / 'drivers/SonyWcn/platform069/adapt069.py')):
            del inputs[path]
        else:
            require(sha(path) == inputs[path], 'Unrelated template input changed: ' + path)
    plan['compile_receipts'] = [path for path in plan['compile_receipts']
        if not any(Path(path).is_relative_to(parent) for parent in (old_radio, old_display))]

    def pin(path, expected=None):
        path = str(Path(path).absolute())
        actual = sha(path)
        require(expected is None or actual == expected, 'Reviewed input changed: ' + path)
        require(path not in inputs or inputs[path] == actual, 'Conflicting input identity: ' + path)
        inputs[path] = actual
        return path

    def compile_receipt(path):
        path = pin(path)
        row = load(Path(path))
        require(valid(row) and enabled(row['command']) and
                '-fptrauth-function-pointer-type-discrimination' in row['command'],
                'Invalid compile receipt: ' + path)
        pin(row['object'], row['object_sha256'])
        require(path not in plan['compile_receipts'], 'Duplicate compile receipt: ' + path)
        plan['compile_receipts'].append(path)
        return row

    pin(TEMPLATE, TEMPLATE_SHA)
    for folder in (provider, host, display, runtime, adt):
        pin(folder / 'result.json')
    for name, expected in (('addon', rt['addon_sha256']), ('trust', rt['trust_sha256'])):
        pin(rt[name], expected)
    pin(tree['adt']['output'], tree['adt']['output_sha256'])
    for path, digest in r['inputs'].items():
        pin(path, digest)
    for path, digest in d['sources'].items():
        pin(path, digest)
    for row in r['commands'].values():
        path = Path(row['object'] + '.dependencies.json')
        require(load(path) == row, 'Provider compile receipt differs: ' + str(path))
        compile_receipt(path)
    for name in ('Backlight069', 'Display069', 'Resources069', 'Native069'):
        compile_receipt(display / 'objects' / (name + '.o.dependencies.json'))
    require(len(plan['added_archives']) == 1 and Path(plan['added_archives'][0]).parent == old_radio,
            'Unexpected additional archive selection')
    plan['added_archives'] = [pin(r['provider_archive'], r['provider_sha256'])]
    # The frozen ArmCpu owner was composed independently. Never assume a new
    # provider defines the same startup/dispatch contract merely by name.
    owner = Path(r['requires_main_owner_integration'])
    pin(owner)
    arm = load(owner)
    old_arm = old_radio / 'source/ArmCpu069.cpp'
    pin(arm['armcpu_source'], sha(old_arm))
    for row in plan['archive_replacements']:
        archive = Path(row['new'])
        if archive.parent == old_radio:
            key = {'libSonyWcn.a': 'board', 'libSonyAth12kCore.a': 'core'}[archive.name]
            row.update(new=pin(r[key + '_archive'], r[key + '_sha256']),
                replaced_members=r[key + '_replaced_members'], added_members=r[key + '_added_members'])
        elif archive.parent == old_display:
            require(row['old'] == d['replaces'], 'Wrong display archive predecessor')
            row.update(new=pin(d['archive'], d['sha256']), replaced_members=d['replaced_members'],
                added_members=d['added_members'])

    overlays = [row for row in baseline['native_source_patches'] if row['native_source_patch'] == PATCH_NAME]
    require(len(overlays) == 1, 'Expected a single baseline exec overlay')
    overlay = overlays[0]
    blocks = baseline['block_descriptor_abi']['replacements']
    require(len(blocks) == 66, 'Expected exactly 66 baseline Block objects')
    index = next(i for i, row in enumerate(blocks) if row['source'] == overlay['source'])
    old = blocks[index]
    dep = load(Path(pin(old['dependency_receipt'], old['dependency_sha256'])))
    require(valid(dep) and dep['object'] == old['new_object'] and sha(dep['object']) == old['new_sha256'],
            'Baseline exec compile identity differs')
    original = Path(pin(overlay['original_source'], overlay['original_source_sha256']))
    pin(overlay['source'], overlay['source_sha256'])
    pin(Path(__file__).resolve())
    out.mkdir(parents=True, exist_ok=False)
    source = out / 'kern_exec.c'
    source.write_text(adapt_exec(original.read_text()))
    obj = out / Path(old['new_object']).name
    command = []
    args = iter(dep['command'])
    for token in args:
        if token in ('-MF', '-MT', '-MQ', '-MJ'):
            next(args)
        elif token not in ('-MD', '-MMD', '-MP'):
            command.append({old['source']: str(source), old['new_object']: str(obj)}.get(token, token))
    with (out / 'kern_exec.log').open('x') as log:
        completed = run_recorded(command, cwd=old['directory'], stdout=log, stderr=subprocess.STDOUT, timeout=180)
    require(completed.returncode == 0, 'kern_exec compile failed: ' + str(out / 'kern_exec.log'))
    receipt_path = obj.with_name(obj.name + '.dependencies.json')
    new = compile_receipt(receipt_path)
    require({k: v for k, v in dep['dependencies'].items() if k != old['source']} ==
            {k: v for k, v in new['dependencies'].items() if k != str(source)},
            'Unrelated exec dependencies changed')
    update = {**old, 'source': pin(source), 'source_sha256': sha(source),
        'new_object': str(obj), 'new_sha256': new['object_sha256'], 'command': new['command'],
        'dependency_receipt': str(receipt_path), 'dependency_sha256': sha(receipt_path)}
    block_path = out / 'blocks-exec-update.json'
    save(block_path, dict(replacement_index=index, replacement_row=update, replace_selected_object=old['new_object']))
    plan['block_replacement_updates'] = [dict(path=pin(block_path), sha256=sha(block_path))]
    plan['object_replacements'].append(dict(old=old['new_object'], new=str(obj)))
    plan['source_patch_updates'].append({**overlay, 'source': str(source), 'source_sha256': sha(source)})
    adapter = Path(pin(ROOT / 'ci/platform069/display_runtime.py'))
    plan['source_qualifiers'].append(dict(module='platform069.display_runtime', sha256=sha(adapter)))
    plan['result_metadata'].update(platform069_radio=r, platform069_oled=d,
        platform069_runtime=dict(receipt=str(runtime / 'result.json'), sha256=sha(runtime / 'result.json'),
            adt_receipt=str(adt / 'result.json'), hardware_verified=False))
    save(out / 'plan.json', plan)
    print(json.dumps(dict(plan=str(out / 'plan.json'), changed_block_row=index, inherited_blocks=len(blocks),
        selected_provider=r['provider_archive'], selected_display=d['archive'], device_operations=False)))


if __name__ == '__main__':
    main()
