#!/usr/bin/env python3
"""Stage bounded peripheral repairs from the exact PDX070 plan."""
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
from platform069.peripherals071 import adapt_boot_log, display_resources, dma, picker

BASE = Path('/mnt/f/UniXNU-Port-artifacts/platform069-20261118')
PLAN = BASE / 'plan-final070-001/plan.json'
PLAN_SHA = '3feaceb43f5c613e3e8a72afa943313e34ba4ead6ce63333da19d24a51206d11'


def load(path):
    return json.loads(Path(path).read_text())


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', required=True, type=Path)
    out = p.parse_args().out.resolve()
    if not out.is_relative_to(BASE) or sha(PLAN) != PLAN_SHA:
        raise ValueError('Exact PDX070 plan and separate F: output required')
    plan = load(PLAN)
    inputs = plan['inputs']
    for path, expected in inputs.items():
        if sha(path) != expected:
            raise ValueError('PDX070 input drift: ' + path)
    out.mkdir()
    new_objects = {}

    def pin(path):
        inputs[str(path)] = sha(path)
        return str(path)

    def compile_member(name, transform, cwd=None):
        paths = [x for x in plan['compile_receipts'] if Path(x).name == name + '.dependencies.json']
        if len(paths) != 1:
            raise ValueError('Missing unique PDX070 compiler receipt: ' + name)
        old = load(paths[0])
        if not valid(old) or sha(old['object']) != old['object_sha256'] or not enabled(old['command']):
            raise ValueError('Unqualified predecessor: ' + name)
        source = out / Path(old['source']).name
        source.write_text(transform(Path(old['source']).read_text()))
        obj = out / name
        cmd = []
        tokens = iter(old['command'])
        for token in tokens:
            if token in ('-MF', '-MT', '-MQ', '-MJ'):
                next(tokens)
            elif token not in ('-MD', '-MMD', '-MP'):
                cmd.append({old['source']: str(source), old['object']: str(obj)}.get(token, token))
        with (out / (name + '.log')).open('x') as log:
            done = run_recorded(cmd, cwd=cwd or old.get('cwd') or ROOT,
                                stdout=log, stderr=subprocess.STDOUT, timeout=120)
        if done.returncode:
            raise RuntimeError((out / (name + '.log')).read_text()[-5000:])
        receipt = obj.with_name(name + '.dependencies.json')
        cur = load(receipt)
        if (not valid(cur) or not enabled(cur['command']) or
                {k: v for k, v in old['dependencies'].items() if k != old['source']} !=
                {k: v for k, v in cur['dependencies'].items() if k != str(source)}):
            raise ValueError('Unexpected compiler dependency drift: ' + name)
        plan['compile_receipts'].remove(paths[0])
        plan['compile_receipts'].append(pin(receipt))
        pin(obj)
        pin(source)
        new_objects[name] = dict(object=str(obj), source=str(source), dependencies=str(receipt), old=old['object'])
        return str(obj)

    def patch_archive(path, *objects):
        target = out / Path(path).name
        with target.open('xb') as f:
            f.write(Path(path).read_bytes())
        subprocess.run(['llvm-ar', 'r', str(target), *objects], check=True, timeout=30)
        return pin(target)

    radio = plan['result_metadata']['platform069_radio']
    prior_provider = radio['provider_archive']
    new_provider = patch_archive(prior_provider, compile_member('SonyWifiDma.o', dma),
                                 compile_member('Sm8550AppsSmmu.o', picker))
    plan['added_archives'][plan['added_archives'].index(prior_provider)] = new_provider
    display = plan['result_metadata']['platform069_oled']
    display_row = next(x for x in plan['archive_replacements'] if x['new'] == display['archive'])
    obj_dep = load(next(x for x in plan['compile_receipts'] if Path(x).name == 'Resources069.o.dependencies.json'))
    cwd = next(Path(x).parent for x in obj_dep['dependencies'] if Path(x).name == 'meta_features.h')
    display_row['new'] = patch_archive(display['archive'], compile_member('Resources069.o', display_resources, cwd))

    patch = next(x for x in plan['source_patch_updates'] if x['native_source_patch'] == 'crashes069-persistent-lines')
    original = Path(patch['original_source']).read_text()
    old_bootlog = plan['result_metadata']['platform069_crashes']['member_objects'][0]
    if old_bootlog['member'] != 'BootLog.o':
        raise ValueError('Unexpected BootLog provenance')
    bootlog = compile_member('BootLog.o', lambda _: adapt_boot_log(original), old_bootlog['directory'])
    member = next(x for x in plan['member_replacements'] if Path(x['object']).name == 'BootLog.o')
    member['object'] = bootlog
    patch['source'] = new_objects['BootLog.o']['source']
    patch['source_sha256'] = sha(patch['source'])
    qualifier = ROOT / 'ci/platform069/peripherals071.py'
    q = next(x for x in plan['source_qualifiers'] if x['module'] == 'platform069.recovery070')
    q.update(module='platform069.peripherals071', sha256=sha(qualifier))
    pin(qualifier)
    pin(Path(__file__).resolve())
    pin(PLAN)
    plan['result_metadata']['platform069_followup071'] = dict(
        provider=new_provider, display=display_row['new'], objects=new_objects, hardware_verified=False)
    with (out / 'plan.json').open('x') as f:
        f.write(json.dumps(plan, indent=2) + '\n')
    print(out / 'plan.json')


if __name__ == '__main__':
    main()
