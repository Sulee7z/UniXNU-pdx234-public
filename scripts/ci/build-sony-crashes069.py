#!/usr/bin/env python3
"""Compile two isolated068-derived storage members for069 crash evidence/policy."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import subprocess
import difflib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ci/platform069/crashes'))
from audit import NATIVE, NATIVE_SHA, FRESH, sha
from source import preserve_crash_messages, launch_policy
sys.path.insert(0, str(ROOT / 'ci'))
from compile_dependencies import run_recorded, valid
from block_descriptor_abi import FLAGS, enabled

BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def load(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n')


def clean(cmd):
    output, i = [], 0
    while i < len(cmd):
        if cmd[i] in ('-MF', '-MT', '-MQ', '-MJ'):
            i += 2
        elif cmd[i] in ('-MD', '-MMD', '-MP'):
            i += 1
        else:
            output.append(cmd[i]); i += 1
    return output


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, default=FRESH / 'crashes-build-001')
    a = p.parse_args()
    out = a.out.resolve()
    if not out.is_relative_to(FRESH) and not out.is_relative_to(ROOT / 'ci/platform069/crashes'):
        raise ValueError('Require new069 artifact/assigned output directory')
    if out.exists():
        raise ValueError('Preserve existing attempt')
    n = load(NATIVE / 'result.json')
    if sha(NATIVE / 'native.macho') != NATIVE_SHA:
        raise ValueError('Actual068 native baseline changed')
    link = load(NATIVE / 'native-link.command.json')
    storage = [Path(x.split('-Wl,-force_load,')[1]) for x in link
               if x.startswith('-Wl,-force_load,') and Path(x.split('-Wl,-force_load,')[1]).name == 'libShengUfs.a']
    if len(storage) != 1:
        raise ValueError('Expected exact one selected Sony storage archive')
    provider_obj = Path(n['platform067_logging']['new_provider_object'])
    provider_receipt = Path(str(provider_obj) + '.dependencies.json')
    old_policy_obj = BASE / 'native-screen007-055-001/objects/storage/BootWatchdogPolicy.o'
    policy_receipt = Path(str(old_policy_obj) + '.json')
    rows = [('BootLog.o', provider_obj, provider_receipt, preserve_crash_messages),
            ('BootWatchdogPolicy.o', old_policy_obj, policy_receipt,
             lambda text: launch_policy(text, (FRESH / 'sheng/package/BootWatchdogPolicy.c').read_text()))]
    out.mkdir(parents=True)
    (out / 'objects').mkdir()
    inputs = {str(NATIVE / 'result.json'): sha(NATIVE / 'result.json'),
              str(NATIVE / 'native-link.command.json'): sha(NATIVE / 'native-link.command.json'),
              str(storage[0]): sha(storage[0]), str(ROOT / 'ci/platform069/crashes/source.py'): sha(ROOT / 'ci/platform069/crashes/source.py'),
              str(FRESH / 'sheng/package/BootWatchdogPolicy.c'): sha(FRESH / 'sheng/package/BootWatchdogPolicy.c')}
    builds = []
    for member, old_obj, receipt_path, adapter in rows:
        rec = load(receipt_path)
        if sha(old_obj) != rec.get('object_sha256', rec.get('sha256')) or not valid(rec):
            raise ValueError('Selected compiler/object/dependencies changed: ' + str(old_obj))
        source = Path(rec['source'])
        expected = rec.get('source_sha256', rec.get('dependencies', {}).get(str(source)))
        if sha(source) != expected:
            raise ValueError('Selected source differs')
        staged = out / source.name
        text = adapter(source.read_text())
        staged.write_text(text)
        diff = out / (source.name + '.patch')
        diff.write_text('\n'.join(difflib.unified_diff(source.read_text().splitlines(), text.splitlines(),
                                                       fromfile='a/package/' + source.name, tofile='b/package/' + source.name)) + '\n')
        command = clean(rec['command'])
        command[command.index(str(source))] = str(staged)
        obj = out / 'objects' / member
        command[command.index('-o') + 1] = str(obj)
        command += ['-iquote', str(source.parent)]
        if not enabled(command):
            command += FLAGS
        if '-fptrauth-function-pointer-type-discrimination' not in command:
            command += ['-fptrauth-function-pointer-type-discrimination']
        if any(x.startswith('-fno-ptrauth') for x in command):
            raise ValueError('PAC disabling flags forbidden')
        directory = rec.get('directory')
        if not directory:
            candidates = {str(Path(s).parent) for s in rec['dependencies'] if Path(s).name == 'meta_features.h'}
            if len(candidates) != 1:
                raise ValueError('Cannot recover exact compile directory')
            directory = candidates.pop()
        with Path(str(obj) + '.log').open('x') as log:
            done = run_recorded(command, cwd=directory, stdout=log, stderr=subprocess.STDOUT, timeout=180)
        if done.returncode:
            raise RuntimeError(Path(str(obj) + '.log').read_text()[-10000:])
        new_receipt = Path(str(obj) + '.dependencies.json')
        if not valid(load(new_receipt)):
            raise ValueError('New compiler receipt invalid')
        for path in (source, staged, obj, new_receipt, receipt_path, diff):
            inputs[str(path)] = sha(path)
        builds.append({'member': member, 'archive': str(storage[0]), 'old_object': str(old_obj), 'old_object_sha256': sha(old_obj),
                       'source': str(staged), 'source_sha256': sha(staged), 'input_source': str(source),
                       'input_source_sha256': sha(source), 'object': str(obj), 'object_sha256': sha(obj),
                       'dependency_receipt': str(new_receipt), 'dependency_sha256': sha(new_receipt),
                       'directory': directory, 'command': load(new_receipt)['command']})
        print('Compiled', member, flush=True)
    result = {'schema': 1, 'baseline_native_sha256': NATIVE_SHA, 'baseline': str(NATIVE), 'inputs': inputs,
              'builds': builds, 'compile_receipts': [r['dependency_receipt'] for r in builds],
              'member_replacements': [{'archive': r['archive'], 'object': r['object']} for r in builds],
              'block_descriptor_replacements_unchanged': True, 'original_block_abi_objects': 66,
              'official_policy_source': str(FRESH / 'sheng/package/BootWatchdogPolicy.c'),
              'preserved': ['Sony builtin boot arguments including watchdog policy', 'PAC/AMFI/signature/trust/verified-root checks',
                            'jetsam budgets', 'existing log layout and bounded UFS callbacks', '2GiB seed and data-persist0'],
              'changed': ['existing bl_latency_message selection runs for storage-probe1 without GPU diagnostics',
                          'current official enable-jobs and POLICY_CALL staging; no new selected disabled labels'],
              'new_disabled_jobs': [], 'device_operations': False, 'linked': False, 'qualified': False}
    save(out / 'result.json', result)
    print(json.dumps({'out': str(out), 'members': [r['member'] for r in builds], 'linked': False}))


if __name__ == '__main__':
    main()
