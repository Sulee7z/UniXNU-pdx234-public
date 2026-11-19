#!/usr/bin/env python3
"""Recompile all four PDX071 objects and carry them through the final image."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

DEVICE = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/f/UniXNU-Port-artifacts/platform069-20261118')
sys.path.insert(0, str(DEVICE/'ci'))
from compile_dependencies import valid
from link_inputs import collect_link_inputs


def sha(path):
    with Path(path).open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def load(path):
    return json.loads(Path(path).read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    out = parser.parse_args().out.resolve()
    if not out.is_relative_to(BASE) or out == BASE:
        parser.error('Use a new directory under ' + str(BASE))
    out.mkdir()

    def run(script, label, *switches, **options):
        command = [sys.executable, '-B', str(DEVICE/'scripts/ci'/script), *switches]
        for name, value in options.items():
            command.extend(('--' + name.replace('_', '-'), str(value)))
        log = out/(label+'.log')
        with log.open('x') as stream:
            result = subprocess.run(command, cwd=DEVICE, stdout=stream, stderr=subprocess.STDOUT, timeout=950)
        if result.returncode:
            raise SystemExit(log.read_text(errors='replace')[-6000:] + '\nStage failed: ' + label)
        print(label + ': passed', flush=True)

    # The public builder regenerates the four exact source adaptations from 070,
    # compiles them with recorded Clang24 and checks their dependency identities.
    run('plan-sony-platform071.py', 'compile-four', out=out/'plan')
    compiled = {}
    for name in ('SonyWifiDma.o', 'Sm8550AppsSmmu.o', 'Resources069.o', 'BootLog.o'):
        receipt = load(out/'plan'/(name+'.dependencies.json'))
        original = load(BASE/'plan-final071-001'/(name+'.dependencies.json'))
        if (not valid(receipt) or sha(receipt['source']) != sha(original['source']) or
                receipt['dependency_compiler_sha256'] != original['dependency_compiler_sha256'] or
                '-fptrauth-function-pointer-type-discrimination' not in receipt['command']):
            raise ValueError('Recompiled source or compiler ABI differs: ' + name)
        compiled[name] = {key: receipt[key] for key in ('source', 'object', 'object_sha256',
            'dependency_compiler', 'dependency_compiler_sha256')}
        compiled[name]['receipt'] = str(out/'plan'/(name+'.dependencies.json'))
    run('relink-sony-platform069.py', 'native-link', plan=out/'plan/plan.json', out=out/'native')
    closure = collect_link_inputs(load(out/'native/native-link.command.json'))
    (out/'link-inputs.json').write_text(json.dumps({str(p): {'sha256': sha(p), 'roles': roles}
        for p, roles in closure.items()}, indent=2)+'\n')
    run('finish-sony-platform069.py', 'strict', '--expanded-native-data', build=out/'native', out=out/'strict',
        profile=DEVICE/'profiles/ios-27.0.1-24A446-iphone14/graphics-prelink.toml',
        symbol_evidence=BASE/'strict-final069-001/XnuPrelink/fixtures/fileset-d27-graphics-symbols.json')
    run('verify-sony-platform069-handset.py', 'handset-audit', native=out/'native', strict=out/'strict',
        out=out/'handset-audit', touch=BASE/'verify-final069-touch-input-001',
        block_tests='/mnt/e/UniXNU-sheng27-sony-20261113/block-descriptor-test-008/result.json')
    required = load(BASE/'linked-requirements071-001/requirements.json')
    required['inputs'][str(out/'plan/plan.json')] = sha(out/'plan/plan.json')
    requirements = out/'requirements.json'
    requirements.write_text(json.dumps(required, indent=2)+'\n')
    run('check-sony-platform069-linked.py', 'linked-audit', native=out/'native', strict=out/'strict',
        requirements=requirements, out=out/'linked-audit')
    run('package-sony-platform069.py', 'package', version='071', work=out/'package', out=out/'release',
        native=out/'native', strict=out/'strict', verification=out/'handset-audit',
        platform_verification=out/'linked-audit', policy=BASE/'policy-final071-001', runtime=BASE/'runtime070-001',
        adt_receipt=BASE/'radio-adt-address-qualified069-003', skip_setup=BASE/'skip-setup-seed-001',
        seed_tests=BASE.parent/'platform067-20261118/volatile-seed-tests-001',
        skip_seed_tests=BASE/'skip-setup-native-sparse-001/test')
    strict = load(out/'strict/result.json')
    linked = load(out/'linked-audit/result.json')
    release = load(out/'release/release.json')
    record = dict(passed=True, mode='source-incremental', compiled_objects=compiled,
        link_inputs_verified=len(closure), native_sha256=load(out/'native/result.json')['native_sha256'],
        strict_sha256=strict['candidate_sha256'], strict_missing=strict['strict_missing'],
        strict_stubbed=strict['strict_stubbed'], radio_pac_slots=linked['radio_pac_slots'],
        signed_blocks_inputs=linked['actual_signed_blocks_inputs_verified'],
        image=release['image'], image_sha256=release['sha256'],
        image_byte_identical_to_original=release['sha256']=='56d09a18ddf1217c44664a2de754840c780a73f9fd8b2ad5b0e20b2d2637dd64',
        source_paths_embedded_in_debug_metadata=True, handset_verified=False, device_operations=False)
    (out/'incremental-result.json').write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps({key: record[key] for key in ('passed', 'mode', 'link_inputs_verified', 'image_sha256')}))


if __name__ == '__main__':
    main()
