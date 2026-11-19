#!/usr/bin/env python3
"""Strictly prelink a rebuilt D27 native kernel and RELEASE-LTO reference.

Recovered names use pinned original bodies and an archived matcher snapshot;
all final addresses come from the current native symbol table. No Actions,
hardware operations, allow-missing or unmapped stubs are used.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tomllib

DEVICE = Path(__file__).resolve().parents[2]


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(command, cwd, log):
    with log.open('x') as stream:
        return subprocess.run(command, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree', required=True, type=Path)
    parser.add_argument('--mainline', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path, help='Fresh ext4 directory for strict attempts/logs')
    parser.add_argument('--native', type=Path, help='Defaults to the selected profile native kernel under tree')
    args = parser.parse_args()
    tree, mainline, output = args.tree.resolve(), args.mainline.resolve(), args.output.resolve()
    if output.exists():
        parser.error('Preserve prior outputs; select a new output directory')
    output.mkdir(parents=True)
    profile = tomllib.loads((DEVICE / 'profiles/ios-27.0.1-24A446-iphone14/profile.toml').read_text())
    spec = profile['kernel']['prelink']
    native = args.native.resolve() if args.native else tree / spec['kernel']
    original = DEVICE / '.cache/iphone14-ios27/ipsw/24A446/kernelcache.decompressed'
    if sha(original) != spec['kernelcache_sha256']:
        raise ValueError('Wrong D27 kernelcache')
    initial, final = output / 'initial', output / 'final'
    first = [sys.executable, str(DEVICE / 'scripts/ci/prelink-local.py'), '--native', str(native),
             '--reference-tree', str(tree), '--mainline', str(mainline), '--output', str(initial)]
    first_exit = run(first, tree, output / 'initial.log')
    first_report = initial / 'kernel.json'
    if not first_report.exists():
        raise SystemExit('Prelink failed before the missing-target report; see initial.log')
    report = json.loads(first_report.read_text())
    final.mkdir()
    map_path = initial / 'kernel.map.json'
    imported = None
    if report['missing']:
        evidence = DEVICE / 'ci/strict5-reference-evidence'
        imported = [sys.executable, str(DEVICE / 'scripts/ci/import-runner-identities.py'),
                    '--runner-map', str(evidence / 'names.json'), '--runner-kit', str(evidence / 'kit'),
                    '--local-map', str(map_path), '--local-failure', str(first_report),
                    '--kernelcache', str(original), '--native', str(initial / 'native.macho'),
                    '--kit', str(initial / 'tool'), '--output', str(final / 'kernel.map.json')]
        if run(imported, tree, output / 'identity-recovery.log'):
            raise SystemExit('Historical identity checks rejected the inputs')
    else:
        (final / 'kernel.map.json').write_bytes(map_path.read_bytes())
    emit = [sys.executable, str(initial / 'tool/fileset_emit.py'), str(original), str(initial / 'native.macho'),
            '--map', str(final / 'kernel.map.json'), '--output', str(final / 'kernel.macho'),
            '--report', str(final / 'kernel.json')]
    for root in spec['roots']:
        emit.extend(['--root', root])
    emit.extend(['--early-security-init', spec['early_security_init']])
    code = run(emit, tree, output / 'final.log')
    if code:
        raise SystemExit('Strict emission still has gaps; inspect final/kernel.json')
    report = json.loads((final / 'kernel.json').read_text())
    if report['missing'] or report.get('stubbed') or not report['candidate_written'] or report.get('allow_missing'):
        raise SystemExit('Strict completeness not achieved')
    module_spec = importlib.util.spec_from_file_location('strict5_bringup', DEVICE / 'scripts/ci/qemu-bringup.py')
    bringup = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(bringup)
    inputs = json.loads((initial / 'inputs.json').read_text())
    seal = bringup.seal(final / 'kernel.macho', mainline / 'scripts/seal-source-crypto-kernel.py',
                       inputs['boot_args'], profile)
    (output / 'final-seal.log').write_text(seal.stdout + seal.stderr)
    if seal.returncode:
        raise SystemExit('Final source crypto seal failed')
    report['pre_seal_candidate_sha256'] = report['candidate_sha256']
    report['candidate_sha256'] = sha(final / 'kernel.macho')
    report['source_crypto_final_seal'] = {'sha256': report['candidate_sha256'],
                                        'boot_args': inputs['boot_args'], 'exit_code': seal.returncode}
    (final / 'kernel.json').write_text(json.dumps(report, indent=2) + '\n')
    mapping = json.loads((final / 'kernel.map.json').read_text())
    result = {'initial_command': first, 'initial_exit': first_exit,
              'identity_recovery_command': imported, 'strict_command': emit, 'strict_exit': code,
              'candidate': str(final / 'kernel.macho'), 'candidate_sha256': report['candidate_sha256'],
              'candidate_written': True, 'missing': report['missing'], 'stubbed': report.get('stubbed'),
              'allow_missing': False, 'reference_sha256': report['reference_sha256'],
              'native_sha256': report['inputs']['native_sha256'],
              'recovered_reference_names': len(mapping.get('portable_naming_provenance', {}).get('accepted', [])),
              'runtime_qualified': False, 'device_operations': False, 'github_actions_invoked': False}
    (output / 'strict-result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
