#!/usr/bin/env python3
"""Run local strict prelink with the exact reviewed CI source snapshot.

Reference worktrees and prior inputs stay unchanged. Every attempt uses a new
ext4 directory; allow-missing remains an explicitly separate experiment.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

DEVICE = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', required=True, type=Path)
    parser.add_argument('--reference-tree', required=True, type=Path)
    parser.add_argument('--mainline', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--allow-missing', action='store_true')
    args = parser.parse_args()
    bringup = load('local_bringup', DEVICE / 'scripts/ci/qemu-bringup.py')
    verifier = load('local_reference', DEVICE / 'scripts/ci/verify-fileset-reference.py')
    receipt = verifier.verify(args.reference_tree.resolve())
    if args.output.exists():
        parser.error('Preserve the existing attempt; choose a fresh output directory')
    args.output.mkdir(parents=True)
    filesystem = subprocess.check_output(['findmnt', '-T', str(args.output), '-n', '-o', 'FSTYPE'], text=True).strip()
    if filesystem != 'ext4':
        parser.error('Local prelink output must be on ext4')
    board = bringup.load_board(DEVICE)
    profile, spec = bringup.load_spec(DEVICE, board)
    original = DEVICE / '.cache/iphone14-ios27/ipsw/24A446/kernelcache.decompressed'
    if sha(original) != spec['kernelcache_sha256']:
        raise ValueError('Wrong D27 original kernelcache')
    kit = args.output / 'tool'
    manifest = json.loads((DEVICE / 'ci/source-overlays.json').read_text())
    snapshot_hashes = {}
    for entry in manifest['component_files']:
        relative = Path(entry['path'])
        source = DEVICE / 'ci/XnuPrelink' / relative
        data = source.read_bytes().replace(b'\r\n', b'\n')
        if hashlib.sha256(data).hexdigest() != entry['sha256_lf']:
            raise ValueError('CI source snapshot changed: ' + str(relative))
        target = kit / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        snapshot_hashes[str(relative)] = entry['sha256_lf']
    native = args.output / 'native.macho'
    shutil.copyfile(args.native, native)
    if sha(native) != sha(args.native):
        raise ValueError('Native input transfer changed bytes')
    boot_args = bringup.merged_boot_arguments(board['payload']['kernel_args'],
                  ['interrupt-masked-debug-mode=1', 'sched_preemption_disable_debug_mode=1'])
    sealer = args.mainline.resolve() / 'scripts/seal-source-crypto-kernel.py'
    sealed = bringup.seal(native, sealer, boot_args, profile)
    (args.output / 'native-seal.log').write_text(sealed.stdout + sealed.stderr)
    if sealed.returncode:
        raise ValueError('Native POST seal failed')
    spec = dict(spec, tool=str(kit / 'emit_prelink.py'), kernel=str(native))
    extra = list(spec.get('extra_args', []))
    extra[extra.index('--fileset-reference') + 1] = receipt['reference']
    spec['extra_args'] = extra
    candidate = args.output / 'kernel.macho'
    command = bringup.emit_command(spec, original, candidate, allow_missing=args.allow_missing)
    record = {'native_source': str(args.native.resolve()), 'native_source_sha256': sha(args.native),
              'sealed_native_sha256': sha(native), 'reference': receipt, 'kernelcache_sha256': sha(original),
              'source_snapshot': snapshot_hashes, 'boot_args': boot_args, 'command': command,
              'allow_missing': args.allow_missing, 'filesystem': filesystem, 'device_operations': False}
    (args.output / 'inputs.json').write_text(json.dumps(record, indent=2) + '\n')
    with (args.output / 'prelink.log').open('x') as stream:
        result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode == 0 and candidate.is_file():
        sealed = bringup.seal(candidate, sealer, boot_args, profile)
        (args.output / 'final-seal.log').write_text(sealed.stdout + sealed.stderr)
        if sealed.returncode:
            raise ValueError('Final candidate POST seal failed')
    record.update(exit_code=result.returncode, candidate_exists=candidate.is_file())
    report = candidate.with_suffix('.json')
    if report.is_file():
        record['unresolved'] = bringup.unresolved(json.loads(report.read_text()))
    (args.output / 'execution.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({key: record[key] for key in ('exit_code', 'candidate_exists', 'allow_missing')} |
                     {'unresolved': record.get('unresolved')}, indent=2))
    raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
