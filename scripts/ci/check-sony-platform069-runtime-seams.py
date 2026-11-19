#!/usr/bin/env python3
"""Run the frozen 069 ITS and brightness control flow against host stand-ins."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('plan', 'provider', 'out'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    plan_path, provider, out = (p.resolve() for p in (args.plan, args.provider, args.out))
    plan = json.loads(plan_path.read_text())
    provider_result = provider / 'result.json'
    receipt = json.loads(provider_result.read_text())
    its = provider / 'source/SonyIts.cpp'
    encoding = its.with_suffix('.c')
    header = its.with_suffix('.h')
    overlay = next(row for row in plan['source_patch_updates']
                   if row['native_source_patch'] == 'audit-d27-addon-reference')
    exec_source = Path(overlay['source'])
    archive = Path(receipt['provider_archive'])
    inputs = {}
    for path in (its, encoding, header, exec_source, archive, provider_result):
        digest = sha(path)
        if plan['inputs'].get(str(path)) != digest:
            raise ValueError(f'Input differs from the frozen link plan: {path}')
        inputs[str(path)] = digest
    if str(archive) not in plan['added_archives'] or receipt['provider_sha256'] != inputs[str(archive)]:
        raise ValueError('Wrong linked provider')
    inputs[str(plan_path)] = sha(plan_path)
    out.mkdir(parents=True, exist_ok=False)
    cpp = its.read_text()
    c = exec_source.read_text()
    (out / 'its_init_actual.inc').write_text('namespace {\n' + cpp[cpp.index('void release_preflight_allocations(){'):])
    start = c.index('static int\nnative_display069_file(')
    end = c.index('static void\nnative_gpu_addon_prepare(', start)
    (out / 'display_mount_actual.inc').write_text(c[start:end])

    its_test = ROOT / 'tests/sony_its_init069.cpp'
    display_test = ROOT / 'tests/sony_display_mount069.c'
    for path in (its_test, display_test, Path(__file__).resolve()):
        inputs[str(path)] = sha(path)
    flags = ['-g', '-O1', '-Wall', '-Wextra', '-Werror', '-fno-omit-frame-pointer',
             '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-I', str(out)]
    runs = []

    def run(label, *command):
        result = subprocess.run(list(map(str, command)), capture_output=True, timeout=60)
        log = out / (label + '.log')
        log.write_bytes(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(f'{label}: exit {result.returncode}; see {log}')
        runs.append({'label': label, 'command': list(map(str, command)), 'log_sha256': sha(log)})

    run('compile-its-encoding', 'clang', '-std=c11', *flags, '-c', encoding, '-o', out / 'encoding.o')
    run('compile-its', 'clang++', '-std=c++17', *flags, '-I', its.parent, its_test, out / 'encoding.o', '-o', out / 'its')
    run('compile-display', 'clang', '-std=c11', *flags, display_test, '-o', out / 'display')
    its_cases = ('4k', '16k', '64k', 'foreign-baser', 'foreign-peer', 'foreign-properties',
                 'probe-restore', 'no-page', 'alloc', 'commit-readback', 'stalled')
    display_cases = ('success', 'disabled', 'control-off', 'no-addon', 'incomplete-addon',
                     'missing-daemon', 'missing-marker', 'library-eagain', 'library-hidden',
                     'exec-eagain', 'exec-hidden', 'wifi-hidden', 'backboard-hidden', 'rollback-denied')
    for suite, cases in (('its', its_cases), ('display', display_cases)):
        for case in cases:
            run(f'{suite}-{case}', out / suite, case)
    if any(sha(Path(path)) != digest for path, digest in inputs.items()):
        raise ValueError('Test inputs changed during the run')
    record = dict(passed=True, inputs=inputs, runs=runs, its_cases=len(its_cases),
                  display_cases=len(display_cases), hardware_verified=False, device_operations=False,
                  scope='Frozen production control flow; registers, allocation, VFS and syscalls modeled')
    (out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    print(f'PASS: {len(its_cases)} ITS and {len(display_cases)} brightness mount host cases')


if __name__ == '__main__':
    main()
