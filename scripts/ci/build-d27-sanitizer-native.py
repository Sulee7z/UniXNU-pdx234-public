#!/usr/bin/env python3
"""Replay a reviewed sanitizer overlay on the exact 47-bit/JOP native parent.

The source bundle must contain the final task, exec and spawn changes. This
builder preserves existing parent object substitutions and never edits the
prepared source tree. It does not run prelink or boot an incomplete adapter.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

DEVICE = Path(__file__).resolve().parents[2]


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load_record(path):
    return json.JSONDecoder().raw_decode(path.read_text())[0]


def output_path(record):
    value = Path(record['arguments'][record['arguments'].index('-o') + 1])
    return value if value.is_absolute() else (Path(record['directory']) / value).resolve()


def run(command, cwd, env, log):
    with log.open('x') as stream:
        result = subprocess.run(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(log.read_text(errors='replace')[-6000:])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree', required=True, type=Path)
    parser.add_argument('--parent', required=True, type=Path)
    parser.add_argument('--bundle', required=True, type=Path,
                        help='Reviewed source bundle with integration.json and modified/')
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--plan-only', action='store_true')
    args = parser.parse_args()
    tree, parent, bundle, out = (value.resolve() for value in
                                (args.tree, args.parent, args.bundle, args.out))
    review = json.loads((bundle / 'integration.json').read_text())
    if not review.get('exec_recomputation_complete') or not review.get('spawn_translation_complete'):
        parser.error('Source bundle must include reviewed exec and spawn lifecycle')
    parent_report = json.loads((parent / 'report.json').read_text())
    if sha(parent / 'native.macho') != parent_report['native_sha256']:
        parser.error('Parent kernel no longer matches its receipt')
    if parent_report.get('intended_user_va_bits') != 47 or parent_report.get('carrier_enabled'):
        parser.error('Expected verified 47-bit no-carrier parent')
    out.mkdir(parents=True, exist_ok=False)
    work = tree / '.cache/xnu-work'
    objdir = tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
    link = json.loads((parent / 'native-link.command.json').read_text())
    filelist = Path(link[link.index('-filelist') + 1]).read_text().splitlines()
    overlay = json.loads((parent / 'overlay.json').read_text())
    roots = {entry['name']: entry for entry in overlay['roots']}
    sources = []
    for relative, expected in review['source_hashes'].items():
        original, modified = work / relative, bundle / 'modified' / relative
        baseline_ok = (sha(original) == expected['baseline']) if original.exists() else expected['baseline'] is None
        if not baseline_ok or sha(modified) != expected['modified']:
            raise ValueError('Reviewed source bytes changed: ' + relative)
        roots[str(original)] = {'type': 'file', 'name': str(original), 'external-contents': str(modified)}
        if original.suffix in ('.c', '.cpp'):
            sources.append(str(original))
        if original.suffix == '.h':
            exported = tree / 'build/xnu/ios-obj/EXPORT_HDRS' / relative
            if exported.exists():
                if sha(exported) != sha(original):
                    raise ValueError('Exported header does not match baseline: ' + relative)
                roots[str(exported)] = {'type': 'file', 'name': str(exported),
                                        'external-contents': str(modified)}
    overlay['roots'] = list(roots.values())
    overlay_path = out / 'overlay.json'
    overlay_path.write_text(json.dumps(overlay, indent=2) + '\n')
    recipes = {}
    source_directories = {}
    for path in objdir.rglob('*.json'):
        if not path.name.endswith(('.o.json', '.cpo.json')):
            continue
        record = load_record(path)
        recipes[str(output_path(record))] = record
        source_directories.setdefault(record['file'], set()).add(record['directory'])
    # Parent substitutions have their own recorded compiler arguments. Retain
    # those flags, especially startup/root policy defines, rather than replaying
    # an older recipe for an object that merely shares the source filename.
    for directory in [parent, DEVICE / 'out/d27-owner-startup-native-004',
                      DEVICE / 'out/d27-native-jop-key-001']:
        paths = list(directory.glob('compile-*.json')) + list(directory.glob('*.command.json'))
        for path in paths:
            command = json.loads(path.read_text())
            if not isinstance(command, list) or '-o' not in command or '-c' not in command:
                continue
            old = command[command.index('-o') + 1]
            if old not in filelist:
                continue
            source = next((value for value in command if value.endswith(('.c', '.cpp', '.s'))), None)
            if not source:
                continue
            if source not in sources:
                continue
            directories = source_directories.get(source, set())
            if len(directories) != 1:
                raise ValueError('Need unique recorded compile directory for ' + source)
            recipes[old] = {'arguments': command, 'file': source,
                            'directory': next(iter(directories))}
    units = [(index, old, recipes[old]) for index, old in enumerate(filelist)
             if old in recipes and recipes[old]['file'] in sources]
    matched = {record['file'] for _, _, record in units}
    if matched != set(sources):
        raise ValueError('Modified source missing from parent link: ' + str(set(sources) - matched))
    layout = review['layout_verification']
    if not layout.get('all_existing_offsets_unchanged') or layout.get('size') != 2112:
        raise ValueError('Incremental replay requires proven unchanged task ABI')
    plan = {'parent_sha256': sha(parent / 'native.macho'), 'review': review,
            'units': [{'old': old, 'source': record['file']} for _, old, record in units],
            'parent_object_substitutions_retained': True, 'device_operations': False,
            'runtime_qualified': False}
    (out / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    if args.plan_only:
        print(json.dumps(plan, indent=2))
        return
    spec = importlib.util.spec_from_file_location('replay', DEVICE / 'scripts/ci/build-d27-native-jop-key.py')
    replay = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(replay)
    env = dict(os.environ, TMPDIR=str(out), PYTHONDONTWRITEBYTECODE='1')
    for number, (index, old, record) in enumerate(units):
        target = out / ('unit-' + str(number) + Path(old).suffix)
        command = replay.replay(record, Path(record['file']), target)
        # The merged overlay includes the original 47-bit VA overlay as well.
        while '-ivfsoverlay' in command:
            pos = command.index('-ivfsoverlay')
            del command[pos:pos + 2]
        command += ['-ivfsoverlay', str(overlay_path)]
        (out / f'compile-{number}.json').write_text(json.dumps(command, indent=2) + '\n')
        run(command, record['directory'], env, out / f'compile-{number}.log')
        filelist[index] = str(target)
    linked = out / 'link.filelist'
    linked.write_text('\n'.join(filelist) + '\n')
    link[link.index('-filelist') + 1] = str(linked)
    link[link.index('-o') + 1] = str(out / 'native.macho')
    env.update(CROSS_CLANG='/root/unixnu-build/pdx234-pac-toolchain/llvm/bin/clang-24',
               DARWIN_TRIPLE='arm64e-apple-ios27.0')
    env['PATH'] = '/root/unixnu-build/pdx234-pac-toolchain/CommandLineTools/usr/bin:' + env['PATH']
    (out / 'native-link.command.json').write_text(json.dumps(link, indent=2) + '\n')
    run(link, objdir, env, out / 'native-link.log')
    plan['native_sha256'] = sha(out / 'native.macho')
    (out / 'report.json').write_text(json.dumps(plan, indent=2) + '\n')
    print(json.dumps({'native_sha256': plan['native_sha256'], 'units': len(units)}))


if __name__ == '__main__':
    main()
