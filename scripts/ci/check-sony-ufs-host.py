#!/usr/bin/env python3
"""Run sanitizer checks of upstream UFS logic and captured Sony GPT selection."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tomllib

DEVICE = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--adapter', type=Path, required=True)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--preview', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    source, out = args.source.resolve(), args.out.resolve()
    if subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip() != \
            'fd420df000f43213d9cd019725abff0849c98c72':
        parser.error('Require documentation-pinned UFS sources')
    adapter = json.loads((args.adapter / 'report.json').read_text())
    staged_source = args.adapter / 'source'
    for name, digest in adapter['staged_sources_sha256'].items():
        if hashlib.sha256((staged_source / name).read_bytes()).hexdigest() != digest:
            raise ValueError('Compiled adapter source changed: ' + name)
    tests = out / 'tests'
    tests.mkdir()
    for header in source.glob('*.h'):
        (out / header.name).symlink_to(header)
    results = []

    def run(name, source_file, parameters=(), includes=(), crypto=False, flags=()):
        command = ['g++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
                   '-fsanitize=address,undefined', '-g', *includes, *flags, str(source_file), '-o', str(out / name)]
        if crypto:
            command += ['-lcrypto']
        (out / (name + '.command.json')).write_text(json.dumps(command, indent=2) + '\n')
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        (out / (name + '.compile.log')).write_text(result.stdout + result.stderr)
        result.check_returncode()
        with (out / (name + '.log')).open('x') as log:
            subprocess.run([str(out / name), *map(str, parameters)], stdout=log,
                           stderr=subprocess.STDOUT, check=True, timeout=30)
        results.append(name)
        print('PASS: ' + name, flush=True)

    for name in ('RootLayout', 'RootWindowRead', 'RootDiagnostics', 'RootPublication', 'SmmuTakeover', 'TransferPoll'):
        text = (source / 'tests' / (name + '.cpp')).read_text()
        if name == 'RootWindowRead':
            # LP64 GCC gives UINT64_MAX a different type from 0ULL. This affects
            # only the upstream host fixture, never production driver operations.
            text = text.replace('{0ULL,UINT64_MAX}', '{uint64_t(0),uint64_t(UINT64_MAX)}')
        target = tests / (name + '.cpp')
        target.write_text(text)
        run(name, target, crypto=name == 'RootLayout')
    # Upstream single-threaded command fixture has no interrupt waiter, so its
    # production spin-budget variable is intentionally unused in this host mode.
    run('RootCommands', source / 'tests/RootCommands.cpp', flags=('-Wno-unused-variable',))
    run('SonySmmuTakeover', DEVICE / 'ci/ufs/SonySmmuTakeover.cpp',
        includes=('-I', str(staged_source)))
    profile = tomllib.loads((DEVICE / 'profiles/ios-27.0.1-24A446-iphone14/profile.toml').read_text())['root']
    manifest = bytearray(4096)
    manifest[:8] = b'SHNGROOT'
    struct.pack_into('<II', manifest, 8, 1, 2)
    cursor = 1 << 20
    # Synthetic metadata only. Actual raw image content is not modified or copied.
    for i, (name, size, prefix) in enumerate((('OS', 9537847296, 'os'), ('SystemOS', 6012534784, 'systemos'))):
        struct.pack_into('<32sQQII32s', manifest, 24 + i * 128, name.encode(), cursor, size, 512, 1,
                         bytes.fromhex(profile[prefix + '_image_sha256']))
        cursor = (cursor + size + (1 << 20) - 1) & -(1 << 20)
    struct.pack_into('<Q', manifest, 16, cursor)
    manifest[4064:] = hashlib.sha256(manifest[:4064]).digest()
    fixture = out / 'd27-window-manifest-fixture.bin'
    fixture.write_bytes(manifest)
    run('SonyRootLayout', DEVICE / 'ci/ufs/SonyRootLayout.cpp',
        (args.capture / 'gpt-primary-region.bin', args.preview / 'gpt-primary.preview.bin', fixture),
        ('-I', str(staged_source)), crypto=True)
    report = dict(host_checks_passed=results, sanitizers=['address', 'undefined'],
                  compiler=subprocess.check_output(['g++', '--version'], text=True).splitlines()[0],
                  actual_sony_gpt_fixture=True, manifest_is_synthetic_metadata=True,
                  firmware_handoff_qualified=False, xnu_ufs_qualified=False, device_operations=False)
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
