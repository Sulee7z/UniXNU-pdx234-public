#!/usr/bin/env python3
"""Compile an isolated provider069-011 ITS archive with only the BASER owner fix."""
from __future__ import annotations

import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
FRESH = Path('/mnt/f/UniXNU-Port-artifacts/platform069-20261118')
BASE = FRESH / 'radio-provider069-011'
OUT = FRESH / 'its-baser-owner-mask-fix-009'
G_MIN_FREE = 8 * 1024**3
OWNER_MASK = '0x8000fffffffff000'


def sha(path: Path) -> str:
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run_logged(label: str, argv: list[str], cwd: Path, log: Path, env=None) -> subprocess.CompletedProcess:
    log.parent.mkdir(parents=True, exist_ok=True)
    done = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=180)
    log.write_text(done.stdout + done.stderr, encoding='utf-8')
    if done.returncode:
        raise RuntimeError(f'{label} failed ({done.returncode}); see {log}')
    return done


def archive_members(archive: Path) -> dict[str, str]:
    names = subprocess.check_output(['llvm-ar', 't', str(archive)], text=True).splitlines()
    if not names or len(names) != len(set(names)):
        raise ValueError(f'Invalid provider archive member list: {archive}')
    return {name: hashlib.sha256(subprocess.check_output(['llvm-ar', 'p', str(archive), name])).hexdigest()
            for name in names}


def apply_scoped_patch(source_dir: Path) -> dict:
    """Patch known provider011 anchors, independently of broader live ITS edits."""
    header = source_dir / 'SonyIts.h'
    c_source = source_dir / 'SonyIts.c'
    cpp_source = source_dir / 'SonyIts.cpp'
    before = {path.name: path.read_text(encoding='utf-8') for path in (header, c_source, cpp_source)}

    header_anchor = '#define SONY_ITS_LPI_BASE 8192u\n'
    if before['SonyIts.h'].count(header_anchor) != 1 or 'SONY_ITS_BASER_OWNER_MASK' in before['SonyIts.h']:
        raise ValueError('Frozen provider011 header does not match the qualified patch anchor')
    helper_decl = (
        '#define SONY_ITS_BASER_OWNER_MASK ((1ULL<<63)|0x0000fffffffff000ULL)\n'
        'int sony_its_baser_has_owner(uint64_t value);\n')
    after_header = before['SonyIts.h'].replace(header_anchor, header_anchor + helper_decl, 1)

    c_anchor = ('int sony_its_register_matches(uint64_t actual,uint64_t expected,uint64_t mask){\n'
                '    return (actual&mask)==(expected&mask);\n'
                '}\n')
    if before['SonyIts.c'].count(c_anchor) != 1 or 'sony_its_baser_has_owner' in before['SonyIts.c']:
        raise ValueError('Frozen provider011 C helper does not match the qualified patch anchor')
    helper_impl = ('\nint sony_its_baser_has_owner(uint64_t value){\n'
                   '    return (value&SONY_ITS_BASER_OWNER_MASK)!=0;\n'
                   '}\n')
    after_c = before['SonyIts.c'].replace(c_anchor, c_anchor + helper_impl, 1)

    old_check = ('if((baser_before[i]&(1ULL<<63)) || '
                 '(baser_before[i]&0x0000ffffffff0000ULL))return preflight_failure(EBUSY);')
    new_check = 'if(sony_its_baser_has_owner(baser_before[i]))return preflight_failure(EBUSY);'
    if before['SonyIts.cpp'].count(old_check) != 1 or 'sony_its_baser_has_owner(baser_before[i])' in before['SonyIts.cpp']:
        raise ValueError('Frozen provider011 preflight does not match the qualified old inline mask')
    after_cpp = before['SonyIts.cpp'].replace(old_check, new_check, 1)
    if (before['SonyIts.cpp'].count('SONY_ITS_BASER_READBACK_MASK') !=
            after_cpp.count('SONY_ITS_BASER_READBACK_MASK')):
        raise ValueError('BASER readback path changed in the scoped patch')

    for path, text in ((header, after_header), (c_source, after_c), (cpp_source, after_cpp)):
        path.write_text(text, encoding='utf-8')
    parts = []
    for name, text in (('SonyIts.h', after_header), ('SonyIts.c', after_c), ('SonyIts.cpp', after_cpp)):
        parts.extend(difflib.unified_diff(before[name].splitlines(keepends=True), text.splitlines(keepends=True),
                                          fromfile='radio-provider069-011/' + name,
                                          tofile='its-baser-owner-mask-fix-001/' + name))
    patch_path = source_dir.parent / 'source.patch'
    patch_path.write_text(''.join(parts), encoding='utf-8')
    patch_text = patch_path.read_text(encoding='utf-8')
    hunk_headers = [line for line in patch_text.splitlines() if line.startswith('@@ ')]
    if len(hunk_headers) != 3:
        raise ValueError('Expected a three-file, three-hunk preflight/helper-only patch')
    if before['SonyIts.cpp'].count('SONY_ITS_BASER_READBACK_MASK') != after_cpp.count('SONY_ITS_BASER_READBACK_MASK'):
        raise ValueError('Source patch changes BASER readback verification')
    return {
        name: {'baseline_sha256': hashlib.sha256(before[name].encode()).hexdigest(),
               'patched_sha256': sha(source_dir / name)}
        for name in ('SonyIts.h', 'SonyIts.c', 'SonyIts.cpp')
    } | {'patch': str(patch_path), 'patch_sha256': sha(patch_path), 'three_hunks_only': True}


def compile_selected(name: str, object_name: str, source_dir: Path,
                     object_dir: Path, logs: Path) -> dict:
    prior_path = BASE / 'objects' / (object_name + '.dependencies.json')
    prior = json.loads(prior_path.read_text(encoding='utf-8'))
    old_source = str(BASE / 'source' / name)
    source = source_dir / name
    obj = object_dir / object_name
    command = list(prior['command'])
    if command.count(old_source) != 1 or command.count(prior['object']) != 1:
        raise ValueError(f'Unexpected provider011 source/object tokens for {object_name}')
    command[command.index(old_source)] = str(source)
    command[command.index(prior['object'])] = str(obj)
    for flag in ('-MD', '-MF'):
        if flag not in command:
            raise ValueError(f'Recorded dependency flag missing: {flag}')
    if '-MT' not in command:
        command.extend(['-MT', 'pdx_object'])
    command[command.index('-MF') + 1] = str(obj.with_name(object_name + '.d'))
    old_include = '-I' + str(BASE / 'source')
    if old_include not in command:
        raise ValueError(f'Recorded source include directory missing for {object_name}')
    command[command.index(old_include)] = '-I' + str(source_dir)
    if '--target=arm64e-apple-ios27.0' not in command:
        raise ValueError('Selected compile target is not arm64e iOS27')
    if '-fptrauth-function-pointer-type-discrimination' not in command:
        raise ValueError('PAC function-pointer type discrimination must remain enabled')
    blocks = any(command[i:i + 2] == ['-Xclang', '-fptrauth-block-descriptor-pointers']
                 for i in range(len(command) - 1))
    if name.endswith('.cpp') and not blocks:
        raise ValueError('Selected C++ source requires the signed Blocks frontend flag')
    if any(value.startswith('-fno-ptrauth') for value in command):
        raise ValueError('PAC-disable option is forbidden')
    compiler = Path(prior['dependency_compiler'])
    if sha(compiler) != prior['dependency_compiler_sha256']:
        raise ValueError('Recorded compiler identity changed')
    run_logged('compile-' + object_name, command, Path(prior['cwd']),
               logs / (object_name + '.compile.log'))
    sys.path.insert(0, str(ROOT / 'ci'))
    from compile_dependencies import capture
    receipt = capture(obj.with_name(object_name + '.d'), Path(prior['cwd']), compiler)
    receipt.update(source=str(source), object=str(obj), object_sha256=sha(obj), command=command)
    receipt_path = obj.with_name(object_name + '.dependencies.json')
    receipt_path.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    return {'prior_receipt': str(prior_path), 'prior_receipt_sha256': sha(prior_path),
            'source': str(source), 'source_sha256': sha(source),
            'object': str(obj), 'object_sha256': sha(obj),
            'dependency_receipt': str(receipt_path), 'dependency_receipt_sha256': sha(receipt_path),
            'target': 'arm64e-apple-ios27.0',
            'ptrauth_function_pointer_type_discrimination': True,
            'ptrauth_signed_blocks': blocks, 'command': command}


def main() -> int:
    if sys.platform != 'linux':
        raise SystemExit('Run inside UniXNU-Build WSL')
    if OUT.exists():
        raise FileExistsError(f'Refusing to overwrite prior output: {OUT}')
    g_free = shutil.disk_usage('/mnt/g').free
    if g_free < G_MIN_FREE:
        raise OSError(f'G: free space {g_free} is below the 8 GiB guard')
    baseline_path = BASE / 'result.json'
    baseline = json.loads(baseline_path.read_text(encoding='utf-8'))
    if (baseline.get('passed') is not True or baseline.get('hardware_verified') is not False or
            baseline.get('device_operations') is not False):
        raise ValueError('Expected preserved host-only radio-provider069-011')
    archive = Path(baseline['provider_archive'])
    if sha(archive) != baseline['provider_sha256']:
        raise ValueError('Preserved provider069-011 archive hash mismatch')
    cpp_receipt_path = BASE / 'objects/SonyIts.o.dependencies.json'
    cpp_receipt = json.loads(cpp_receipt_path.read_text(encoding='utf-8'))
    if cpp_receipt != baseline['commands']['SonyIts.cpp'] or sha(Path(cpp_receipt['object'])) != cpp_receipt['object_sha256']:
        raise ValueError('provider011 SonyIts.o is not the selected recipe object')

    OUT.mkdir(parents=True, exist_ok=False)
    staged_source = OUT / 'source'
    shutil.copytree(BASE / 'source', staged_source)
    inputs = {}
    qualification = {}
    builds = {}
    try:
        qualification = apply_scoped_patch(staged_source)
        for name in ('SonyIts.h', 'SonyIts.c', 'SonyIts.cpp'):
            inputs[str(ROOT / 'drivers/SonyWcn/platform069' / name)] = sha(ROOT / 'drivers/SonyWcn/platform069' / name)
            inputs[str(BASE / 'source' / name)] = sha(BASE / 'source' / name)
            inputs[str(staged_source / name)] = sha(staged_source / name)
        test_source = ROOT / 'tests/sony_its_baser_owner069.c'
        inputs[str(test_source)] = sha(test_source)
        spec = FRESH / 'its-audit-001/arm-ihi0069g.txt'
        inputs[str(spec)] = sha(spec)
        inputs[str(baseline_path)] = sha(baseline_path)
        inputs[str(archive)] = sha(archive)
        inputs[str(cpp_receipt_path)] = sha(cpp_receipt_path)

        objects = OUT / 'objects'
        objects.mkdir()
        logs = OUT / 'logs'
        builds['SonyIts.cpp'] = compile_selected('SonyIts.cpp', 'SonyIts.o', staged_source, objects, logs)
        builds['SonyIts.c'] = compile_selected('SonyIts.c', 'SonyIts_encoding.o', staged_source, objects, logs)

        old_members = archive_members(archive)
        required_members = {'SonyIts.o', 'SonyIts_encoding.o'}
        if not required_members <= old_members.keys():
            raise ValueError('Provider011 archive lacks selected ITS members')
        new_archive = OUT / archive.name
        shutil.copyfile(archive, new_archive)
        run_logged('archive-update', ['llvm-ar', 'r', str(new_archive), str(objects / 'SonyIts.o'),
                                      str(objects / 'SonyIts_encoding.o')], OUT,
                   logs / 'archive-update.log')
        run_logged('archive-index', ['llvm-ranlib', str(new_archive)], OUT, logs / 'archive-index.log')
        new_members = archive_members(new_archive)
        if new_members.keys() != old_members.keys():
            raise ValueError('Provider archive member names/order changed')
        changed = sorted(name for name in old_members if old_members[name] != new_members[name])
        if changed != ['SonyIts.o', 'SonyIts_encoding.o']:
            raise ValueError(f'Only Sony ITS C/C++ members are expected to change: {changed}')

        test_binary = OUT / 'host/sony_its_baser_owner069'
        test_binary.parent.mkdir(parents=True)
        host_command = ['/usr/bin/clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-I', str(staged_source),
                        str(test_source), str(staged_source / 'SonyIts.c'), '-o', str(test_binary)]
        run_logged('host-compile', host_command, OUT, logs / 'host-compile.log')
        env = dict(os.environ)
        env['ASAN_OPTIONS'] = 'abort_on_error=1:detect_leaks=1:strict_string_checks=1'
        env['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
        test = subprocess.run([str(test_binary)], cwd=OUT, env=env, capture_output=True, text=True, timeout=45)
        (logs / 'host-test.log').write_text(test.stdout + test.stderr, encoding='utf-8')
        if test.returncode:
            raise RuntimeError(f'Focused BASER owner regression failed with exit {test.returncode}')

        result = {
            'schema': 'unixnu.sony-its-baser-owner-mask-fix.v1', 'passed': True,
            'created_utc': datetime.now(timezone.utc).isoformat(),
            'scope': 'Only the GITS_BASER preflight owner mask is repaired; no other ITS findings are included.',
            'device_operations': False, 'guest_operations': False, 'hardware_verified': False,
            'baseline_provider_result': str(baseline_path), 'baseline_provider_result_sha256': sha(baseline_path),
            'baseline_archive': str(archive), 'baseline_archive_sha256': sha(archive),
            'replacement_archive': str(new_archive), 'replacement_archive_sha256': sha(new_archive),
            'source_qualification': qualification, 'compiled_objects': builds,
            'archive_members_before': old_members, 'archive_members_after': new_members,
            'changed_archive_members': changed, 'owner_mask': OWNER_MASK,
            'host_regression': {'source': str(test_source), 'source_sha256': sha(test_source),
                                'command': host_command, 'log': str(logs / 'host-test.log'),
                                'stdout': test.stdout.strip(), 'asan_ubsan': True,
                                'zero_and_typed_presets_tested': True,
                                'all_individual_bits_over_each_preset_tested': True,
                                'old_mask_false_negative_bits_12_to_15_tested': True},
            'status': 'PASS focused regression and selected arm64e objects; parent relink pending',
        }
        result_path = OUT / 'result.json'
        result_path.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        handoff_path = OUT / 'HANDOFF.md'
        handoff_path.write_text(f'''# Sony ITS BASER owner-mask fix 001

**Status:** focused ASan/UBSan regression and provider069-011 arm64e/iOS 27 ITS C/C++ object builds passed. No device, guest, or QEMU operations.

## Change

One shared helper tests GITS_BASER.Valid and the full register address field `[47:12]` with mask `{OWNER_MASK}`. The selected preflight calls the helper. The BASER readback mask, register writes, and other ITS behavior are unchanged. The host regression covers zero, typed Device/Collection presets, and every bit individually; it also verifies the former mask misses bits 12–15.

## Parent integration inputs

- Replace provider archive: `{new_archive}` (SHA-256 `{sha(new_archive)}`)
- Changed archive members: `{', '.join(changed)}`
- `SonyIts.o`: `{builds['SonyIts.cpp']['object']}` (SHA-256 `{builds['SonyIts.cpp']['object_sha256']}`)
- `SonyIts.o` dependency receipt: `{builds['SonyIts.cpp']['dependency_receipt']}` (SHA-256 `{builds['SonyIts.cpp']['dependency_receipt_sha256']}`)
- `SonyIts_encoding.o`: `{builds['SonyIts.c']['object']}` (SHA-256 `{builds['SonyIts.c']['object_sha256']}`)
- `SonyIts_encoding.o` dependency receipt: `{builds['SonyIts.c']['dependency_receipt']}` (SHA-256 `{builds['SonyIts.c']['dependency_receipt_sha256']}`)

The parent must replace `radio-provider069-011/libSonyRadioPlatform069.a`, bind the result and both compile receipts, then relink and rerun strict/native/final-package verification. No parent relink or package was run here.

## Verification

- `{test.stdout.strip()}`
- Original provider069-011 archive preserved byte-for-byte: `{result['baseline_archive_sha256']}`
- Logs: `{logs}`
''', encoding='utf-8')
        result['handoff_sha256'] = sha(handoff_path)
        result_path.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    except BaseException as error:
        failure = {'schema': 'unixnu.sony-its-baser-owner-mask-fix.v1', 'passed': False,
                   'created_utc': datetime.now(timezone.utc).isoformat(), 'device_operations': False,
                   'guest_operations': False, 'hardware_verified': False,
                   'error': f'{type(error).__name__}: {error}', 'source_qualification': qualification,
                   'compiled_objects': builds}
        (OUT / 'result.json').write_text(json.dumps(failure, indent=2) + '\n', encoding='utf-8')
        (OUT / 'HANDOFF.md').write_text(f"# Sony ITS BASER owner-mask fix 001\n\n**FAILED:** `{failure['error']}`. Staged files and logs retained.\n", encoding='utf-8')
        raise
    print(json.dumps({'passed': True, 'result': str(OUT / 'result.json'),
                      'replacement_archive': str(new_archive),
                      'replacement_archive_sha256': sha(new_archive),
                      'changed_members': changed}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
