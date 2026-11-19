#!/usr/bin/env python3
"""Stage and compile one qualified IOUserClient.cpp with optional RAM tracing.

Does not modify the source tree, baseline objects, filelist, archive or kernel.
result.json identifies the one object the consuming native relink must replace.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys


BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
DEVICE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(DEVICE / 'ci'))
import framebuffer_call_trace as overlay
from compile_dependencies import run_recorded


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def object_symbols(path):
    data = path.read_bytes()
    magic, cpu, subtype, kind, count = struct.unpack_from('<5I', data)
    if (magic, cpu, subtype & 0xffffff, kind) != (0xfeedfacf, 0x100000c, 2, 1):
        raise ValueError('Expected an arm64e Mach-O relocatable object')
    offset = 32
    for _ in range(count):
        command, size = struct.unpack_from('<II', data, offset)
        if command == 2:
            symoff, nsyms, stroff, _ = struct.unpack_from('<4I', data, offset + 8)
            found = {}
            for index in range(nsyms):
                string, ntype, section, desc, value = struct.unpack_from('<IBBHQ', data, symoff + index * 16)
                end = data.index(b'\0', stroff + string)
                found[data[stroff + string:end].decode()] = dict(type=ntype, section=section, desc=desc, value=value)
            return found
        offset += size
    raise ValueError('Object has no symbol table')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--baseline', type=Path, default=BASE / 'native-screen007-055-001')
    parser.add_argument('--tests', type=Path, required=True, help='Passing actual-method ASan/UBSan result.json')
    args = parser.parse_args()
    baseline = args.baseline.resolve()
    plan = json.loads((baseline / 'plan.json').read_text())
    jobs = [job for job in plan['jobs'] if Path(job['source']).name == 'IOUserClient.cpp']
    if len(jobs) != 1:
        raise ValueError('Expected exactly one recorded native IOUserClient.cpp job')
    job = jobs[0]
    source = Path(job['source'])
    source_bytes = source.read_bytes()
    if sha(source) != overlay.SOURCE_SHA256 or job['source_sha256'] != overlay.SOURCE_SHA256:
        raise ValueError('Recorded and current native source must match the qualified SHA256')
    text = source_bytes.decode()
    adapted = overlay.adapt_source(text)
    original_object = Path(job['output'])
    original_receipt = json.loads(original_object.with_name(original_object.name + '.json').read_text())
    if original_receipt['exit'] or sha(original_object) != original_receipt['sha256']:
        raise ValueError('Original cached IOUserClient object identity changed')
    tests = json.loads(args.tests.read_text())
    if (not tests.get('passed') or tests['original_source_sha256'] != overlay.SOURCE_SHA256 or
            tests['adapted_source_sha256'] != overlay.digest(adapted.encode()) or
            tests['overlay_sha256'] != sha(DEVICE / 'ci/framebuffer_call_trace.py') or
            tests['headers'][overlay.HEADER_NAME] != sha(DEVICE / 'ci' / overlay.HEADER_NAME) or
            tests['test_sha256'] != sha(DEVICE / 'ci/framebuffer_call_trace_tests.py')):
        raise ValueError('Require passing tests of the current exact overlay and header')
    command = job['command']
    compiler = Path(command[0])
    if sha(compiler) != plan['compiler_sha256']:
        raise ValueError('Recorded PAC compiler changed')
    if '-fptrauth-function-pointer-type-discrimination' not in command or not any(
            value.startswith('--target=arm64e-apple-ios27.') for value in command):
        raise ValueError('Require the native arm64e/iOS27 PAC compilation recipe')
    if any(value.startswith(('-fno-ptrauth', '-mno-ptrauth')) for value in command):
        raise ValueError('PAC-disabling flags are not permitted')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    staged_source = out / source.name
    staged_source.write_bytes(adapted.encode())
    staged_header = out / overlay.HEADER_NAME
    shutil.copyfile(DEVICE / 'ci' / overlay.HEADER_NAME, staged_header)
    destination = out / 'IOUserClient.cpo'
    compiled = []
    index = 0
    while index < len(command):
        value = command[index]
        if value == job['source']:
            compiled.append(str(staged_source))
        elif value == '-o':
            compiled += ['-o', str(destination)]
            index += 1
        elif value in ('-MF', '-MT', '-MJ'):
            index += 1
        elif value not in ('-MD', '-MP', '-MMD'):
            compiled.append(value)
        index += 1
    # Preserve quoted private-header lookup after moving only the source file.
    # Preserve the retained XNU warning policy, including its existing SDK and
    # newer-Clang header warnings. Refuse warnings in the added code below.
    compiled += ['-I', str(out), '-I', str(source.parent)]
    env = dict(os.environ, CCC_OVERRIDE_OPTIONS='# +-Wno-missing-designated-field-initializers +-Wno-unused-but-set-global')
    (out / 'compile-command.json').write_text(json.dumps(compiled, indent=2) + '\n')
    result = run_recorded(compiled, cwd=job['directory'], env=env, capture_output=True, text=True)
    (out / 'compile.log').write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError((result.stdout + result.stderr)[-7000:])
    helper_line = adapted[:adapted.index(overlay.HELPER)].count('\n') + 1
    trace_end_line = helper_line + overlay.extracted_code(adapted).count('\n')
    for diagnostic in (result.stdout + result.stderr).splitlines():
        if 'warning:' not in diagnostic:
            continue
        if str(staged_header) + ':' in diagnostic:
            raise ValueError('New trace header warning: ' + diagnostic)
        match = re.match(re.escape(str(staged_source)) + r':(\d+):\d+: warning:', diagnostic)
        if match and helper_line <= int(match[1]) <= trace_end_line:
            raise ValueError('New trace source warning: ' + diagnostic)
    symbols = object_symbols(destination)
    for name in ('_pdx_framebuffer_call_begin', '_pdx_framebuffer_call_end'):
        value = symbols[name]
        if value['type'] & 0xe or not value['desc'] & 0x40:
            raise ValueError('Callback must be an undefined Mach-O weak import: ' + name)
    symbol = '__ZN12IOUserClient18callExternalMethodEjP25IOExternalMethodArguments'
    if symbol not in symbols:
        raise ValueError('Native callExternalMethod definition missing')
    disassembler = '/usr/lib/llvm-23/bin/llvm-objdump'
    disasm_command = [disassembler, '-d', '--disassemble-symbols=' + symbol, str(destination)]
    disasm = subprocess.check_output(disasm_command, text=True)
    (out / 'callExternalMethod.asm').write_text(disasm)
    if 'pacibsp' not in disasm or 'blraa' not in disasm or 'retab' not in disasm:
        raise ValueError('Adapted function did not retain native PAC entry/dispatch/return')
    if source.read_bytes() != source_bytes:
        raise ValueError('Original native source changed while compiling')
    receipt = dict(
        object=str(destination), object_sha256=sha(destination),
        obj=str(destination), command=compiled,
        replaces_object=job['output'], baseline=str(baseline),
        original_object=str(original_object), original_object_sha256=sha(original_object),
        source=str(staged_source), source_sha256=sha(staged_source),
        original_source=str(source), original_source_sha256=overlay.SOURCE_SHA256,
        original_source_unchanged=True, header=str(staged_header), header_sha256=sha(staged_header),
        overlay_sha256=sha(DEVICE / 'ci/framebuffer_call_trace.py'),
        builder_sha256=sha(Path(__file__)), compiler=str(compiler), compiler_sha256=sha(compiler),
        compile_recipe=str(out / 'compile-command.json'),
        dependency_receipt=str(destination.with_name(destination.name + '.dependencies.json')),
        weak_callbacks=['pdx_framebuffer_call_begin', 'pdx_framebuffer_call_end'],
        boot_argument='first-frame-diag=1', client_class='IOMobileFramebufferUserClient',
        pac_flag='-fptrauth-function-pointer-type-discrimination', native_pac_dispatch_verified=True,
        source_method_envelope_only=True, original_private_layout_reads=False,
        vtable_interposition=False, policy_changes=False, auth_instruction_patches=False,
        verified=True, test_receipt=str(args.tests.resolve()), test_receipt_sha256=sha(args.tests),
        source_patch=dict(source=str(staged_source), source_sha256=sha(staged_source),
                          original_source=str(source), original_source_sha256=overlay.SOURCE_SHA256,
                          native_source_patch=overlay.PATCH_NAME),
        relinked=False, device_operations=False, runtime_verified=False)
    (out / 'result.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
