#!/usr/bin/env python3
"""Stage/compile only the exact missing official addon truncation hunk.

Everything created stays below ci/platform067/arm64e. The selected066 object,
its signed-Block ABI and all source/dependency hashes are checked first.
No link, package, global recipe edit, shared source edit, or device access.
"""
from __future__ import annotations

import argparse
import difflib
import json
from pathlib import Path
import subprocess
import sys

from audit import BASE, FRESH, HERE, REPO, NATIVE_SHA, sha, parse_patch, selected_inputs

ANCHOR = ('\t\tVATTR_SET(&va, va_mode, mode);\n'
          '\t\terror = vnode_setattr(vp, &va, ctx);')
ADDITION = ('\t\t/* Kernel vnode_open does not finish O_TRUNC on the non-compound path. */\n'
            '\t\tVATTR_SET(&va, va_data_size, size);\n')


def adapt(text: str, official: str) -> str:
    diffs = parse_patch(official)
    added = [line for diff in diffs for hunk in diff.hunks for tag, line in hunk.lines if tag == '+']
    if ADDITION.rstrip('\n') not in '\n'.join(added):
        raise ValueError('Fixed official patch does not contain the requested hunk')
    if text.count(ANCHOR) != 1:
        raise ValueError('Addon-only anchor missing or ambiguous; refuse already applied/modified source')
    start = text.rfind('native_gpu_addon_write(', 0, text.index(ANCHOR))
    if start < 0 or not text[start:text.index(ANCHOR)].lstrip().startswith('native_gpu_addon_write('):
        raise ValueError('Anchor outside the expected addon writer')
    return text.replace(ANCHOR, '\t\tVATTR_SET(&va, va_mode, mode);\n' + ADDITION +
                        '\t\terror = vnode_setattr(vp, &va, ctx);', 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=HERE / 'addon-size-compile-001')
    parser.add_argument('--compile', action='store_true')
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to(HERE) or out == HERE or out.exists():
        raise ValueError('Require a new isolated directory beneath ' + str(HERE))
    native = BASE / 'native-sony-touch-066-002'
    result = json.loads((native / 'result.json').read_text())
    if sha(native / 'native.macho') != NATIVE_SHA:
        raise ValueError('066 baseline changed')
    replacement = next(r for r in result['block_descriptor_abi']['replacements']
                       if Path(r['old_object']).name == 'kern_exec.o')
    _, inputs = selected_inputs(native)
    if replacement['new_object'] not in inputs:
        raise ValueError('This is not the actually selected signed-Block kern_exec object')
    source = Path(replacement['source'])
    receipt_path = Path(replacement['dependency_receipt'])
    receipt = json.loads(receipt_path.read_text())
    if sha(source) != replacement['source_sha256'] or sha(replacement['new_object']) != replacement['new_sha256']:
        raise ValueError('Selected source/object identity changed')
    for path, digest in receipt['dependencies'].items():
        if sha(path) != digest:
            raise ValueError('Selected compiler dependency changed: ' + path)
    if sha(receipt['dependency_compiler']) != receipt['dependency_compiler_sha256']:
        raise ValueError('Selected compiler changed')
    flags = receipt['command']
    if '-fptrauth-function-pointer-type-discrimination' not in flags or not any(
            flags[i:i + 2] == ['-Xclang', '-fptrauth-block-descriptor-pointers'] for i in range(len(flags) - 1)):
        raise ValueError('Require inherited063 type-discrimination and Block-descriptor ABI')
    official = FRESH / 'UniXNU/patches/xnu-12377/zzy-native-gpu-addon-mount.patch'
    original = source.read_text()
    adapted = adapt(original, official.read_text())
    out.mkdir(parents=True, exist_ok=False)
    staged = out / 'kern_exec.c'
    staged.write_text(adapted)
    delta = '\n'.join(difflib.unified_diff(original.splitlines(), adapted.splitlines(),
                                         fromfile='a/bsd/kern/kern_exec.c', tofile='b/bsd/kern/kern_exec.c')) + '\n'
    (out / 'official-addon-size.patch').write_text(delta)
    command = []
    skip_next = False
    for i, value in enumerate(flags):
        if skip_next:
            skip_next = False
            continue
        if value in ('-MF', '-MT', '-MQ', '-MJ'):
            skip_next = True
            continue
        if value in ('-MD', '-MMD', '-MP'):
            continue
        command.append(value)
    command[command.index(str(source))] = str(staged)
    obj = out / 'kern_exec.o'
    command[command.index('-o') + 1] = str(obj)
    # Preserve lookup semantics when the translation unit moves; no header is copied/modified.
    command += ['-iquote', str(source.parent)]
    directory = replacement['directory']
    plan = {'official_patch': str(official), 'official_patch_sha256': sha(official),
            'baseline_native_sha256': NATIVE_SHA, 'selected_object': replacement['new_object'],
            'selected_object_sha256': replacement['new_sha256'], 'selected_source': str(source),
            'selected_source_sha256': sha(source), 'staged_source': str(staged),
            'staged_source_sha256': sha(staged), 'directory': directory, 'command': command,
            'delta': delta, 'pac_type_discrimination_retained': True, 'signed_block_descriptors_retained': True,
            'shared_source_mutation': False, 'link_executed': False, 'device_operations': False}
    (out / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    if args.compile:
        sys.path.insert(0, str(REPO / 'ci'))
        from compile_dependencies import run_recorded, valid
        with (out / 'compile.log').open('x') as stream:
            done = run_recorded(command, cwd=directory, stdout=stream, stderr=subprocess.STDOUT, timeout=180)
        if done.returncode:
            raise RuntimeError((out / 'compile.log').read_text()[-7000:])
        new_receipt = json.loads(Path(str(obj) + '.dependencies.json').read_text())
        if not valid(new_receipt):
            raise ValueError('New isolated object dependencies are not valid')
        plan.update(compiled=True, object=str(obj))
        plan['object_sha256'] = sha(obj)
        plan['dependency_receipt'] = str(obj) + '.dependencies.json'
        plan['dependency_receipt_sha256'] = sha(plan['dependency_receipt'])
        plan['dependencies_valid'] = True
    else:
        plan['compiled'] = False
    (out / 'result.json').write_text(json.dumps(plan, indent=2) + '\n')
    print(json.dumps({'out': str(out), 'compiled': plan['compiled'], 'object_sha256': plan.get('object_sha256'),
                      'baseline_unchanged': sha(source) == replacement['source_sha256'], 'linked': False}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
