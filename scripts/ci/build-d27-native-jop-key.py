#!/usr/bin/env python3
"""Replay the missing upstream JOP selector hunk; preserve the no-carrier baseline."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

DEVICE = Path(__file__).resolve().parents[2]
UPSTREAM = DEVICE.parents[1]/'sources/UniXNU-main-20261109/patches/xnu-12377/native-pac-keys.patch'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def replay(record, source, obj):
    command, index = [], 0
    arguments = record['arguments']
    while index < len(arguments):
        value = arguments[index]
        if value == record['file']:
            command.append(str(source))
        elif value == '-o':
            command.extend(['-o', str(obj)]); index += 1
        elif value in ('-MF', '-MT', '-MQ', '-MJ'):
            index += 1
        elif value in ('-MD', '-MMD', '-MP'):
            pass
        elif value == '-Xclang' and index+1 < len(arguments) and arguments[index+1].startswith('-W'):
            index += 1
        else:
            command.append(value)
        index += 1
    if command.count(str(source)) != 1 or command.count(str(obj)) != 1:
        raise ValueError('Need exact recorded source/output replacements')
    return command+['-Wno-unknown-warning-option']


def apply_hunk(text, patch):
    section = patch.split('diff --git a/osfmk/arm64/machine_routines_asm.s', 1)[0]
    addition = '\n'.join(line[1:] for line in section.splitlines()
                         if line.startswith('+') and not line.startswith('+++'))+'\n'
    if not addition.startswith('#elif HAS_NATIVE_PAC\n') or '\treturn 1;' not in addition:
        raise ValueError('Pinned upstream native JOP hunk changed')
    before = ('ml_default_jop_pid(void)\n{\n#if HAS_PARAVIRTUALIZED_PAC\n'
              '\tvmapple_pac_get_default_keys();\n\treturn vmapple_default_jop_pid;\n')
    if text.count(before+'#else\n\treturn 0;') != 1:
        raise ValueError('Missing-hunk assumption is not true for this source')
    return text.replace(before, before+addition, 1)


def run(command, cwd, env, log):
    with log.open('x') as stream:
        result = subprocess.run(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(log.read_text()[-6000:])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree', type=Path, required=True)
    parser.add_argument('--mainline', type=Path, required=True)
    parser.add_argument('--startup-native', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--strict-out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    out = args.out.resolve()
    objdir = args.tree/'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
    native = args.startup_native.resolve()
    saved = json.loads((native/'report.json').read_text())
    if sha(native/'native.macho') != saved['native_sha256']:
        raise ValueError('Unchanged startup native is required')
    recipe = objdir/'osfmk/DEVELOPMENT/machine_routines_apple.o.json'
    record = json.JSONDecoder().raw_decode(recipe.read_text())[0]
    original = Path(record['file'])
    source = out/'machine_routines_apple.c'
    source.write_text(apply_hunk(original.read_text(), UPSTREAM.read_text()))
    obj = out/'machine_routines_apple.o'
    command = replay(record, source, obj)
    (out/'compile.command.json').write_text(json.dumps(command, indent=2)+'\n')
    env = dict(os.environ, TMPDIR=str(out), PYTHONDONTWRITEBYTECODE='1')
    run(command, record['directory'], env, out/'compile.log')
    link = json.loads((native/'native-link.command.json').read_text())
    original_list = Path(link[link.index('-filelist')+1])
    paths = original_list.read_text().splitlines()
    old = str(objdir/'osfmk/DEVELOPMENT/machine_routines_apple.o')
    if paths.count(old) != 1:
        raise ValueError('Ambiguous native JOP selector object')
    paths[paths.index(old)] = str(obj)
    required = [native/'bsd_init.o', native/'kern_exec.o', native/'IOKitBSDInit.cpo']
    if any(paths.count(str(path)) != 1 for path in required):
        raise ValueError('Verified startup objects were lost')
    if paths.count(str(objdir/'bsd/DEVELOPMENT/vm_unix.o')) != 1:
        raise ValueError('Keep the original no-carrier VM object')
    filelist = out/'link.filelist'
    filelist.write_text('\n'.join(paths)+'\n')
    link[link.index('-filelist')+1] = str(filelist)
    link[link.index('-o')+1] = str(out/'native.macho')
    (out/'native-link.command.json').write_text(json.dumps(link, indent=2)+'\n')
    env.update(CROSS_CLANG='/root/unixnu-build/pdx234-pac-toolchain/llvm/bin/clang-24',
               DARWIN_TRIPLE='arm64e-apple-ios27.0')
    env['PATH']='/root/unixnu-build/pdx234-pac-toolchain/CommandLineTools/usr/bin:'+env['PATH']
    run(link, objdir, env, out/'native-link.log')
    report = dict(upstream_patch=str(UPSTREAM), upstream_patch_sha256=sha(UPSTREAM),
                  baseline_source_sha256=sha(original), adapted_source_sha256=sha(source),
                  native_sha256=sha(out/'native.macho'), startup_objects={str(p):sha(p) for p in required},
                  carrier_enabled=False, native_jop_selector_expected=1, pac_authentication_retained=True,
                  runtime_qualified=False, device_operations=False)
    (out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2), flush=True)
    command = [sys.executable, '-B', str(DEVICE/'scripts/ci/finish-strict5-prelink.py'),
               '--tree', str(args.tree), '--mainline', str(args.mainline),
               '--native', str(out/'native.macho'), '--output', str(args.strict_out)]
    run(command, args.tree, env, out/'strict.log')
    print((out/'strict.log').read_text()[-2500:])


if __name__ == '__main__':
    main()
