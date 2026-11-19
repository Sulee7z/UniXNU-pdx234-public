#!/usr/bin/env python3
"""Prepare and compile both states of the QEMU-only BSD storage caller.

The existing source tree and kernel are never changed. Outputs are staged for
later explicit QEMU integration; compilation is not guest execution.
"""
import argparse
import difflib
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

MARKER = '\tvfsinit();\n'
CALLER = '''\tvfsinit();
#if defined(XNU_QEMU_SOURCE_BLOCK) && XNU_QEMU_SOURCE_BLOCK
\t/* QEMU-only late storage classes; the runtime independently rejects other platforms. */
\textern void native_qemu_storage_start(void);
\tnative_qemu_storage_start();
#endif
'''


def inject(text):
    if text.count(MARKER) != 1 or 'native_qemu_storage_start' in text:
        raise ValueError('Require one unmodified BSD VFS initialization caller')
    return text.replace(MARKER, CALLER)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree', required=True, type=Path)
    parser.add_argument('--mainline', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    tree, mainline, out = args.tree.resolve(), args.mainline.resolve(), args.output.resolve()
    source = tree / '.cache/xnu-work/bsd/kern/bsd_init.c'
    original = source.read_bytes()
    text = original.decode().replace('\r\n', '\n')
    changed = inject(text)
    recipe = tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/bsd/DEVELOPMENT/bsd_init.o.json'
    record = json.loads(recipe.read_text().strip().rstrip(','))
    native_warning_policy = ['-Wno-missing-designated-field-initializers',
                             '-Wno-unknown-warning-option', '-Wno-sign-compare']
    if any(flag not in record['arguments'] for flag in native_warning_policy):
        raise ValueError('Recorded native BSD warning policy changed')
    spec = importlib.util.spec_from_file_location('qemu_bsd_compile', mainline / 'scripts/build-sheng-source-drivers.py')
    compiler = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(compiler)
    nm = Path(record['arguments'][0]).parent / 'llvm-nm'
    if not nm.is_file():
        nm = Path(shutil.which('llvm-nm') or '/nonexistent/llvm-nm')
    if not nm.is_file():
        parser.error('LLVM nm is needed to verify the caller is actually opt-in')
    out.mkdir(parents=True, exist_ok=False)
    staged = out / 'bsd_init.c'
    staged.write_text(changed)
    patch = ''.join(difflib.unified_diff(text.splitlines(keepends=True), changed.splitlines(keepends=True),
                                       fromfile='a/bsd/kern/bsd_init.c', tofile='b/bsd/kern/bsd_init.c'))
    (out / 'qemu-storage-caller.patch').write_text(patch)
    objects = []
    for enabled in (0, 1):
        output = out / f'bsd_init-mode{enabled}.o'
        command = compiler.compile_command(record, staged, output, [],
                                            [*native_warning_policy, f'-DXNU_QEMU_SOURCE_BLOCK={enabled}'])
        (out / f'mode{enabled}.command.json').write_text(json.dumps(command, indent=2) + '\n')
        done = subprocess.run(command, cwd=record['directory'], capture_output=True, text=True, timeout=180)
        (out / f'mode{enabled}.log').write_text(done.stdout + done.stderr)
        if done.returncode:
            raise RuntimeError((done.stdout + done.stderr)[-6000:])
        symbols = subprocess.check_output([str(nm), '-u', str(output)], text=True).splitlines()
        imported = any(line.split()[-1] == '_native_qemu_storage_start' for line in symbols if line.strip())
        if imported != bool(enabled):
            raise ValueError('Compiled BSD caller does not follow its QEMU-only configuration')
        objects.append({'enabled': bool(enabled), 'object_sha256': hashlib.sha256(output.read_bytes()).hexdigest(),
                        'imports_qemu_storage_start': imported, 'werror': True})
    if source.read_bytes() != original:
        raise ValueError('Existing source changed during the preparation; preserve both inputs')
    report = {'original_source': str(source), 'original_source_sha256': hashlib.sha256(original).hexdigest(),
              'staged_source_sha256': hashlib.sha256(staged.read_bytes()).hexdigest(), 'objects': objects,
              'recorded_native_warning_policy': native_warning_policy,
              'original_source_unchanged': True, 'kernel_linked': False, 'guest_executed': False,
              'device_operations': False}
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
