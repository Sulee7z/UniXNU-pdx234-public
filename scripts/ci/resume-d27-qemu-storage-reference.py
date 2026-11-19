#!/usr/bin/env python3
"""Validate an already successful storage native link and continue RELEASE-LTO."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    record_path = args.out / 'build-result.json'
    report = json.loads(record_path.read_text())
    if report['native_exit'] != 0 or report['reference_exit'] is not None:
        parser.error('Require successful native and no completed reference attempt')
    tree = Path(report['tree'])
    with (tree.parent / '.storage-reference.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        obj = tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
        source = tree / '.cache/xnu-work/bsd/kern/bsd_init.c'
        recipe = json.JSONDecoder().raw_decode((obj / 'bsd/DEVELOPMENT/bsd_init.o.json').read_text())[0]
        argv = recipe['arguments']
        enabled = '-DXNU_QEMU_SOURCE_BLOCK=1' in argv or any(
            a == '-D' and b == 'XNU_QEMU_SOURCE_BLOCK=1' for a, b in zip(argv, argv[1:]))
        if recipe['file'] != str(source) or sha(source) != report['source_bsd_sha256'] or not enabled:
            raise ValueError('Actual source/mode differs from the selected native build')
        nm = '/usr/lib/llvm-18/bin/llvm-nm'
        imported = subprocess.check_output([nm, '-u', str(obj / 'bsd/DEVELOPMENT/bsd_init.o')], text=True)
        if '_native_qemu_storage_start' not in imported.split():
            raise ValueError('Actual BSD object does not call source storage')
        native = obj / 'mach.development.bcm2837.unstripped'
        names = subprocess.check_output([nm, '-g', '--defined-only', str(native)], text=True)
        defined = {line.split()[-1] for line in names.splitlines() if line.strip()}
        for name in ('_native_qemu_storage_start', '_native_qemu_storage_state', '_native_virtio_read_checkpoint'):
            if name not in defined:
                raise ValueError('Actual native link lacks ' + name)
        shutil.copyfile(native, native.with_suffix(native.suffix + '.noctf'))
        report.update(native_sha256=sha(native), caller_integrated=True,
                      caller_object_sha256=sha(obj / 'bsd/DEVELOPMENT/bsd_init.o'),
                      validation_fix='Accept clang -D NAME=VALUE as well as -DNAME=VALUE')
        record_path.write_text(json.dumps(report, indent=2) + '\n')
        saved = json.loads(args.inputs.read_text())
        old = saved['new_tree']
        env = dict(os.environ)
        env.update({k: v.replace(old, str(tree)) for k, v in saved['environment'].items()})
        clt = Path(env['CLT_PREFIX'])
        env.update(PLATFORM='iPhoneOS', HOST_CC=str(clt / 'bin/xnu-host-cc'),
                   MIGCOM=str(clt / 'libexec/migcom'), TMPDIR=str(args.out.resolve()),
                   PYTHONDONTWRITEBYTECODE='1')
        print('Native source, -D pair, caller object and linked storage symbols verified', flush=True)
        # A single pipe reader serializes writes to the G-drive log. Clang children
        # do not contend on a shared DrvFS file position for every diagnostic.
        with (args.out / 'reference-build.log').open('xb') as log:
            process = subprocess.Popen(['python3', '-u', '-B',
                str(tree / 'scripts/build-fileset-release-reference.py'), '--tree', str(tree), '--lto'],
                cwd=tree, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            with process.stdout:
                while chunk := process.stdout.read(65536):
                    log.write(chunk)
            code = process.wait()
        report['reference_exit'] = code
        if code == 0:
            report['reference_sha256'] = sha(tree / 'build/xnu/fileset-reference/mach.release.bcm2837.unstripped.noctf')
        record_path.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2), flush=True)
        raise SystemExit(code)


if __name__ == '__main__':
    main()
