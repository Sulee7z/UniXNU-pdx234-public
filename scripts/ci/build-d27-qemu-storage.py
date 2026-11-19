#!/usr/bin/env python3
"""Build the opt-in D27 QEMU source storage kernel in a separate Linux tree."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess

DEVICE = Path(__file__).resolve().parents[2]


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def helper(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--archive-report', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True, help='New ext4 build directory')
    parser.add_argument('--out', type=Path, required=True, help='New G-drive log directory')
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    saved = json.loads(args.inputs.read_text())
    old = Path(saved['new_tree']).resolve()
    archive_record = json.loads(args.archive_report.read_text())
    archive = Path(archive_record['archive']).resolve()
    if sha(archive) != archive_record['archive_sha256'] or archive_record['complete_block_pac_slots_checked'] != 190:
        parser.error('Require the exact audited source-block archive')
    if not archive_record['early_class_initializer_sections_removed']:
        parser.error('Source storage must register after the original family')
    if subprocess.check_output(['findmnt', '-T', str(args.work.parent), '-n', '-o', 'FSTYPE'], text=True).strip() != 'ext4':
        parser.error('Build work requires ext4')
    args.out.mkdir(parents=True, exist_ok=False)
    args.work.mkdir(parents=True, exist_ok=False)
    tree = args.work.resolve() / 'tree'
    with (old.parent / '.strict5-build.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print('Copy prepared tree; preserve baseline source and objects', flush=True)
        subprocess.run(['cp', '-a', '--reflink=auto', str(old), str(tree)], check=True)
    resume = helper('storage_rebase', DEVICE / 'scripts/ci/resume-strict5-local.py')
    rebased = resume.rebase_generated(tree / 'build/xnu', old, tree)
    caller = helper('storage_caller', DEVICE / 'scripts/ci/prepare-qemu-storage-caller.py')
    source = tree / '.cache/xnu-work/bsd/kern/bsd_init.c'
    baseline = sha(source)
    source.write_text(caller.inject(source.read_text()))
    script = tree / 'scripts/build-xnu-4k-baseline.sh'
    text = script.read_text()
    lines = text.splitlines(keepends=True)
    sites = [i for i, line in enumerate(lines) if line.startswith('EXTRA_MAKE_ARGS+=("bsd_init.o_CFLAGS_ADD=')]
    if len(sites) != 1:
        raise ValueError('Native BSD object flag declaration changed')
    index = sites[0]
    lines[index] = lines[index].replace('bsd_init.o_CFLAGS_ADD=',
                                        'bsd_init.o_CFLAGS_ADD=-DXNU_QEMU_SOURCE_BLOCK=1 ', 1)
    text = ''.join(lines)
    script.write_text(text)
    env = dict(os.environ)
    env.update({k: v.replace(str(old), str(tree)) for k, v in saved['environment'].items()})
    clt = Path(env['CLT_PREFIX'])
    env.update(PLATFORM='iPhoneOS', HOST_CC=str(clt / 'bin/xnu-host-cc'),
               MIGCOM=str(clt / 'libexec/migcom'), TMPDIR=str(args.out.resolve()),
               PYTHONDONTWRITEBYTECODE='1',
               XNU_EXTRA_LD_ARCHIVES=f'-Wl,-force_load,{archive}')
    obj = tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
    # A freshly copied kernel must be linked even if Make does not track extra archives.
    native = obj / 'mach.development.bcm2837.unstripped'
    (args.out / 'baseline-native.sha256').write_text(sha(native) + '\n')
    native.unlink()
    report = dict(tree=str(tree), baseline_tree=str(old), generated_files_rebased=len(rebased),
                  baseline_bsd_sha256=baseline, source_bsd_sha256=sha(source),
                  archive_sha256=sha(archive), native_exit=None, reference_exit=None,
                  caller_integrated=False, actual_io_qualified=False, root_mounted=False,
                  device_operations=False, github_actions_invoked=False)
    record_path = args.out / 'build-result.json'
    record_path.write_text(json.dumps(report, indent=2) + '\n')
    print('Build native with QEMU-only BSD caller and late storage archive', flush=True)
    with (args.out / 'native-build.log').open('x') as log:
        code = subprocess.run(['bash', str(script)], cwd=tree, env=env,
                              stdout=log, stderr=subprocess.STDOUT).returncode
    report['native_exit'] = code
    record_path.write_text(json.dumps(report, indent=2) + '\n')
    if code:
        raise SystemExit('Native build failed; see native-build.log')
    recipe = json.JSONDecoder().raw_decode((obj / 'bsd/DEVELOPMENT/bsd_init.o.json').read_text())[0]
    argv = recipe['arguments']
    enabled = '-DXNU_QEMU_SOURCE_BLOCK=1' in argv or any(
        a == '-D' and b == 'XNU_QEMU_SOURCE_BLOCK=1' for a, b in zip(argv, argv[1:]))
    if recipe['file'] != str(source) or not enabled:
        raise ValueError('BSD caller was not compiled from the new source with the selected mode')
    nm = '/usr/lib/llvm-18/bin/llvm-nm'
    names = subprocess.check_output([nm, '-g', '--defined-only', str(native)], text=True)
    for symbol in ('_native_qemu_storage_start', '_native_qemu_storage_state', '_native_virtio_read_checkpoint'):
        if not any(line.split()[-1] == symbol for line in names.splitlines() if line.strip()):
            raise ValueError('Storage implementation not linked: ' + symbol)
    shutil.copyfile(native, native.with_suffix(native.suffix + '.noctf'))
    report.update(native_sha256=sha(native), caller_integrated=True)
    record_path.write_text(json.dumps(report, indent=2) + '\n')
    print('Native linked; build RELEASE-LTO reference', flush=True)
    with (args.out / 'reference-build.log').open('x') as log:
        code = subprocess.run(['python3', '-B', str(tree / 'scripts/build-fileset-release-reference.py'),
                               '--tree', str(tree), '--lto'], cwd=tree, env=env,
                              stdout=log, stderr=subprocess.STDOUT).returncode
    report['reference_exit'] = code
    if not code:
        report['reference_sha256'] = sha(tree / 'build/xnu/fileset-reference/mach.release.bcm2837.unstripped.noctf')
    record_path.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2), flush=True)
    raise SystemExit(code)


if __name__ == '__main__':
    main()
