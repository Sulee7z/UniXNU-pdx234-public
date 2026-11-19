#!/usr/bin/env python3
"""Resume the isolated D27 build after rebasing copied generated Makefiles.

Local build only. This never invokes GitHub, Actions or device tools. Supply
the saved build-inputs.json and its existing isolated tree explicitly.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def rebase_generated(build, old, new):
    """Change only generated dependencies/file lists/Makefiles, not old logs or records."""
    changed = []
    for path in Path(build).rglob('*'):
        if not path.is_file() or path.is_symlink():
            continue
        if not (path.name.startswith('Makefile') or path.suffix in ('.d', '.dep', '.exp', '.filelist')):
            continue
        data = path.read_bytes()
        replaced = data.replace(str(old).encode(), str(new).encode())
        if replaced != data:
            path.write_bytes(replaced)
            changed.append(str(path.relative_to(build)))
    return changed


def preserve_stale_objects(tree, artifacts):
    root = tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
    backup = artifacts / 'rejected-stale-source-001'
    if backup.exists():
        raise ValueError('Stale-source backup exists; do not repeat this resume')
    backup.mkdir()
    paths = []
    for folder, name, extension in [('iokit', 'IOUserServer', 'cpo'),
                                    ('iokit', 'IOService.iig', 'cpo'),
                                    ('libkern', 'image4_v2', 'o')]:
        paths.extend(root / folder / 'DEVELOPMENT' / (name + suffix)
                     for suffix in ('.' + extension, '.' + extension + '.json', '.d'))
    paths.extend(p for p in root.glob('mach.development.bcm2837.*') if p.is_file())
    saved = []
    for path in paths:
        if path.exists():
            target = backup / path.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(path), target)
            saved.append(str(path.relative_to(root)))
    return saved


def enable_recursive_jobserver(source):
    path = source / 'makedefs/MakeInc.dir'
    text = path.read_text()
    # These recipes are expanded by eval; '+' retains GNU make's jobserver FDs.
    count = text.count('\t$(_v)$(MAKE) ')
    if count != 2:
        raise ValueError('Unexpected recursive make template; inspect before changing it')
    path.write_text(text.replace('\t$(_v)$(MAKE) ', '\t+$(_v)$(MAKE) '))
    return count


def run(command, cwd, env, log):
    with log.open('x') as stream:
        return subprocess.run(command, cwd=cwd, env=env,
                              stdout=stream, stderr=subprocess.STDOUT).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', required=True, type=Path)
    parser.add_argument('--artifacts', required=True, type=Path)
    parser.add_argument('--reference-only', action='store_true',
                        help='Retry only RELEASE-LTO after validating the successful native hash')
    parser.add_argument('--reference-log', help='Fresh log filename under artifacts, e.g. reference-build-004.log')
    args = parser.parse_args()
    if args.reference_log and (Path(args.reference_log).name != args.reference_log or not args.reference_log.endswith('.log')):
        parser.error('--reference-log must be a simple .log filename')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    inputs = json.loads(args.inputs.read_text())
    old, tree = Path(inputs['old_tree']), Path(inputs['new_tree'])
    if old.resolve() == tree.resolve() or not (tree / '.cache/xnu-work').is_dir():
        parser.error('Require a distinct, already prepared isolated build tree')
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    with (tree.parent / '.strict5-build.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        env = dict(os.environ)
        env.update(inputs['environment'])
        # The native bash child exports these internally; Python does not inherit
        # a child's environment when it starts the separate reference builder.
        clt = Path(env['CLT_PREFIX'])
        env.update(PLATFORM='iPhoneOS', HOST_CC=str(clt / 'bin/xnu-host-cc'),
                   MIGCOM=str(clt / 'libexec/migcom'))
        result_path = artifacts / 'build-result.json'
        obj = tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
        native = obj / 'mach.development.bcm2837.unstripped'
        if args.reference_only:
            report = json.loads(result_path.read_text())
            if report.get('native_exit') != 0 or report.get('native_sha256') != sha(native):
                raise SystemExit('Reference retry requires the recorded successful native build')
            report['previous_reference_exit'] = report.get('reference_exit')
            report['reference_exit'] = None
        else:
            rebased = rebase_generated(tree / 'build/xnu', old, tree)
            saved = preserve_stale_objects(tree, artifacts)
            jobserver = enable_recursive_jobserver(tree / '.cache/xnu-work')
            report = {'old_tree_read_only': str(old), 'new_tree': str(tree),
                      'generated_files_rebased': rebased, 'stale_outputs_preserved': saved,
                      'recursive_jobserver_recipes_fixed': jobserver,
                      'native_exit': None, 'reference_exit': None, 'device_operations': False,
                      'github_actions_invoked': False}
            result_path.write_text(json.dumps(report, indent=2) + '\n')
            code = run(['bash', str(tree / 'scripts/build-xnu-4k-baseline.sh')], tree, env,
                       artifacts / 'native-build-002.log')
            report['native_exit'] = code
            result_path.write_text(json.dumps(report, indent=2) + '\n')
            if code:
                raise SystemExit('Native rebuild failed; see native-build-002.log')
            for relative in ('iokit/DEVELOPMENT/IOUserServer.cpo.json', 'libkern/DEVELOPMENT/image4_v2.o.json'):
                record = json.JSONDecoder().raw_decode((obj / relative).read_text())[0]
                if not record['file'].startswith(str(tree / '.cache/xnu-work') + '/'):
                    raise SystemExit('A changed source was compiled from a stale path: ' + relative)
            shutil.copyfile(native, native.with_suffix(native.suffix + '.noctf'))
            report['native_sha256'] = sha(native)
        report['reference_host_environment'] = {name: env[name] for name in ('PLATFORM', 'HOST_CC', 'MIGCOM')}
        result_path.write_text(json.dumps(report, indent=2) + '\n')
        log_name = args.reference_log or ('reference-build-003.log' if args.reference_only else 'reference-build-002.log')
        code = run(['python3', str(tree / 'scripts/build-fileset-release-reference.py'),
                    '--tree', str(tree), '--lto'], tree, env, artifacts / log_name)
        report['reference_exit'] = code
        if code == 0:
            report['reference_sha256'] = sha(tree / 'build/xnu/fileset-reference/mach.release.bcm2837.unstripped.noctf')
        result_path.write_text(json.dumps(report, indent=2) + '\n')
        if code:
            raise SystemExit('RELEASE-LTO rebuild failed; see ' + log_name)
        print(json.dumps({k: report[k] for k in ('native_exit', 'reference_exit', 'native_sha256', 'reference_sha256')}))


if __name__ == '__main__':
    main()
