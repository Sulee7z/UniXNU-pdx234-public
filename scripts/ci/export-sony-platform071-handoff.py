#!/usr/bin/env python3
"""Export the PDX071 source tree and the files used in a successful local replay."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile

DEVICE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(DEVICE/'ci'))
from link_inputs import collect_link_inputs
PORTS = DEVICE.parent
BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
ARTIFACTS = Path('/mnt/f/UniXNU-Port-artifacts')
CURRENT = ARTIFACTS / 'platform069-20261118'
TOOLS = Path('/root/unixnu-build')
TOOLCHAIN = Path('/root/unixnu-toolchain')
SONY_TOUCH_REFERENCE = PORTS.parent / 'references/sony-sw82907-20261118'
BULK = BASE / 'sources/UniXNU/out/pdx234/ios-27.0.1-24A446-iphone14/pdx234_sheng27_bulk/tree'
SAFE_ROOTS = (PORTS, SONY_TOUCH_REFERENCE, BASE, ARTIFACTS, TOOLS, TOOLCHAIN)
SOURCE_SUFFIXES = {
    '.ac', '.am', '.awk', '.c', '.cc', '.cfg', '.cl', '.cmake', '.conf', '.cpp', '.cxx', '.dec', '.def',
    '.defs', '.dsc', '.dts', '.dtsi', '.exports', '.fdf', '.fish', '.glsl', '.gni', '.go', '.h', '.hh',
    '.hpp', '.i', '.iig', '.in', '.inc', '.inf', '.json', '.l', '.ld', '.lds', '.m', '.m4', '.mak', '.map',
    '.md', '.mk', '.mm', '.patch', '.plist', '.py', '.rst', '.rs', '.s', '.sh', '.symbols', '.tbd',
    '.toml', '.txt', '.xml', '.y', '.yaml', '.yml', '.zsh',
}
SOURCE_NAMES = {'Kbuild', 'Makefile', 'meson.build', 'meson.options', 'meson_options.txt', 'README', 'unixnu', 'series',
                '.config', '.gitignore', '.gitattributes', '.gitmodules'}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def git(directory, *args):
    return subprocess.check_output(['git', '-C', str(directory), *args], timeout=45)


def in_layout(path):
    return any(path.is_relative_to(root) for root in SAFE_ROOTS)


def valid_name(path):
    name = path.name.lower()
    return (name not in {'local.toml', 'unixnu.local.toml', '.env', '.git-credentials', 'hosts.yml'}
            and path.suffix.lower() not in {'.pem', '.p12', '.key', '.pfx', '.dmg', '.ipsw'}
            and not any(part in {'.git', '.ssh', '__pycache__'} for part in path.parts)
            and 'ios-log-window.bin' not in str(path))


def is_source(path):
    name = path.name
    if not valid_name(path) or path.name == 'SonyGeniFirmware.cpp':
        return False
    if name.startswith(('LICENSE', 'COPYING', 'NOTICE')) or name.endswith('_defconfig'):
        allowed = True
    else:
        allowed = path.suffix.lower() in SOURCE_SUFFIXES or name in SOURCE_NAMES
    if not allowed or not path.is_file():
        return False
    with path.open('rb') as stream:
        return b'\0' not in stream.read(8192)


def tree(root):
    for directory, subdirs, names in os.walk(root):
        subdirs[:] = [x for x in subdirs if x not in {'.git', '.cache', '__pycache__', '.venv', '.idea', 'node_modules'}]
        for name in names:
            yield Path(directory) / name


def git_tree(root, untracked=False):
    args = ['ls-files', '-z', '--cached']
    if untracked:
        args += ['--others', '--exclude-standard']
    return (root / os.fsdecode(name) for name in git(root, *args).split(b'\0') if name)


def describe_git(root, local=False):
    if not (root / '.git').exists():
        return {'path': str(root), 'type': 'source export', 'local': local}
    result = {'path': str(root), 'commit': git(root, 'rev-parse', 'HEAD').decode().strip(), 'local': local}
    try:
        origin = git(root, 'remote', 'get-url', 'origin').decode().strip()
    except subprocess.CalledProcessError:
        return result
    if origin.startswith('https://') and '@' not in origin:
        result['origin'] = origin
    return result


def trace_files(trace):
    """Use successful read-only opens and executable paths from strace -f -yy."""
    opens = re.compile(r'\bopen(?:at2?)?\(.*?"([^"\n]+)".*O_RDONLY.*?= \d+<([^>\n]+)>')
    execs = re.compile(r'\bexecve\("(/[^"\n]+)".*\) += 0$')
    paths = set()
    with trace.open(errors='replace') as stream:
        for line in stream:
            if line.startswith('/'):
                paths.add(Path(line.rstrip('\n')))
                continue
            match = opens.search(line)
            found = (match[1], match[2]) if match else execs.findall(line.rstrip())
            for name in found:
                if name.startswith('/'):
                    paths.add(Path(os.path.normpath(name)))
    return paths


def add_bytes(archive, name, data, mode=0o644):
    info = tarfile.TarInfo(name)
    info.mode, info.size = mode, len(data)
    archive.addfile(info, io.BytesIO(data))


def add_file(archive, name, path):
    info = archive.gettarinfo(str(path.resolve()), name)
    if not info.isfile():
        raise ValueError(f'Expected regular file {path}')
    info.mode, info.uid, info.gid, info.mtime = 0o755 if info.mode & 0o111 else 0o644, 0, 0, 0
    info.uname = info.gname = ''
    with path.open('rb') as stream:
        archive.addfile(info, stream)
    return {'path': name, 'bytes': info.size, 'sha256': sha(path), 'mode': oct(info.mode)}


def pack(output, files, manifest, extras):
    with tarfile.open(output, 'x:gz', compresslevel=3) as archive:
        records = [add_file(archive, 'layout/' + str(p).lstrip('/'), p) for p in sorted(files)]
        for name, path in extras.items():
            add_file(archive, name, path)
        add_bytes(archive, manifest, (json.dumps(records, indent=2) + '\n').encode())
    return len(records)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--trace', required=True, type=Path, action='append')
    p.add_argument('--replay', type=Path)
    p.add_argument('--part', choices=('source', 'build'), required=True)
    args = p.parse_args()
    out = args.out.resolve()
    tools = DEVICE / 'scripts/handoff'
    replay = args.replay.resolve() if args.replay else None
    if args.part == 'build':
        build_pack(out, tools, replay, args.trace)
        return

    source_files = set()
    pins = []

    def include(items):
        source_files.update(p for p in items if in_layout(p) and is_source(p))

    for root in (DEVICE, PORTS / 'uefi-pdx234'):
        pins.append(describe_git(root, local=True))
        include(git_tree(root, untracked=True))
    for root in (CURRENT / 'UniXNU', CURRENT / 'sheng', CURRENT / 'AdrenoMetal', BASE / 'sources/UniXNU',
                 BASE / 'sources/sheng', BASE / 'sources/armcpu-spi', BASE / 'sources/sm8550',
                 BASE / 'sources/sony-current-ufs', DEVICE / '.cache/firmware-components/DarwinBoot',
                 DEVICE / 'drivers/QcomXnuUsbDebug', BASE/'metal-runtime-001/.cache/mesa-work',
                 BASE/'metal-runtime-001/.cache/gpu-reference/metal2vulkan'):
        pins.append(describe_git(root, local=root.is_relative_to(BASE)))
        include(git_tree(root, untracked=True))
    for root in (
        BULK / '.cache/xnu-work', BULK / 'patches', BULK / 'scripts', BASE / 'sources/d27-bulk-overlays',
        BASE / 'sources/sony', BASE / 'display-source-004/drivers', BASE / 'display-source-004/kits',
        BASE / 'gpu-source-006/drivers', BASE / 'gpu-source-006/kits', BASE / 'metal-d27-strip-fixed-001',
        BASE / 'metal-runtime-001/drivers', BASE / 'metal-runtime-001/kits', BASE / 'metal-runtime-001/host-bin',
        BASE / 'metal-runtime-001/.cache/mesa-work', BASE / 'sony-wcn-067-002/source',
        BASE / 'sony-wcn-067-002/components', BASE / 'sony-touch-driver-015/source',
        BASE / 'block-descriptor-test-008', BASE / 'strict-006/XnuPrelink', CURRENT / 'plan-final071-001',
        CURRENT / 'radio-provider070-001/source', CURRENT / 'wifi-supplicant070-001/component',
        CURRENT / 'radio-userland069-002/source', CURRENT / 'display-driver-015',
        CURRENT / 'shared-owners069-006/source', CURRENT / 'display-reference-001', CURRENT / 'display-gdsc-reference-003',
        CURRENT / 'display-inputs-003', CURRENT / 'crashes-build-001', CURRENT / 'performance-build-002/sources',
    ):
        if root.is_dir():
            include(tree(root))
        else:
            raise ValueError(f'Expected source tree {root}')
    for name, record in (('radio', BASE / 'sony-wcn-067-002/result.json'), ('display', BASE / 'display-source-004/result.json'),
                         ('graphics', BASE / 'gpu-source-006/result.json')):
        pins.append({'role': name, 'receipt': str(record), 'pins': json.loads(record.read_text())['pins']})
        include([record])
    reference = BULK / 'refer'
    for name in ('xnu', 'IOStorageFamily', 'IOHIDFamily', 'libplatform', 'libdispatch', 'AvailabilityVersions', 'libpthread', 'corecrypto-2023'):
        root = (reference / name).resolve()
        if root.is_relative_to(TOOLS):
            pins.append(describe_git(root))
            include(git_tree(root))
    include(set().union(*(trace_files(path) for path in args.trace)))
    native = json.loads((CURRENT/'native-final071-001/result.json').read_text())
    for row in native['native_source_patches']:
        include(Path(row[key]) for key in ('source', 'original_source'))
    plan = json.loads((CURRENT/'plan-final071-001/plan.json').read_text())
    for receipt in plan['compile_receipts']:
        include([Path(json.loads(Path(receipt).read_text())['source'])])

    out.mkdir()
    pins_file = out / 'source-pins.json'
    pins_file.write_text(json.dumps(pins, indent=2) + '\n')
    count = pack(out/'PDX071-source.tar.gz', source_files, 'source-files.json', {'source-pins.json': pins_file})
    (out/'source-index.json').write_text(json.dumps(sorted(str(p) for p in source_files))+'\n')
    print(f'Archived {count} source files')


def build_pack(out, tools, replay, traces):
    source_files = {Path(path) for path in json.loads((out/'source-index.json').read_text())}
    used = set().union(*(trace_files(path) for path in traces))
    for file in ('native-final071-001/result.json', 'package-final071-001/report.json'):
        record = json.loads((CURRENT / file).read_text())
        used.update(Path(path) for path in record.get('platform069', record)['inputs'])
    used.update({
        CURRENT/'native-final071-001/native-link.command.json',
        DEVICE/'out/d27-pac-abi-release-20261118-068/boot-pdx234-pac-abi-068.img',
        BASE/'strict-008-kmod-pac/result.json',
    })
    link_inputs = {}
    for folder in (CURRENT/'native-final071-001', ARTIFACTS/'platform067-20261118/native-platform067-full-002'):
        command = folder/'native-link.command.json'
        for path, roles in collect_link_inputs(json.loads(command.read_text())).items():
            used.add(path)
            link_inputs[str(path)] = {'sha256': sha(path), 'bytes': path.stat().st_size, 'roles': roles}
    (out/'native-link-inputs.json').write_text(json.dumps(link_inputs, indent=2)+'\n')
    private_files = {p for p in used if in_layout(p) and valid_name(p) and p.is_file()
                     and not any(part.startswith('replay-for-handoff071-') for part in p.parts)
                     and not p.is_relative_to(out.parent)}
    for path in tuple(private_files):
        if path.is_symlink() and in_layout(path.resolve()):
            private_files.add(path.resolve())
    # Text input receipts remain in the private build pack with their referenced bytes.
    private_files.difference_update(source_files)
    missing = set(map(Path, link_inputs)) - source_files - private_files
    if missing:
        raise ValueError('Linker inputs were excluded from both archives: ' + ', '.join(map(str, sorted(missing))))
    metadata = {
        'host-tools.json': {name: {'path': shutil.which(name), 'version': subprocess.run([name, '--version'],
            capture_output=True, text=True, timeout=10).stdout.splitlines()[:2]}
            for name in ('python3', 'clang', 'ld.lld', 'llvm-ar', 'llvm-mc-23', 'llvm-objcopy', 'mformat', 'dtc', 'git')},
    }
    for name, data in metadata.items():
        (out / name).write_text(json.dumps(data, indent=2) + '\n')
    bundles = {}
    for name in ('sheng', 'UniXNU'):
        target = out / (name + '.bundle')
        subprocess.run(['git', '-C', str(CURRENT/name), 'bundle', 'create', str(target), 'HEAD'],
                       check=True, timeout=90, stdout=subprocess.DEVNULL)
        bundles['git/' + name + '.bundle'] = target
    receipts = ('d27-pac-abi-release-071-001/release.json', 'package-final071-001/report.json',
                'package-final071-001/independent-linux-verification.json', 'windows-final071-001/readback.json',
                'peripheral-host071-001/result.json', 'board-inputs071-001/result.json',
                'replay-for-handoff071-003/package/independent-linux-verification.json')
    extras = {'PDX071-HANDOFF.md': DEVICE/'docs/PDX071-HANDOFF.md', 'host-tools.json': out/'host-tools.json',
              'native-link-inputs.json': out/'native-link-inputs.json',
              'check-handoff.py': tools/'check-handoff.py', 'replay.sh': tools/'replay.sh',
              **{'verification/' + path: CURRENT/path for path in receipts}, **bundles}
    if replay and (replay/'replay.json').is_file():
        extras['verification/replay.json'] = replay/'replay.json'
    q = pack(out/'PDX071-build-handoff.tar.gz', private_files, 'replay-inputs.json', extras)
    lines = [f'{sha(path)}  {path.name}' for path in sorted(out.glob('*.tar.gz'))]
    (out/'SHA256SUMS').write_text('\n'.join(lines) + '\n')
    print(json.dumps({'source_files': len(source_files), 'private_replay_files': q, 'checksums': lines}))


if __name__ == '__main__':
    main()
