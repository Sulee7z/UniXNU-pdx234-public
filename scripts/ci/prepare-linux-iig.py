#!/usr/bin/env python3
"""Build a private iig-port with the shared authenticated member-cast fallback."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess

DEVICE = Path(__file__).resolve().parents[2]
CORE = Path('/mnt/e/UniXNU-sheng27-sony-20261113/sources/UniXNU')
SOURCE = Path('/root/unixnu-build/toolchain-work/iig-port')
REVISION = 'ea6d147d668ca15d490da638012243fcd705f30d'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(command, log, cwd):
    with log.open('x') as stream:
        result = subprocess.run(list(map(str, command)), cwd=cwd, stdout=stream, stderr=subprocess.STDOUT, timeout=120)
    if result.returncode:
        raise RuntimeError(log.read_text()[-5000:])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    original = subprocess.check_output(['git', '-C', str(SOURCE), 'show', REVISION + ':iig.cpp'])
    (out / 'iig.cpp').write_bytes(original)
    patches = [CORE / 'scripts/linux/iig-port-darwin-target.patch', DEVICE / 'patches/host/iig-port-ptrauth-cast.patch']
    for index, patch in enumerate(patches):
        run(['patch', '-p1', '--batch', '--forward', '--fuzz=0', '-i', patch], out / f'patch-{index}.log', out)
    config = Path('/usr/lib/llvm-23/bin/llvm-config')
    compiler = Path('/usr/lib/llvm-23/bin/clang++')
    flags = shlex.split(subprocess.check_output([str(config), '--cxxflags', '--ldflags'], text=True))
    libdir = subprocess.check_output([str(config), '--libdir'], text=True).strip()
    resource = subprocess.check_output([str(compiler), '-print-resource-dir'], text=True).strip()
    binary = out / 'iig'
    command = [str(compiler), *flags, '-std=c++17', '-DUNIXNU_CLANG_RESOURCE_DIR="' + resource + '"',
               str(out / 'iig.cpp'), '-Wl,-rpath,' + libdir, '-lclang', '-ldl', '-o', str(binary)]
    run(command, out / 'build.log', out)
    version = subprocess.check_output([str(binary), '--version'], text=True).strip()
    receipt = dict(built=True, source_revision=REVISION, source_sha256=hashlib.sha256(original).hexdigest(),
                   patched_source_sha256=sha(out / 'iig.cpp'), command=command, binary=str(binary), binary_sha256=sha(binary),
                   version=version, patches={str(p): sha(p) for p in patches},
                   upstream='Allenwdk/UniXNU@f9248435b415440e8bb1619f48fe56013f7b273f/scripts/linux/iig-port-ptrauth-cast.patch',
                   authenticated_cast=True, raw_signature_stripping=False, original_toolchain_modified=False,
                   device_operations=False)
    (out / 'result.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, indent=2), flush=True)


if __name__ == '__main__':
    main()
