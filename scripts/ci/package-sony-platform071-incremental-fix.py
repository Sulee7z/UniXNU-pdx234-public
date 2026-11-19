#!/usr/bin/env python3
"""Supplement delivery-003 with omitted final and baseline linker inputs."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile

DEVICE = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/f/UniXNU-Port-artifacts')
ARTIFACTS = BASE/'platform069-20261118'
DELIVERY = BASE/'pdx071-handoff-001/delivery-003'
sys.path.insert(0, str(DEVICE/'ci'))
from link_inputs import collect_link_inputs

EXPECTED_MISSING = {'version.o', 'lastkerneldataconst.o', 'lastkernelconstructor.last.o', 'nonlto.o',
                    'libfirehose_kernel.a', 'libcorecrypto_kernel_noasm-namespaced.a', 'recount.o'}


def sha(path):
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def inventory():
    rows = {}
    for filename, index in (('PDX071-source.tar.gz', 'source-files.json'),
                            ('PDX071-build-handoff.tar.gz', 'replay-inputs.json')):
        with tarfile.open(DELIVERY/filename, 'r|gz') as archive:
            for member in archive:
                if member.name == index:
                    rows.update({Path('/'+x['path'].removeprefix('layout/')): x for x in json.load(archive.extractfile(member))})
                    break
            else:
                raise ValueError('Missing archive index: ' + index)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir()
    packed = inventory()
    closure = {}
    commands = []
    for directory in (ARTIFACTS/'native-final071-001', BASE/'platform067-20261118/native-platform067-full-002'):
        command_file = directory/'native-link.command.json'
        commands.append({'path': str(command_file), 'sha256': sha(command_file)})
        for path, roles in collect_link_inputs(json.loads(command_file.read_text())).items():
            closure[str(path)] = {'bytes': path.stat().st_size, 'sha256': sha(path), 'roles': roles}
    missing = [Path(path) for path in closure if Path(path) not in packed]
    if {path.name for path in missing} != EXPECTED_MISSING or len(missing) != 7:
        raise ValueError('Unexpected delivery-003 linker omissions: ' + str(missing))
    additions = {'layout/'+str(path).lstrip('/'): path for path in missing}
    for relative in ('ci/link_inputs.py', 'scripts/ci/rebuild-sony-platform071.py',
                     'scripts/ci/package-sony-platform071-incremental-fix.py', 'tests/test_link_inputs.py'):
        source = DEVICE/relative
        if source in packed:
            raise ValueError('The incremental supplement must not overwrite a frozen manifest file: ' + relative)
        additions['layout/'+str(source).lstrip('/')] = source
    for name in ('check-incremental.py', 'rebuild-incremental.sh'):
        additions[name] = DEVICE/'scripts/handoff'/name
    text = '''# PDX071 incremental link correction

delivery-003 verified the frozen native replay, but omitted six files that the
native linker takes directly outside -filelist and -force_load. This supplement
adds the original four objects and two ordinary archives, plus recount.o from
the inherited baseline filelist. Original files and
private firmware are unchanged. native-link-inputs.json covers the entire
baseline/final linker input union, not only the six reported files.

Extract into the SAME directory as both delivery-003 archives:

```bash
tar -xzf PDX071-incremental-fix.tar.gz -C /path/to/extracted-pdx071
cd /path/to/extracted-pdx071
python3 check-incremental.py
sudo bash rebuild-incremental.sh "$PWD" /path/to/new-results
```

The new command recompiles SonyWifiDma.o, Sm8550AppsSmmu.o, Resources069.o and
BootLog.o with the packaged Clang 24, replaces their actual archive members,
links a NEW native kernel, strictly prelinks and checks PAC, and creates a new
read-back-verified image. Results are in incremental/incremental-result.json.
It does not use --frozen-native. Source paths in debug information can change
the binary SHA-256; a successful source rebuild need not match the frozen IMG.
The original replay.sh remains the byte-identical frozen-native replay.

The six original objects/archives remain private handoff inputs. The public
repository contains the input enumeration and reconstruction scripts only.
'''
    (out/'README-INCREMENTAL.md').write_text(text)
    additions['README-INCREMENTAL.md'] = out/'README-INCREMENTAL.md'
    files = {name: {'bytes': path.stat().st_size, 'sha256': sha(path)} for name, path in additions.items()}
    receipt = {'original_delivery': str(DELIVERY), 'commands': commands,
               'link_inputs': len(closure), 'omitted_original_files': [str(path) for path in missing],
               'hardware_verified': False}
    blobs = {'native-link-inputs.json': closure, 'incremental-files.json': files,
             'supplement-receipt.json': receipt}
    archive_path = out/'PDX071-incremental-fix.tar.gz'
    with tarfile.open(archive_path, 'x:gz', compresslevel=6) as archive:
        for name, path in additions.items():
            info = archive.gettarinfo(str(path), arcname=name)
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ''
            info.mode = 0o755 if path.suffix == '.sh' else 0o644
            with path.open('rb') as file:
                archive.addfile(info, file)
        for name, value in blobs.items():
            data = (json.dumps(value, indent=2)+'\n').encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
            (out/name).write_bytes(data)
    (out/'SHA256SUMS').write_text(sha(archive_path)+'  '+archive_path.name+'\n')
    print(json.dumps({'archive': str(archive_path), 'bytes': archive_path.stat().st_size,
                      'sha256': sha(archive_path), 'link_inputs_verified': len(closure)}))


if __name__ == '__main__':
    main()
