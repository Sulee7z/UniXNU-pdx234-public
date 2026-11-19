#!/usr/bin/env python3
"""Extract hash-bound Sony LXS/GENI reference sources without archive paths escaping."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--index', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--board-only', action='store_true')
    parser.add_argument('--registers-only', action='store_true')
    args = parser.parse_args()
    expected = 'cc91361a2aaec52b94ef2f9da29fb489e02fd8383bb12535446fc6945bf659da'
    if args.archive.stat().st_size != 1275418198 or sha(args.archive) != expected:
        raise ValueError('Require the recorded Sony 67.2.A.3.141 source archive')
    wanted = set()
    for row in json.loads(args.index.read_text()):
        name = row['path']
        if row['type'] != '0':
            continue
        if args.registers_only:
            if '/Library/I2CLib/' in name and PurePosixPath(name).name in ('HALqupv3SeHwio.h','HALqupv3CommonHwio.h'):
                wanted.add(name)
            continue
        if args.board_only:
            if (PurePosixPath(name).name in ('gcc-kalama.c', 'pinctrl-kalama.c', 'i2c_fw_load.c', 'i2c_fw_load.h') or
                    ('SocPkg/Kailua/Settings/I2C/' in name and name.endswith(('.c', '.h')))):
                wanted.add(name)
            continue
        if ('/msm/lxs_ts/' in name or
                PurePosixPath(name).name in ('i2c-qcom-geni.c', 'i2c-msm-geni.c', 'qcom-geni-se.c', 'qcom-geni-se.h') or
                ('Kailua/Settings/I2C/' in name and name.endswith(('.c', '.h'))) or
                ('kalama' in name.lower() and name.endswith(('.dts', '.dtsi')) and
                 any(word in name.lower() for word in ('sony', 'pdx', 'yodo', 'touch')))):
            wanted.add(name)
    if not args.board_only and not args.registers_only and not any('/msm/lxs_ts/lxs_ts.h' in name for name in wanted):
        raise ValueError('Source index lacks the actual LXS module')
    args.out.mkdir(parents=True, exist_ok=False)
    record = {'archive': str(args.archive), 'archive_sha256': expected,
              'reference_only': True, 'not_current_android_kernel_source': True, 'files': {}}
    with tarfile.open(args.archive, 'r|bz2') as archive:
        for member in archive:
            if member.name not in wanted:
                continue
            relative = PurePosixPath(member.name)
            if relative.is_absolute() or '..' in relative.parts or not member.isfile() or member.size > 8 << 20:
                raise ValueError('Invalid source member: ' + member.name)
            destination = args.out.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            data = archive.extractfile(member).read()
            destination.write_bytes(data)
            record['files'][member.name] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
            wanted.remove(member.name)
            print(member.name, len(data), flush=True)
            if not wanted:
                break
    if wanted:
        raise ValueError('Missing indexed members: ' + repr(sorted(wanted)))
    record['completed'] = True
    (args.out / 'provenance.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Extracted', len(record['files']), 'reference sources', flush=True)


if __name__ == '__main__':
    main()
