#!/usr/bin/env python3
"""Verify the completed RELEASE-LTO reference without running another build."""
import argparse
import hashlib
import json
from pathlib import Path


def verify(tree):
    reference = tree / 'build/xnu/fileset-reference/mach.release.bcm2837.unstripped.noctf'
    record = json.loads(reference.with_suffix('.json').read_text())
    inputs = record['inputs']
    if inputs['mode'] != 'lto':
        raise ValueError('Fileset comparison was not built with LTO')
    with reference.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != record['sha256']:
        raise ValueError('Fileset reference differs from its completed-build receipt')
    build = Path(record['build']).resolve()
    if not build.is_relative_to(reference.parent.resolve()):
        raise ValueError('Fileset reference receipt points outside the selected build tree')
    command = json.loads((build / 'lto-command.json').read_text())
    for required in ('BUILD_LTO=1', 'KERNEL_CONFIGS=RELEASE',
                     'ARCH_STRING_FOR_CURRENT_MACHINE_CONFIG=arm64e'):
        if required not in command:
            raise ValueError('Fileset reference command is missing ' + required)
    return {'status': 'verified', 'configuration': 'RELEASE', 'build_lto': 1,
            'reference': str(reference), 'sha256': digest,
            'build': str(build), 'compiler': inputs['compiler'],
            'versions': inputs['versions'], 'builds_started_by_check': 0,
            'runtime_configuration': 'DEVELOPMENT / non-LTO',
            'runtime_qualified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    try:
        report = verify(args.work.resolve() / 'tree')
    except (OSError, ValueError, KeyError) as error:
        args.report.write_text(json.dumps({'status': 'failed', 'error': str(error)}, indent=2) + '\n')
        raise SystemExit(str(error))
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print('Verified RELEASE-LTO reference:', report['sha256'])


if __name__ == '__main__':
    main()
