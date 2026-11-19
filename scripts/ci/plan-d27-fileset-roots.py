#!/usr/bin/env python3
"""Test whether extra original D27 components close a strict fileset prelink."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

DEVICE = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tool', type=Path, required=True, help='Pinned emit_prelink.py snapshot')
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--kernelcache', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--root', action='append', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    command = [sys.executable, '-B', str(args.tool),
               '--kernel', str(args.native), '--prelinked', str(args.kernelcache), '--slide=0']
    for root in args.root:
        command += ['--root', root]
    command += ['--fileset-reference', str(args.reference), '--output', str(args.out/'kernel.macho')]
    (args.out/'command.json').write_text(json.dumps(command, indent=2)+'\n')
    with (args.out/'prelink.log').open('x') as log:
        done = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    report_path = args.out/'kernel.json'
    report = json.loads(report_path.read_text()) if report_path.is_file() else {}
    print(json.dumps(dict(exit_code=done.returncode,
                          components=len(report.get('components', []) or []),
                          missing=len(report.get('missing', {}) or {}),
                          stubbed=len(report.get('stubbed', {}) or {}),
                          candidate=(args.out/'kernel.macho').is_file()), indent=2))


if __name__ == '__main__':
    main()
