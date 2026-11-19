#!/usr/bin/env python3
"""Test whether the original D27 Sandbox components close a strict prelink."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys

DEVICE = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--kernelcache', type=Path, required=True)
    parser.add_argument('--roots', nargs='+', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    prelink = load('native_prelink', DEVICE/'ci/XnuPrelink/native_prelink.py')
    native = args.native.read_bytes()
    original = args.kernelcache.read_bytes()
    report = prelink.plan(native, original, args.roots, 0)
    (args.out/'plan.json').write_text(json.dumps(report, indent=2, default=str)+'\n')
    print(json.dumps(dict(components=len(report.get('components', [])),
                          kernel_interfaces=len(report.get('kernel_interfaces', [])),
                          codeless=len(report.get('codeless_components', [])),
                          missing=len(report.get('missing', {}) or {}),
                          stubbed=len(report.get('stubbed', {}) or {})), indent=2))


if __name__ == '__main__':
    main()
