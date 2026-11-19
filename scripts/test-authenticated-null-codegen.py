#!/usr/bin/env python3
"""Require actual authenticated-null lowering, not just accepted qualifier spelling."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

DEVICE = Path(__file__).resolve().parents[1]


def body(ir: str, name: str) -> str:
    match = re.search(r'^define[^\n]*@' + re.escape(name) + r'\([^\n]*\)[^\n]*\{\n(.*?)^}', ir, re.M | re.S)
    if not match:
        raise RuntimeError(f'Missing compiled function {name}')
    return match.group(1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir()
    source = DEVICE / 'tests/toolchain/authenticated-null.c'
    report = dict(compiler=str(args.compiler), source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                  target='arm64e-apple-ios27.0', checks=[], passed=True)
    for optimization in ('0', '2'):
        irfile = args.out / f'auth-null-O{optimization}.ll'
        command = [str(args.compiler), '-target', report['target'], '-S', '-emit-llvm',
                   '-O' + optimization, str(source), '-o', str(irfile)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        (args.out / f'compile-O{optimization}.log').write_text(result.stdout + result.stderr)
        if result.returncode:
            report['checks'].append(dict(name=f'O{optimization} compilation', passed=False,
                                         command=command, exit_code=result.returncode))
            report['passed'] = False
            continue
        ir = irfile.read_text()
        store, load, ordinary = body(ir, 'auth_store_zero'), body(ir, 'auth_load'), body(ir, 'ordinary_store_zero')
        checks = {
            'null store signs raw zero': re.search(r'@llvm\.ptrauth\.sign\(i64 (?:noundef )?0, i32 2,', store) is not None,
            'null store has no raw-zero bypass': 'icmp ' not in store,
            'signed-null load authenticates': '@llvm.ptrauth.auth' in load,
            'signed-null load has no raw-zero bypass': 'icmp ' not in load,
            'ordinary null keeps old representation': '@llvm.ptrauth.sign' not in ordinary and 'null' in ordinary,
            'explicit global null is signed': re.search(r'@explicit_global_zero[^\n]*ptrauth \(ptr null,', ir) is not None,
            'implicit global null is signed': re.search(r'@implicit_global_zero[^\n]*ptrauth \(ptr null,', ir) is not None,
        }
        for name, passed in checks.items():
            report['checks'].append(dict(name=f'O{optimization}: {name}', passed=passed))
            report['passed'] &= passed
    invalid = args.out / 'invalid-option.c'
    invalid.write_text('void * __ptrauth(2,1,0,"unimplemented-option") field;\n')
    result = subprocess.run([str(args.compiler), '-target', report['target'], '-fsyntax-only', str(invalid)],
                            capture_output=True, text=True, timeout=30)
    (args.out / 'invalid-option.log').write_text(result.stderr)
    passed = result.returncode != 0 and 'unsupported' in result.stderr
    report['checks'].append(dict(name='unknown authentication option rejected', passed=passed))
    report['passed'] &= passed
    (args.out / 'report.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
