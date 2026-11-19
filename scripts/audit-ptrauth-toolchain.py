#!/usr/bin/env python3
"""Compile PAC qualifier fixtures without weakening their authentication semantics."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

COMPILERS = ['/root/unixnu-toolchain/llvm/bin/clang', '/usr/bin/clang']
CASES = {
    'control-three-arguments': '__ptrauth(2, 1, 0x2345)',
    'required-authenticated-null': '__ptrauth(2, 1, 0x2345, "authenticates-null-values")',
    'invalid-option': '__ptrauth(2, 1, 0x2345, "not-a-valid-option")',
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--compiler', action='append')
    args = parser.parse_args()
    args.out.mkdir()
    report = dict(target='arm64e-apple-ios27.0', qualifier_removed=False,
                  null_authentication_weakened=False, hardware_verified=False, compilers=[])
    for index, compiler in enumerate(args.compiler or COMPILERS):
        version = subprocess.check_output([compiler, '--version'], text=True)
        row = dict(compiler=compiler, version=version, cases=[])
        for label, qualifier in CASES.items():
            source = ('struct S { void * ' + qualifier + ' p; };\n'
                      'void *load(struct S *s) { return s->p; }\n'
                      'void store_zero(struct S *s) { s->p = (void *)0; }\n')
            stem = args.out / f'compiler-{index}-{label}'
            stem.with_suffix('.c').write_text(source)
            command = [compiler, '--target=arm64e-apple-ios27.0', '-S', '-emit-llvm',
                       '-O1', '-x', 'c', '-', '-o', str(stem.with_suffix('.ll'))]
            result = subprocess.run(command, input=source, text=True, capture_output=True, timeout=30)
            stem.with_suffix('.stderr.log').write_text(result.stderr)
            row['cases'].append(dict(name=label, command=command, exit_code=result.returncode,
                                     source_sha256=hashlib.sha256(source.encode()).hexdigest(),
                                     stderr=result.stderr))
        row['required_qualifier_compiles'] = row['cases'][1]['exit_code'] == 0
        row['invalid_option_rejected'] = row['cases'][2]['exit_code'] != 0
        report['compilers'].append(row)
    (args.out / 'report.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    # Parsing success alone would still require inspecting authenticated-null code generation.
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
