#!/usr/bin/env python3
"""Compile DarwinBoot's production Mach-O parser and check a kernel file.

The parser is extracted from the device's own DarwinBoot checkout, not a copy.
It checks Mach-O structure only. It does NOT validate the loader request, its
boot arguments, firmware allocation or handoff; use check-darwinboot-request.py
and the final-image argument gate too. No guest or SpringBoard is run here.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

PREAMBLE = '''
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef uint8_t UINT8; typedef uint32_t UINT32; typedef uint64_t UINT64;
typedef size_t UINTN; typedef int BOOLEAN; typedef int EFI_STATUS;
#define STATIC static
#define CONST const
#define TRUE 1
#define FALSE 0
#define EFI_SUCCESS 0
#define EFI_UNSUPPORTED 3
#define EFI_LOAD_ERROR 1
#define MAX_UINT64 UINT64_MAX
#define WINDOW_SIZE 0x10000000ULL
#define SIZE_2MB 0x200000ULL
#define EFI_PAGE_MASK 4095
#define MAX_SEGMENTS 64
#define MIN(a,b) ((a)<(b)?(a):(b))
#define MAX(a,b) ((a)>(b)?(a):(b))
#define ZeroMem(p,n) memset(p,0,n)
#define CompareMem(a,b,n) memcmp(a,b,n)
#define EFI_ERROR(s) ((s) != EFI_SUCCESS)
static UINT32 U32(const void *p) { UINT32 v; memcpy(&v,p,4); return v; }
static UINT64 U64(const void *p) { UINT64 v; memcpy(&v,p,8); return v; }
'''


def parser_source(repo):
    source = (repo / 'DarwinBootPkg/Driver/DarwinBoot.c').read_text()
    types = source[source.index('typedef struct {'):source.index('STATIC EFI_HANDLE')]
    parser = source[source.index('STATIC\nEFI_STATUS\nParseKernelHeader'):source.index('STATIC\nBOOLEAN\nAdtNode')]
    return PREAMBLE + types + parser + '\nint check(const UINT8 *p, UINTN n) { KERNEL k; return ParseKernel(p,n,&k); }\n'


def build(repo, work):
    text = parser_source(repo)
    (work / 'parser.c').write_text(text)
    library = work / 'parser.dylib'
    subprocess.run(['clang', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
                    str(work / 'parser.c'), '-o', str(library)], check=True)
    return ctypes.CDLL(str(library)), hashlib.sha256(text.encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--darwinboot', required=True, type=Path)
    parser.add_argument('--kernel', required=True, type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='darwinboot-parser-') as directory:
        library, digest = build(args.darwinboot.resolve(), Path(directory))
        library.check.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        data = args.kernel.read_bytes()
        buffer = ctypes.create_string_buffer(data)
        status = library.check(buffer, len(data))
    report = {'darwinboot_parser_sha256': digest, 'kernel': str(args.kernel),
              'kernel_bytes': len(data), 'kernel_sha256': hashlib.sha256(data).hexdigest(),
              'parse_status': status, 'accepted': status == 0,
              'guest_executed': False, 'springboard_verified': False}
    text = json.dumps(report, indent=2) + '\n'
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text)
    print(text, end='')
    raise SystemExit(0 if status == 0 else 1)


if __name__ == '__main__':
    main()
