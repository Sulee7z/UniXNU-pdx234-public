#!/usr/bin/env python3
"""Build the repaired compiler's real PAC instructions for execution in a UEFI guest."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

SOURCE = Path('/mnt/g/UniXNU-Port/ports/UniXNU-pdx234/tests/toolchain/authenticated-null.c')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir()
    obj, elf, binary = [args.out / ('fixture.' + suffix) for suffix in ('o', 'elf', 'bin')]
    compile_command = [str(args.compiler), '-target', 'aarch64-none-elf', '-march=armv8.3-a',
                       '-Xclang', '-fptrauth-intrinsics', '-DQEMU_RUNTIME=1', '-O2', '-ffreestanding',
                       '-fno-builtin', '-fno-stack-protector', '-fno-unwind-tables',
                       '-fno-asynchronous-unwind-tables', '-c', str(SOURCE), '-o', str(obj)]
    subprocess.run(compile_command, check=True)
    linker = args.out / 'fixture.ld'
    linker.write_text('ENTRY(auth_store_zero)\nSECTIONS { . = 0; .text : { *(.text .text.*) } '
                      '.rodata : { *(.rodata .rodata.*) } /DISCARD/ : { *(.eh_frame .comment .note*) } }\n')
    subprocess.run(['ld.lld', '-T', str(linker), str(obj), '-o', str(elf)], check=True)
    symbols = subprocess.check_output(['llvm-nm', '--defined-only', str(elf)], text=True)
    required = ['auth_store_zero', 'auth_load', 'auth_store_pointer', 'auth_copy',
                'ordinary_to_auth', 'auth_to_ordinary', 'ordinary_store_zero', 'ordinary_load']
    offsets = {}
    for line in symbols.splitlines():
        match = re.fullmatch(r'([0-9a-fA-F]+)\s+\w\s+(\S+)', line)
        if match and match[2] in required:
            offsets[match[2]] = int(match[1], 16)
    if set(offsets) != set(required):
        raise RuntimeError('Compiled runtime exports are missing')
    subprocess.run(['llvm-objcopy', '-O', 'binary', str(elf), str(binary)], check=True)
    header = '\n'.join(f'#define OFFSET_{name.upper()} 0x{offset:x}' for name, offset in sorted(offsets.items())) + '\n'
    (args.out / 'BlobOffsets.h').write_text(header)
    (args.out / 'Blob.S').write_text('.text\n.p2align 12\n.globl AuthNullBlob\nAuthNullBlob:\n  .incbin "' + str(binary) + '"\n')
    (args.out / 'blob.json').write_text(json.dumps(dict(source_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        compiler=str(args.compiler), command=compile_command, exports=offsets,
        bytes=binary.stat().st_size, binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest()), indent=2))
    print(json.dumps(offsets, indent=2))


if __name__ == '__main__':
    main()
