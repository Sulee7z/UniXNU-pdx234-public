#!/usr/bin/env python3
"""Use the official entry probe on a verified D27 fileset, reading native nlist symbols.

LLVM nm rejects the fileset container's segment/section view. This adapter reads
only com.apple.kernel's defined section symbols, then calls the unchanged probe.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

KERNEL_SHA = '098469d880049ad9f1811c3e893874fa56cba72957200fcb4dad756627af0efe'


def commands(data, header=0):
    if header + 32 > len(data) or struct.unpack_from('<I', data, header)[0] != 0xfeedfacf:
        raise ValueError('Invalid Mach-O header')
    count, extent = struct.unpack_from('<II', data, header + 16)
    at, end = header + 32, header + 32 + extent
    if end > len(data):
        raise ValueError('Truncated load commands')
    for _ in range(count):
        if at + 8 > end:
            raise ValueError('Truncated load command')
        kind, size = struct.unpack_from('<II', data, at)
        if size < 8 or at + size > end:
            raise ValueError('Invalid load command size')
        yield kind, at, size
        at += size
    if at != end:
        raise ValueError('Load-command extent mismatch')


def native_symbols(path):
    data = Path(path).read_bytes()
    headers = []
    for kind, at, size in commands(data):
        if kind == 0x80000035:
            name_offset = struct.unpack_from('<I', data, at + 24)[0]
            end = data.find(b'\0', at + name_offset, at + size)
            if not 32 <= name_offset < size or end < 0:
                raise ValueError('Invalid fileset identifier')
            if data[at+name_offset:end] == b'com.apple.kernel':
                headers.append(struct.unpack_from('<Q', data, at + 16)[0])
    if len(headers) != 1:
        raise ValueError('Require one native com.apple.kernel member')
    header = headers[0]
    sections, symtabs = [], []
    for kind, at, size in commands(data, header):
        if kind == 0x19:
            n = struct.unpack_from('<I', data, at + 64)[0]
            if size != 72 + n*80:
                raise ValueError('Invalid segment sections')
            for i in range(n):
                site = at+72+i*80
                address, length = struct.unpack_from('<QQ', data, site+32)
                sections.append((address, length))
        if kind == 2:
            symtabs.append(struct.unpack_from('<4I', data, at+8))
    if len(symtabs) != 1:
        raise ValueError('Require one native symbol table')
    symoff, count, stroff, strbytes = symtabs[0]
    if symoff+count*16 > len(data) or stroff+strbytes > len(data):
        raise ValueError('Truncated native symbol table')
    result, names = {}, {}
    for i in range(count):
        ix, kind, section, _, value = struct.unpack_from('<IBBHQ', data, symoff+i*16)
        if kind & 0xe0 or kind & 0xe != 0xe or not kind & 1:
            continue  # Only defined external N_SECT; local literal names may repeat.
        if ix >= strbytes or not 1 <= section <= len(sections):
            raise ValueError('Invalid defined symbol')
        end = data.find(b'\0', stroff+ix, stroff+strbytes)
        if end < 0:
            raise ValueError('Unterminated symbol')
        name = data[stroff+ix:end].decode()
        if name == '__mh_execute_header':
            continue  # Linker header marker is not a section-backed function/data symbol.
        address, length = sections[section-1]
        if not address <= value <= address+length:
            raise ValueError(f'Symbol {name} falls outside its native section')
        if name in names and names[name] != value:
            raise ValueError(f'Ambiguous native symbol {name}')
        names[name] = value
        result.setdefault(value, name)
    for name in ('_start_first_cpu', '_panic', '_vinfo'):
        if name not in names:
            raise ValueError(f'Missing native {name}')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', required=True, type=Path, help='Private copy patched in place')
    parser.add_argument('--mainline', required=True, type=Path)
    parser.add_argument('--panic-screen', action='store_true')
    parser.add_argument('--reset-delay', type=int, choices=range(1, 31),
                         help='Enable the official post-MMU PSCI reset after 1..30 seconds')
    parser.add_argument('--reset-after', choices=('_arm_vm_init',),
                        help='Move reset to the verified call return in _arm_init')
    args = parser.parse_args()
    if args.reset_after and args.reset_delay != 6:
        parser.error('--reset-after requires --reset-delay 6')
    original = args.kernel.read_bytes()
    if hashlib.sha256(original).hexdigest() != KERNEL_SHA:
        raise ValueError('Require exact pristine strict D27 candidate copy')
    symbols = native_symbols(args.kernel)
    script = args.mainline / 'scripts/patch-xnu-entry-probe.py'
    spec = importlib.util.spec_from_file_location('official_entry_probe', script)
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    probe.kernel_symbols = native_symbols
    sys.argv = [str(script), str(args.kernel)]
    sys.argv += ['--reset-delay', str(args.reset_delay)] if args.reset_delay else ['--no-reset']
    if args.reset_after:
        sys.argv += ['--reset-after', args.reset_after, '--in', '_arm_init', '--occurrence', '1']
    if args.panic_screen:
        sys.argv.append('--panic-screen')
    probe.main()
    patched = args.kernel.read_bytes()
    report = dict(source_kernel_sha256=KERNEL_SHA, patched_kernel_sha256=hashlib.sha256(patched).hexdigest(),
                  official_probe=str(script), official_probe_sha256=hashlib.sha256(script.read_bytes()).hexdigest(),
                  fileset_symbol_adapter='native N_SECT only; no STAB or indirect symbols',
                   native_defined_symbol_addresses=len(symbols), no_reset=args.reset_delay is None,
                   reset_delay=args.reset_delay, timebase_hz=probe.TIMEBASE,
                    reset_checkpoint=('after _arm_vm_init in _arm_init' if args.reset_after else
                                      'post-MMU' if args.reset_delay else None),
                    reset_after=args.reset_after,
                   panic_screen=args.panic_screen,
                  changed_bytes=sum(a!=b for a,b in zip(original,patched)),
                  kernel_crypto_reseal_required=True, guest_executed=False)
    args.kernel.with_suffix('.entry-probe.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':
    main()
