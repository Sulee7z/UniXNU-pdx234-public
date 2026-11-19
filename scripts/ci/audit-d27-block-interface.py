#!/usr/bin/env python3
"""Compare a compiled arm64e block-class PAC layout with the exact D27 original.

This is a read-only static interface check, not a disk-read or runtime test.
The reference object is never linked or executed by this command.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
from types import SimpleNamespace

KERNELCACHE_SHA256 = 'c28f4fc9b83cde00087e81f890c82d566b9e98b5ac228dfecd83afdf34070445'
CLASS_INITIALIZER = 0xfffffff009bbced8
CLASS_INITIALIZER_SHA256 = 'd506eeab6181fd90c10d2d20a89709eb786014727ebd03bfa6d3d1d070afc19f'
ORIGINAL_METACLASS = 0xfffffff00af07060


def object_vtable(data, name):
    """Read symbol relocations and PAC payloads without treating MH_OBJECT as a kernel."""
    if len(data) < 32:
        raise ValueError('Truncated reference object')
    magic, cpu, subtype, kind, count, command_bytes = struct.unpack_from('<6I', data)
    if (magic, cpu, subtype & 0xffffff, kind) != (0xfeedfacf, 0x100000c, 2, 1):
        raise ValueError('Expected an arm64e Mach-O object')
    if 32 + command_bytes > len(data):
        raise ValueError('Truncated load commands')
    sections, symbols_command = [], None
    at = 32
    for _ in range(count):
        command, size = struct.unpack_from('<II', data, at)
        if size < 8 or at + size > 32 + command_bytes:
            raise ValueError('Invalid load command')
        if command == 0x19:
            section_count = struct.unpack_from('<I', data, at + 64)[0]
            if size < 72 + 80 * section_count:
                raise ValueError('Truncated section commands')
            for index in range(section_count):
                offset = at + 72 + index * 80
                va, length, fileoff, _, relocoff, reloccount = struct.unpack_from('<QQ4I', data, offset + 32)
                sections.append((va, length, fileoff, relocoff, reloccount))
        elif command == 2:
            symbols_command = at
        at += size
    if at != 32 + command_bytes or symbols_command is None:
        raise ValueError('Incomplete object load commands or symbol table')
    symoff, symbol_count, stroff, string_bytes = struct.unpack_from('<4I', data, symbols_command + 8)
    if symoff + 16 * symbol_count > len(data) or stroff + string_bytes > len(data):
        raise ValueError('Truncated object symbol table')
    symbols = []
    for index in range(symbol_count):
        strx, symbol_kind, section, _, address = struct.unpack_from('<IBBHQ', data, symoff + 16 * index)
        if strx >= string_bytes:
            raise ValueError('Invalid symbol string index')
        end = data.find(b'\0', stroff + strx, stroff + string_bytes)
        if end < 0:
            raise ValueError('Unterminated symbol')
        symbols.append((data[stroff + strx:end].decode(), symbol_kind, section, address))
    candidates = [row for row in symbols if row[0] == name and row[1] & 0xe == 0xe and not row[1] & 0xe0]
    if len(candidates) != 1:
        raise ValueError('Missing or ambiguous class vtable')
    _, _, section_index, base = candidates[0]
    if not 1 <= section_index <= len(sections):
        raise ValueError('Invalid vtable section')
    va, length, fileoff, relocoff, reloccount = sections[section_index - 1]
    if fileoff + length > len(data) or relocoff + 8 * reloccount > len(data):
        raise ValueError('Truncated vtable section or relocations')
    relocations = {}
    for index in range(reloccount):
        offset, word = struct.unpack_from('<II', data, relocoff + 8 * index)
        if word >> 27 & 1 and word >> 25 & 3 == 3 and word >> 28 in (0, 11):
            symbol_index = word & 0xffffff
            if symbol_index >= len(symbols) or offset + 8 > length:
                raise ValueError('Invalid vtable relocation')
            relocations[va + offset] = (symbols[symbol_index][0], word >> 28)
    end = min([row[3] for row in symbols if row[2] == section_index and
               row[1] & 0xe == 0xe and not row[1] & 0xe0 and row[3] > base] + [va + length])
    if not va <= base < end <= va + length or data[fileoff + base - va:fileoff + base - va + 16] != bytes(16):
        raise ValueError('Invalid vtable extent or RTTI header')
    rows = []
    for site in range(base + 16, end, 8):
        relocation = relocations.get(site)
        if relocation is None:
            break  # The kext ABI may include a trailing non-function null slot.
        target, relocation_type = relocation
        encoded = struct.unpack_from('<Q', data, fileoff + site - va)[0]
        pac = (encoded >> 63, (encoded >> 49) & 3, (encoded >> 32) & 0xffff, (encoded >> 48) & 1)
        if relocation_type != 11 or pac[:2] != (1, 0):
            raise ValueError('Unauthenticated class method')
        rows.append({'slot': len(rows), 'name': target, 'pac': pac})
    if not rows or len(rows) > 1024:
        raise ValueError('Missing or unbounded vtable methods')
    return rows


def audit(kernelcache, reference_object, kit):
    raw = kernelcache.read_bytes()
    if hashlib.sha256(raw).hexdigest() != KERNELCACHE_SHA256:
        raise ValueError('Wrong D27 kernelcache')
    sys.path.insert(0, str(kit.resolve()))
    from kc_image import Image, scan
    from fileset_match import EXEC_SEGMENTS, vtable_slots
    collection = Image(raw)
    storage = Image(raw, collection.entries['com.apple.iokit.IOStorageFamily'][1])
    initializer = storage.read(CLASS_INITIALIZER, 84)
    if hashlib.sha256(initializer).hexdigest() != CLASS_INITIALIZER_SHA256:
        raise ValueError('Original class initializer changed')
    refs = {target for _, target, _ in scan(initializer, CLASS_INITIALIZER)[1]}
    if ORIGINAL_METACLASS not in refs or not any(storage.cstring(target) == 'IOBlockStorageDevice' for target in refs):
        raise ValueError('Class initializer no longer identifies the original metaclass')
    if struct.unpack_from('<I', initializer, 40)[0] != 0x52801203:
        raise ValueError('Original class-size argument is no longer 0x90')
    fixups = collection.fixups()
    ranges = [(s['va'], s['va'] + s['filesize']) for s in collection.segments if s['name'] in EXEC_SEGMENTS]
    side = SimpleNamespace(fixups=fixups, in_exec=lambda address: any(a <= address < b for a, b in ranges))
    tables = []
    for site in fixups:
        base = site - 16
        if not storage.section(base):
            continue
        try:
            if storage.read(base, 16) != bytes(16):
                continue
        except ValueError:
            continue
        slots = vtable_slots(side, base)
        if len(slots) < 20:
            continue
        getter = fixups.get(base + 0x48)
        if getter and {target for _, target, _ in scan(collection.read(getter[0], 16), getter[0])[1]} == {ORIGINAL_METACLASS}:
            tables.append((base, slots))
    if len(tables) != 1:
        raise ValueError('Original class getter does not uniquely identify one complete table')
    base, original = tables[0]
    data = reference_object.read_bytes()
    compiled = object_vtable(data, '__ZTV20IOBlockStorageDevice')
    if len(original) != len(compiled):
        raise ValueError('Original and compiled method counts differ')
    rows = []
    for source, target in zip(compiled, original):
        if tuple(source['pac']) != target[1:]:
            raise ValueError('Method PAC layout differs at slot ' + str(source['slot']))
        rows.append(dict(source, original_target=hex(target[0])))
    return {'kernelcache_sha256': KERNELCACHE_SHA256,
            'reference_object_sha256': hashlib.sha256(data).hexdigest(),
            'class': 'IOBlockStorageDevice', 'original_class_size': 0x90,
            'original_metaclass': hex(ORIGINAL_METACLASS), 'original_vtable': hex(base),
            'method_slots': len(rows), 'pac_layout_matches': True, 'methods': rows,
            'source_object_linked_or_executed': False, 'actual_io_qualified': False,
            'runtime_qualified': False, 'device_operations': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernelcache', required=True, type=Path)
    parser.add_argument('--reference-object', required=True, type=Path)
    parser.add_argument('--kit', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    if args.report.exists():
        parser.error('Refuse to overwrite an existing audit report')
    report = audit(args.kernelcache, args.reference_object, args.kit)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open('x') as stream:
        stream.write(json.dumps(report, indent=2) + '\n')
    print(f"D27: {report['method_slots']} complete block-class PAC slots match; actual I/O remains unqualified")


if __name__ == '__main__':
    main()
