#!/usr/bin/env python3
"""Extract a bounded read-only display PM layout from the linked native object.

This emits an observation plan only. It does not boot a guest, write guest state,
call a power method or establish that a power transition has completed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def attribute(block, name):
    match = re.search(r'\bDW_AT_' + re.escape(name) + r'\s+\(([^\n]*)\)', block)
    if not match:
        raise ValueError('Missing DWARF attribute: ' + name)
    return match.group(1)


def layout(text, class_name, wanted):
    """Accept only direct members of the requested complete class definition."""
    blocks = text.split('\n\n')
    headers = [i for i, block in enumerate(blocks)
               if re.search(r'^0x[0-9a-f]+: DW_TAG_class_type$', block, re.M)
               and 'DW_AT_byte_size' in block
               and attribute(block, 'name') == '"' + class_name + '"']
    if len(headers) != 1:
        raise ValueError('Require one complete DWARF class: ' + class_name)
    header = headers[0]
    extent = int(attribute(blocks[header], 'byte_size'), 0)
    if not 0 < extent <= 4096:
        raise ValueError('Class exceeds the bounded PM observer span')
    members = {}
    for block in blocks[header + 1:]:
        if re.search(r'^0x[0-9a-f]+: DW_TAG_', block, re.M):
            break
        if not re.search(r'^0x[0-9a-f]+:   DW_TAG_member$', block, re.M):
            continue
        name = attribute(block, 'name').strip('"')
        if name not in wanted:
            continue
        if name in members:
            raise ValueError('Ambiguous PM member: ' + name)
        kind = attribute(block, 'type')
        expected_type, width = wanted[name]
        if not kind.endswith('"' + expected_type + '"'):
            raise ValueError('Unexpected PM member type: ' + name + ': ' + kind)
        if 'DW_AT_data_bit_offset' in block:
            bit_offset = int(attribute(block, 'data_bit_offset'), 0)
            bit_size = int(attribute(block, 'bit_size'), 0)
            if bit_size != 1:
                raise ValueError('Only single-bit PM flags are selected')
            row = dict(offset=bit_offset // 8, bytes=1,
                       bit=bit_offset % 8, bit_size=bit_size)
        else:
            row = dict(offset=int(attribute(block, 'data_member_location'), 0), bytes=width)
        if not 0 <= row['offset'] < row['offset'] + row['bytes'] <= extent:
            raise ValueError('PM member is outside its class')
        row['type'] = expected_type
        members[name] = row
    if members.keys() != wanted.keys():
        raise ValueError('Incomplete PM layout: ' + repr(sorted(wanted.keys() - members.keys())))
    return dict(bytes=extent, fields=members)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path, required=True, help='Verified native build directory')
    parser.add_argument('--out', type=Path, required=True, help='New diagnostic output directory')
    parser.add_argument('--dwarfdump', default='llvm-dwarfdump')
    args = parser.parse_args()
    native = args.native.resolve()
    result = json.loads((native / 'result.json').read_text())
    image = native / 'native.macho'
    if (digest(image) != result['native_sha256'] or
            not result['pac_authentication_retained'] or
            result['auth_instruction_patches'] is not False):
        raise ValueError('Require the exact completed PAC native build')
    command = json.loads((native / 'native-link.command.json').read_text())
    filelist = Path(command[command.index('-filelist') + 1])
    objects = [Path(line) for line in filelist.read_text().splitlines()]
    matches = [path for path in objects if path.name == 'IOServicePM.cpo']
    if len(matches) != 1:
        raise ValueError('Require the actual unique linked IOServicePM object')
    obj = matches[0]
    receipt_path = Path(str(obj) + '.json')
    receipt = json.loads(receipt_path.read_text())
    source = Path(receipt['source'])
    if (receipt['exit'] or digest(obj) != receipt['sha256'] or
            digest(source) != receipt['source_sha256']):
        raise ValueError('Linked PM object/source provenance differs')
    args.out.mkdir(parents=True, exist_ok=False)
    service_members = {'pwrMgt': ('IOServicePM *', 8), 'initialized': ('bool', 1)}
    pm_members = {
        'MachineState': ('uint32_t', 4),
        'HeadNotePowerState': ('IOPMPowerStateIndex', 8),
        'InitialPowerChange': ('unsigned int', 4),
        'ParentsKnowState': ('unsigned int', 4),
        'DriverCallBusy': ('unsigned int', 4),
        'DesiredPowerState': ('IOPMPowerStateIndex', 8),
        'NumberOfPowerStates': ('IOPMPowerStateIndex', 8),
        'PowerStates': ('IOPMPSEntry *', 8),
        'ControllingDriver': ('IOService *', 8),
        'CurrentPowerState': ('IOPMPowerStateIndex', 8),
        'ParentsCurrentPowerFlags': ('IOPMPowerFlags', 8),
        'MaxPowerState': ('IOPMPowerStateIndex', 8),
    }
    layouts = {}
    for name, wanted in [('IOService', service_members), ('IOServicePM', pm_members)]:
        argv = [args.dwarfdump, '--debug-info', '--name=' + name, '--show-children', str(obj)]
        done = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=45)
        dump = args.out / (name + '.dwarf.txt')
        dump.write_text(done.stdout)
        layouts[name] = layout(done.stdout, name, wanted)
        layouts[name]['dwarf_sha256'] = digest(dump)
        layouts[name]['command'] = argv
    plan = dict(
        schema='d27-qemu-display-pm-layout-v1',
        native=str(image), native_sha256=digest(image),
        source=str(source), source_sha256=digest(source),
        object=str(obj), object_sha256=digest(obj),
        compile_receipt=str(receipt_path), compile_receipt_sha256=digest(receipt_path),
        compiler_qualified=True, layouts=layouts,
        observation_steps=[
            'Read native_legacy_object from the actual selected guest symbol table',
            'Read bounded IOService fields using actual TTBR1 translation',
            'Canonicalize the real pwrMgt pointer using the stopped TCR_EL1',
            'Read the bounded IOServicePM span and decode these exact fields',
            'Read root-domain/power-plane membership separately if the state requires it',
        ],
        read_only=True, runtime_observed=False,
        guest_register_or_memory_writes=False, device_operations=False,
        limits='Object layout alone does not establish power-plane membership, asynchronous progress or a desktop',
    )
    (args.out / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    print(json.dumps(dict(plan=str(args.out / 'plan.json'), layouts=layouts,
                          read_only=True, runtime_observed=False), indent=2))


if __name__ == '__main__':
    main()
