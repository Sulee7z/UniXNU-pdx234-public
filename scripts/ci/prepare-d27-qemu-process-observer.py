#!/usr/bin/env python3
"""Derive current D27 process/thread observer fields from actual linked DWARF."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def parse(text):
    entries, stack = {}, []
    for block in re.split(r'\n\s*\n', text):
        tag = re.search(r'^0x([0-9a-f]+):( *)DW_TAG_(\w+)', block, re.M)
        if not tag:
            continue
        offset, indent, kind = int(tag[1], 16), len(tag[2]), tag[3]
        fields = {k: v for k, v in re.findall(r'DW_AT_(\w+)\s+\(([^\n]*)\)', block)}
        node = dict(kind=kind, attributes=fields, children=[])
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if stack:
            stack[-1][1]['children'].append(node)
        stack.append((indent, node))
        if offset in entries:
            raise ValueError('Ambiguous DWARF entry')
        entries[offset] = node
    return entries


def structure(entries, name):
    matches = [n for n in entries.values()
               if n['kind'] in ('structure_type', 'class_type')
               and n['attributes'].get('name') == '"' + name + '"'
               and 'byte_size' in n['attributes']]
    if len(matches) != 1:
        raise ValueError('Require one complete structure: ' + name)
    return matches[0]


def member(entries, node, name):
    results = []
    for entry in node['children']:
        if entry['kind'] != 'member':
            continue
        fields = entry['attributes']
        if 'data_member_location' not in fields:
            continue
        offset = int(fields['data_member_location'], 0)
        if fields.get('name') == '"' + name + '"':
            results.append(offset)
        elif 'name' not in fields:
            ref = re.match(r'(0x[0-9a-f]+) ', fields.get('type', ''))
            if ref and int(ref[1], 16) in entries:
                child = entries[int(ref[1], 16)]
                try:
                    results.append(offset + member(entries, child, name))
                except KeyError:
                    pass
    if not results:
        raise KeyError(name)
    if len(results) != 1:
        raise ValueError('Ambiguous anonymous member: ' + name)
    extent = int(node['attributes']['byte_size'], 0)
    if not 0 <= results[0] < extent < 65536:
        raise ValueError('Unbounded member: ' + name)
    return results[0]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--native', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--dwarfdump', default='llvm-dwarfdump')
    a = p.parse_args()
    native = a.native.resolve()
    record = json.loads((native / 'result.json').read_text())
    image = native / 'native.macho'
    if (sha(image) != record['native_sha256'] or
            record['auth_instruction_patches'] is not False or
            record['pac_authentication_retained'] is not True):
        raise ValueError('Require the actual completed native/PAC build')
    command = json.loads((native / 'native-link.command.json').read_text())
    objects = [Path(v) for v in Path(command[command.index('-filelist') + 1]).read_text().splitlines()]
    a.out.mkdir(parents=True, exist_ok=False)
    types, inputs = {}, []
    queries = {
        'kern_proc.o': ['proc', 'proc_ro'],
        'task.o': ['task', '_vm_map', 'pmap', 'vm_shared_region'],
        'thread.o': ['thread', 'thread_ro', 'machine_thread', 'arm_saved_state', 'arm_saved_state64'],
        'pmap.o': ['page_table_attr'],
    }
    for basename, wanted in queries.items():
        matches = [v for v in objects if v.name == basename]
        if len(matches) != 1:
            raise ValueError('Require unique linked object: ' + basename)
        obj = matches[0]
        receipt_path = Path(str(obj) + '.json')
        receipt = json.loads(receipt_path.read_text())
        if (receipt['exit'] or sha(obj) != receipt['sha256'] or
                sha(receipt['source']) != receipt['source_sha256']):
            raise ValueError('Object/source provenance differs: ' + basename)
        inputs.append(dict(object=str(obj), sha256=sha(obj),
                           receipt=str(receipt_path), receipt_sha256=sha(receipt_path)))
        for name in wanted:
            argv = [a.dwarfdump, '--debug-info', '--name=' + name, '--show-children', str(obj)]
            done = subprocess.run(argv, capture_output=True, text=True, timeout=40, check=True)
            dump = a.out / (name + '.dwarf.txt')
            dump.write_text(done.stdout)
            entries = parse(done.stdout)
            types[name] = entries, structure(entries, name)

    def field(kind, name):
        entries, node = types[kind]
        return member(entries, node, name)

    common = dict(thread_ro=field('thread', 't_tro'), ro_owner=field('thread_ro', 'tro_owner'),
                  ro_proc=field('thread_ro', 'tro_proc'), ro_task=field('thread_ro', 'tro_task'),
                  task_region=field('task', 'shared_region'), region_slide=field('vm_shared_region', 'sr_slide'),
                  pid=field('proc', 'p_pid'), comm=field('proc', 'p_comm'),
                  thread_user_state=field('thread', 'machine') + field('machine_thread', 'upcb'))
    threads = dict(proc_ro=field('proc', 'p_proc_ro'), proc_ro_owner=field('proc_ro', 'pr_proc'),
                   proc_ro_task=field('proc_ro', 'pr_task'), task_threads=field('task', 'threads'),
                   task_thread_count=field('task', 'thread_count'), task_map=field('task', 'map'),
                   map_pmap=field('_vm_map', 'pmap'), pmap_ttep=field('pmap', 'ttep'),
                   thread_id=field('thread', 'thread_id'), thread_state=field('thread', 'state'),
                   thread_link=field('thread', 'task_threads'), continuation=field('thread', 'continuation'),
                   wait_event=field('thread', 'wait_event'),
                   attr_root=field('page_table_attr', 'pta_root_level'),
                   attr_shift=field('page_table_attr', 'pta_page_shift'))
    saved_bytes = int(types['arm_saved_state'][1]['attributes']['byte_size'], 0)
    reg_bytes = int(types['arm_saved_state64'][1]['attributes']['byte_size'], 0)
    reg_base = field('arm_saved_state', 'uss')
    if (saved_bytes, reg_bytes, reg_base) != (304, 296, 8):
        raise ValueError('Unsupported actual arm64e saved-state shape')
    saved = dict(bytes=saved_bytes, flavor=21, count=reg_bytes // 4,
                 arguments=reg_base + field('arm_saved_state64', 'x'),
                 fp=reg_base + field('arm_saved_state64', 'fp'),
                 lr=reg_base + field('arm_saved_state64', 'lr'),
                 sp=reg_base + field('arm_saved_state64', 'sp'),
                 pc=reg_base + field('arm_saved_state64', 'pc'),
                 cpsr=reg_base + field('arm_saved_state64', 'cpsr'))
    plan = dict(schema='d27-current-process-layout-v1', native=str(image), native_sha256=sha(image),
                compiler_qualified=True, object_inputs=inputs,
                process_layout=common, thread_snapshot_layout=threads, saved_state_layout=saved,
                process_list_layout=dict(next=field('proc', 'p_list'), pid=common['pid'],
                                         name=common['comm'], state=field('proc', 'p_stat')),
                thread_snapshot_user_pt_attr_symbol='_native_user_pt_attr',
                read_only=True, runtime_observed=False, device_operations=False,
                limits='Bind native_user_pt_attr to the selected prelinked symbol before thread capture; never reuse old kernel offsets or the boot page-table root')
    (a.out / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    print(json.dumps({k: v for k, v in plan.items() if k != 'object_inputs'}, indent=2))


if __name__ == '__main__':
    main()
