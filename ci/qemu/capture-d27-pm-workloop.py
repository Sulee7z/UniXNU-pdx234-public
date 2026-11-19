#!/usr/bin/env python3
"""One bounded read-only live capture of current D27 PM queues and work loop."""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import socket
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    run = a.run.resolve()
    names = json.loads((run / 'symbols.json').read_text())
    inputs = json.loads((run / 'inputs.json').read_text())
    matches = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdecimal():
            continue
        try:
            args = (proc / 'cmdline').read_bytes().split(b'\0')
        except OSError:
            continue
        if (args and args[0].endswith(b'qemu-system-aarch64') and
                any(('fat:' + str(run / 'esp')).encode() in v for v in args)):
            index = args.index(b'-qmp')
            target = args[index + 1].decode().split('unix:', 1)[1].split(',', 1)[0]
            matches.append((int(proc.name), target))
    if len(matches) != 1:
        raise ValueError('Require the explicitly selected live guest')
    a.out.mkdir(parents=True, exist_ok=False)
    result = dict(qemu_pid=matches[0][0], read_only=True, guest_stopped=False,
                  snapshot_consistency='live/non-atomic', started=time.time(),
                  native_sha256=inputs['native_sha256'], guest_memory_writes=False)
    scratch = a.out / 'physical.bin'
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(20)
        sock.connect(matches[0][1])
        stream = sock.makefile('rwb', buffering=0)
        stream.readline()

        def qmp(command, **arguments):
            if command not in ('qmp_capabilities', 'query-status', 'human-monitor-command', 'pmemsave'):
                raise ValueError('Read-only QMP command required')
            if command == 'human-monitor-command' and arguments != {'command-line': 'info registers -a'}:
                raise ValueError('Only a register report is permitted')
            stream.write((json.dumps(dict(execute=command, arguments=arguments)) + '\n').encode())
            while True:
                response = json.loads(stream.readline())
                if 'error' in response:
                    raise RuntimeError(str(response['error']))
                if 'return' in response:
                    return response['return']

        qmp('qmp_capabilities')
        result['status'] = qmp('query-status')
        registers = qmp('human-monitor-command', **{'command-line': 'info registers -a'})
        (a.out / 'registers.txt').write_text(registers)

        def physical(address, size):
            if not 0 <= address < address + size <= 1 << 48 or not 0 < size <= 4096:
                raise ValueError('Bounded physical read required')
            qmp('pmemsave', val=address, size=size, filename=str(scratch))
            raw = scratch.read_bytes()
            if len(raw) != size:
                raise ValueError('Incomplete physical read')
            return raw

        uart = (run / 'observation/gdb-uart.log').read_text()
        loaded = re.search(r'kernel +va 0x([0-9A-Fa-f]+) +pa 0x([0-9A-Fa-f]+)', uart)
        if not loaded:
            raise ValueError('Actual loader mapping unavailable')
        kernel_va, kernel_pa = (int(v, 16) for v in loaded.groups())

        def boot(address, size):
            return physical(kernel_pa + address - kernel_va, size)

        def symbol(name):
            return int(names[name], 16)

        table_root = int.from_bytes(boot(symbol('_cpu_ttep'), 8), 'little')
        attr = int.from_bytes(boot(symbol('_native_pt_attr'), 8), 'little')
        geometry = boot(attr, 120)
        level = int.from_bytes(geometry[64:68], 'little')
        mask = int.from_bytes(geometry[112:120], 'little')
        bits = mask.bit_length()
        if (int.from_bytes(geometry[104:112], 'little') != 12 or
                not 25 <= bits <= 48 or mask != (1 << bits) - 1 or not 0 <= level <= 2):
            raise ValueError('Unqualified native kernel geometry')
        align = 1 << (bits - (12 + 9 * (3 - level)) + 3)
        table_root &= 0x0000ffffffffffff & ~(align - 1)
        result['kernel_geometry'] = dict(root=hex(table_root), first_level=level, bits=bits,
                                         source='Live cpu_ttep/native_pt_attr, not a TCR register sample')

        def canonical(pointer):
            return (pointer & mask) | ((1 << 64) - 1 ^ mask) if pointer else 0

        def read(address, size):
            if not (1 << 64) - (1 << bits) <= address < address + size <= 1 << 64 or not 0 < size <= 4096:
                raise ValueError('Bounded canonical kernel read required')
            output = b''
            while len(output) < size:
                va, table = address + len(output), table_root
                for lev in range(level, 4):
                    shift = 12 + 9 * (3 - lev)
                    index_mask = (1 << (bits - shift)) - 1 if lev == level else 511
                    descriptor = int.from_bytes(physical(table + ((va >> shift) & index_mask) * 8, 8), 'little')
                    if not descriptor & 1:
                        raise ValueError('Actual kernel page is not mapped')
                    if lev < 3 and descriptor & 3 == 3:
                        table = descriptor & 0x0000fffffffff000
                        continue
                    if lev == 3 and descriptor & 3 != 3 or lev < 3 and descriptor & 3 != 1:
                        raise ValueError('Invalid actual page-table leaf')
                    pa = (descriptor & 0x0000fffffffff000 & ~((1 << shift) - 1)) | (va & ((1 << shift) - 1))
                    break
                count = min(size - len(output), 4096 - (va & 4095))
                output += physical(pa, count)
            return output

        def word(address, size=8):
            return int.from_bytes(read(address, size), 'little')

        def pointer(address):
            return canonical(word(address))

        result['globals'] = {}
        for name in ('__ZL13gIOPMWorkLoop', '__ZL17gIOPMRequestQueue', '__ZL15gIOPMReplyQueue',
                     '__ZL14gIOPMWorkQueue', '__ZL20gIOPMCompletionQueue', '__ZL12gIOPMRequest',
                     '__ZL11gRootDomain', '_msgbufp'):
            if name in names:
                result['globals'][name] = hex(pointer(symbol(name)))
        pm_loop = pointer(symbol('__ZL13gIOPMWorkLoop'))
        raw = read(pm_loop, 72)
        gate, chain, thread = (canonical(struct.unpack_from('<Q', raw, o)[0]) for o in (16, 24, 48))
        result['workloop'] = dict(address=hex(pm_loop), gate=hex(gate), event_chain=hex(chain),
                                  work_thread=hex(thread), work_to_do=raw[56], flags=raw[57])
        if gate:
            lock = read(gate, 40)
            result['workloop']['gate_owner'] = hex(canonical(struct.unpack_from('<Q', lock, 24)[0]))
            result['workloop']['gate_count'] = struct.unpack_from('<I', lock, 32)[0]
        thread_layout = json.loads((BASE / 'tmp/qemu-process-observer-002/plan.json').read_text())
        common, tl = thread_layout['process_layout'], thread_layout['thread_snapshot_layout']
        symbols_by_address = sorted((int(v, 16), k) for k, v in names.items())
        addresses = [v for v, _ in symbols_by_address]

        def resolve(raw):
            address = canonical(raw)
            at = bisect.bisect_right(addresses, address) - 1
            return dict(raw=hex(raw), address=hex(address), symbol=symbols_by_address[at][1],
                        offset=address - addresses[at]) if at >= 0 else dict(raw=hex(raw))

        def thread_snapshot(address):
            data = read(address, tl['thread_id'] + 8)
            value = lambda offset, size=8: int.from_bytes(data[offset:offset + size], 'little')
            row = dict(address=hex(address), id=value(tl['thread_id']), state=value(tl['thread_state'], 4),
                       wait_event=hex(value(tl['wait_event'])), continuation=resolve(value(tl['continuation'])),
                       parameter=hex(value(0xe8)), kernel_stack=hex(canonical(value(0xf0))))
            # These fields are independently compiler-qualified in the current
            # machine_thread and arm_kernel_saved_state diagnostic dumps.
            kstack = canonical(value(0x158))
            row['kernel_saved_state'] = hex(kstack)
            if kstack:
                saved = read(kstack, 112)
                fp, lr, sp = struct.unpack_from('<QQQ', saved, 80)
                row.update(saved_fp=hex(fp), saved_lr=resolve(lr), saved_sp=hex(sp), frames=[])
                seen = set()
                fp = canonical(fp)
                while fp and fp not in seen and len(row['frames']) < 24:
                    seen.add(fp)
                    try:
                        next_fp, frame_lr = struct.unpack('<QQ', read(fp, 16))
                    except (ValueError, RuntimeError) as error:
                        row['stack_error'] = str(error)
                        break
                    row['frames'].append(dict(fp=hex(fp), lr=resolve(frame_lr)))
                    if not next_fp:
                        break
                    next_fp = canonical(next_fp)
                    if next_fp <= fp or next_fp - fp > 65536:
                        break
                    fp = next_fp
            return row

        for label, address in [('work_thread', thread), ('gate_owner', canonical(int(result['workloop'].get('gate_owner', '0x0'), 16)))]:
            if address:
                try:
                    result[label] = thread_snapshot(address)
                except (ValueError, RuntimeError) as error:
                    result[label] = dict(error=str(error), address=hex(address))
        result['queues'] = []
        for name in ('__ZL17gIOPMRequestQueue', '__ZL15gIOPMReplyQueue'):
            queue = pointer(symbol(name))
            raw = read(queue, 96)
            head = queue + 72
            node = canonical(struct.unpack_from('<Q', raw, 72)[0])
            row = dict(name=name, address=hex(queue), workloop=hex(canonical(struct.unpack_from('<Q', raw, 48)[0])),
                       enabled=raw[40], flags=struct.unpack_from('<H', raw, 42)[0], requests=[])
            result['queues'].append(row)
            seen = set()
            while node and node != head and node not in seen and len(row['requests']) < 64:
                seen.add(node)
                request = read(node, 136)
                row['requests'].append(dict(address=hex(node), target=hex(canonical(struct.unpack_from('<Q', request, 32)[0])),
                    type=struct.unpack_from('<I', request, 72)[0], work_wait=struct.unpack_from('<I', request, 56)[0],
                    args=[hex(v) for v in struct.unpack_from('<3Q', request, 112)]))
                node = canonical(struct.unpack_from('<Q', request, 16)[0])
            row['complete'] = node == head
        msgbuf = pointer(symbol('_msgbufp'))
        result['msgbuf_header'] = read(msgbuf, 24).hex()
        result['finished'] = time.time()
    scratch.unlink(missing_ok=True)
    (a.out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k not in ('globals',)}, indent=2))


if __name__ == '__main__':
    main()
