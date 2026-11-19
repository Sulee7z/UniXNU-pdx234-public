"""Bounded stopped-guest PM workloop/queue reads, using current native DWARF."""
import bisect
import struct
import json
from pathlib import Path
from d27_user_memory import read_kernel_memory, kernel_pointer_view


def capture(packet, regs, symbols, process_plan):
    names = {k: int(v, 16) if isinstance(v, str) else v for k, v in symbols.items()}
    ordered = sorted((v, k) for k, v in names.items())
    addresses = [v for v, _ in ordered]
    result = dict(read_only=True, snapshot_consistency='stopped guest', globals={}, queues=[])

    def kp(value):
        return kernel_pointer_view(value, regs['TCR_EL1']) if value else 0

    def read(address, size):
        observation = read_kernel_memory(packet, regs, address, size)
        raw = bytes.fromhex(observation['bytes'])
        if len(raw) != size:
            raise ValueError('Incomplete kernel memory at ' + hex(address))
        return raw

    def word(address, size=8):
        return int.from_bytes(read(address, size), 'little')

    def pointer(address):
        return kp(word(address))

    def resolve(value):
        address = kp(value)
        index = bisect.bisect_right(addresses, address) - 1
        return dict(raw=hex(value), address=hex(address), symbol=ordered[index][1],
                    offset=address - addresses[index]) if value and index >= 0 else dict(raw=hex(value))

    for name in ('__ZL13gIOPMWorkLoop', '__ZL17gIOPMRequestQueue', '__ZL15gIOPMReplyQueue',
                 '__ZL14gIOPMWorkQueue', '__ZL20gIOPMCompletionQueue', '__ZL12gIOPMRequest',
                 '__ZL11gRootDomain', '_msgbufp'):
        if name in names:
            result['globals'][name] = hex(pointer(names[name]))
    for name in ('__ZL16gIOPMInitialized', '__ZL21gIOPMBusyRequestCount', '__ZL20gIOPMWorkInvokeCount'):
        if name in names:
            result['globals'][name] = word(names[name], 1 if name.endswith('Initialized') else 4)
    loop = pointer(names['__ZL13gIOPMWorkLoop'])
    if not loop:
        return result
    raw = read(loop, 72)
    gate, chain, thread = (kp(struct.unpack_from('<Q', raw, off)[0]) for off in (16, 24, 48))
    result['workloop'] = dict(address=hex(loop), gate=hex(gate), chain=hex(chain),
                              thread=hex(thread), work_to_do=raw[56], flags=raw[57])
    owner = 0
    if gate:
        lock = read(gate, 40)
        owner = kp(struct.unpack_from('<Q', lock, 24)[0])
        result['workloop'].update(gate_owner=hex(owner), gate_count=struct.unpack_from('<I', lock, 32)[0])

    def kernel_thread(address):
        layout = process_plan['thread_snapshot_layout']
        raw = read(address, layout['thread_id'] + 8)
        value = lambda offset, size=8: int.from_bytes(raw[offset:offset + size], 'little')
        row = dict(address=hex(address), id=value(layout['thread_id']), state=value(layout['thread_state'], 4),
                   continuation=resolve(value(layout['continuation'])), parameter=hex(value(0xe8)),
                   wait_event=hex(value(layout['wait_event'])), kernel_stack=hex(kp(value(0xf0))),
                   saved_kernel_stack=hex(kp(value(0x158))))
        saved = kp(value(0x158))
        if saved:
            state = read(saved, 112)
            fp, lr, sp = struct.unpack_from('<QQQ', state, 80)
            row.update(saved_fp=hex(fp), saved_lr=resolve(lr), saved_sp=hex(sp), frames=[])
            fp = kp(fp)
            seen = set()
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
                next_fp = kp(next_fp)
                if next_fp <= fp or next_fp - fp > 65536:
                    break
                fp = next_fp
        return row

    for name, address in [('thread', thread), ('gate_owner', owner)]:
        if address:
            try:
                result[name] = kernel_thread(address)
            except (ValueError, RuntimeError) as error:
                result[name] = dict(address=hex(address), error=str(error))
    result['event_sources'] = []
    seen = set()
    while chain and chain not in seen and len(result['event_sources']) < 16:
        seen.add(chain)
        raw = read(chain, 72)
        vtable = kp(struct.unpack_from('<Q', raw)[0])
        result['event_sources'].append(dict(address=hex(chain), vtable=resolve(vtable),
            checkForWork=resolve(word(vtable + 16 * 8)), owner=hex(kp(struct.unpack_from('<Q', raw, 24)[0])),
            action=resolve(struct.unpack_from('<Q', raw, 32)[0]), enabled=raw[40],
            flags=struct.unpack_from('<H', raw, 42)[0], workloop=hex(kp(struct.unpack_from('<Q', raw, 48)[0]))))
        chain = kp(struct.unpack_from('<Q', raw, 16)[0])
    for name in ('__ZL17gIOPMRequestQueue', '__ZL15gIOPMReplyQueue'):
        queue = pointer(names[name])
        if not queue:
            continue
        raw = read(queue, 96)
        head = queue + 72
        node = kp(struct.unpack_from('<Q', raw, 72)[0])
        row = dict(name=name, address=hex(queue), workloop=hex(kp(struct.unpack_from('<Q', raw, 48)[0])),
                   enabled=raw[40], requests=[])
        result['queues'].append(row)
        seen = set()
        while node and node != head and node not in seen and len(row['requests']) < 64:
            seen.add(node)
            request = read(node, 136)
            row['requests'].append(dict(address=hex(node), target=hex(kp(struct.unpack_from('<Q', request, 32)[0])),
                type=struct.unpack_from('<I', request, 72)[0], wait=struct.unpack_from('<I', request, 56)[0],
                args=[hex(v) for v in struct.unpack_from('<3Q', request, 112)]))
            node = kp(struct.unpack_from('<Q', request, 16)[0])
        row['complete'] = node == head
    for name in ('_msgbuf', '_msgbufp'):
        try:
            address = pointer(names[name]) if name.endswith('p') else names[name]
            result[name] = dict(address=hex(address), header=read(address, 24).hex())
        except (ValueError, RuntimeError) as error:
            result[name] = dict(error=str(error))
    request=Path('/mnt/e/UniXNU-sheng27-sony-20261113/tmp/qemu-data-capture-request.json')
    if request.is_file():
        selected=json.loads(request.read_text())
        if selected.get('native_sha256')==process_plan['native_sha256']:
            try:
                import importlib.util
                source=Path(__file__).with_name('capture-d27-data.py')
                spec=importlib.util.spec_from_file_location('requested_data_capture',source)
                module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
                result['data_snapshot']=module.capture_qmp(regs,names,selected['destination'])
                Path(selected['destination']).with_suffix('.json').write_text(json.dumps(result['data_snapshot'],indent=2)+'\n')
            except (ValueError,RuntimeError,OSError) as error:result['data_snapshot_error']=str(error)
    return result
