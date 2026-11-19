"""Read actual D27 UI threads using linked compiler layouts and TTBR1 reads."""
import struct
from d27_user_memory import kernel_pointer_view, read_kernel_memory, read_user_memory


def capture(packet, processes, plan, registers):
    if (plan.get('schema') != 'd27-current-process-layout-v1' or
            plan.get('compiler_qualified') is not True):
        raise ValueError('Require the selected native compiler-qualified layout')
    regs = {key: int(value, 16) if isinstance(value, str) else value
            for key, value in registers.items()}
    tcr = regs['TCR_EL1']
    common = plan['process_layout']
    layout = plan['thread_snapshot_layout']
    saved = plan['saved_state_layout']
    if any(not isinstance(n, int) or not 0 <= n < 65536
           for group in (common, layout, saved) for n in group.values()):
        raise ValueError('Unbounded process/thread field')
    if saved['bytes'] != 304 or saved['count'] != 74:
        raise ValueError('Require actual D27 arm64e saved-state shape')

    def kp(pointer):
        return kernel_pointer_view(pointer, tcr) if pointer else 0

    def read(address, size):
        result = read_kernel_memory(packet, regs, address, size)
        data = bytes.fromhex(result['bytes'])
        if len(data) != size:
            raise ValueError('Kernel range is not fully mapped: ' + hex(address))
        return data

    def word(address, size=8):
        return int.from_bytes(read(address, size), 'little')

    def value(data, offset, width=8):
        if not 0 <= offset < offset + width <= len(data):
            raise ValueError('Field exceeds captured class span')
        return int.from_bytes(data[offset:offset + width], 'little')

    attr_symbol = plan.get('thread_snapshot_native_user_pt_attr')
    if attr_symbol is None:
        raise ValueError('Bind native_user_pt_attr to the selected guest symbol')
    if isinstance(attr_symbol, str):
        attr_symbol = int(attr_symbol, 16)
    attr = kp(word(attr_symbol))
    root_level = word(attr + layout['attr_root'], 4)
    shift = word(attr + layout['attr_shift'])
    user_bits = 64 - (tcr & 63)
    actual_levels = (user_bits - 12 + 8) // 9
    if shift != 12 or root_level != 4 - actual_levels:
        raise ValueError('Actual task page-table geometry differs from stopped TCR')
    def read_user(ttep,address,size):
        return bytes.fromhex(read_user_memory(packet,dict(regs,TTBR0_EL1=ttep),address,size)['bytes'])
    return capture_with_readers(processes,plan,read,kp,read_user,user_bits=user_bits,
        root_level=root_level,consistency='stopped guest')


def capture_with_readers(processes,plan,read,kp,read_user,*,user_bits,root_level,consistency):
    """Use explicit actual kernel/task readers without inventing TCR samples."""
    if plan.get('compiler_qualified') is not True or plan.get('schema')!='d27-current-process-layout-v1':
        raise ValueError('Require the actual linked process layout')
    common=plan['process_layout'];layout=plan['thread_snapshot_layout'];saved=plan['saved_state_layout']
    if (not 25<=user_bits<=48 or root_level!=4-((user_bits-12+8)//9) or
            saved['bytes']!=304 or saved['count']!=74):raise ValueError('Unqualified task page-table/saved-state geometry')
    shift=12
    def word(address,size=8):
        data=read(address,size)
        if len(data)!=size:raise ValueError('Incomplete actual kernel field')
        return int.from_bytes(data,'little')
    def value(data,offset,width=8):
        if not 0<=offset<offset+width<=len(data):raise ValueError('Field exceeds captured class span')
        return int.from_bytes(data[offset:offset+width],'little')
    selected_names = ('SpringBoard', 'backboardd', 'launchd', 'runningboardd',
                      'chronod', 'liveactivitiesd', 'keybagd', 'PreBoard', 'Setup',
                      'lsd', 'containermanager', 'installd', 'cfprefsd', 'datamigrator')
    selected = sorted((p for p in processes if p['name'] in selected_names),
                      key=lambda p: selected_names.index(p['name']))[:16]
    results = []
    for process in selected:
        row = dict(process=process, threads=[], complete=False)
        results.append(row)
        try:
            proc = kp(int(process['address'], 16))
            ro = kp(word(proc + layout['proc_ro']))
            if kp(word(ro + layout['proc_ro_owner'])) != proc:
                raise ValueError('Actual process read-only owner mismatch')
            task = kp(word(ro + layout['proc_ro_task']))
            task_span = max(common['task_region'] + 8, layout['task_thread_count'] + 4,
                            layout['task_threads'] + 16, layout['task_map'] + 8)
            task_raw = read(task, task_span)
            count = value(task_raw, layout['task_thread_count'], 4)
            region = kp(value(task_raw, common['task_region']))
            vm_map = kp(value(task_raw, layout['task_map']))
            pmap = kp(word(vm_map + layout['map_pmap']))
            ttep = word(pmap + layout['pmap_ttep'])
            root_alignment = 1 << (user_bits - (12 + 9 * (3 - root_level)) + 3)
            if not ttep or ttep & (root_alignment - 1) or ttep >= 1 << 48:
                raise ValueError('Actual task root table is unaligned or out of range')
            row.update(task=hex(task), thread_count=count, pmap=hex(pmap), ttep=hex(ttep),
                       cache_slide=word(region + common['region_slide'], 4) if region else None,
                       page_shift=shift, root_level=root_level)
            head = task + layout['task_threads']
            node = kp(value(task_raw, layout['task_threads']))
            seen = set()
            while node and node != head and node not in seen and len(row['threads']) < 64:
                seen.add(node)
                thread = node
                span = max(common['thread_ro'] + 8, common['thread_user_state'] + 8,
                           layout['thread_id'] + 8, layout['thread_state'] + 4,
                           layout['thread_link'] + 8, layout['continuation'] + 8,
                           layout['wait_event'] + 8)
                raw = read(thread, span)
                tro = kp(value(raw, common['thread_ro']))
                tro_raw = read(tro, max(common['ro_owner'], common['ro_task']) + 8)
                if (kp(value(tro_raw, common['ro_owner'])) != thread or
                        kp(value(tro_raw, common['ro_task'])) != task):
                    raise ValueError('Actual thread read-only owner/task mismatch')
                state_raw = value(raw, common['thread_user_state'])
                state = kp(state_raw)
                item = dict(thread=hex(thread), thread_id=value(raw, layout['thread_id']),
                            state=value(raw, layout['thread_state'], 4),
                            continuation_raw=hex(value(raw, layout['continuation'])),
                            wait_event=hex(value(raw, layout['wait_event'])),
                            saved_state_raw=hex(state_raw), saved_state=hex(state))
                row['threads'].append(item)
                node = kp(value(raw, layout['thread_link']))
                if not state:
                    continue
                try:
                    data = read(state, saved['bytes'])
                    flavor, words = struct.unpack_from('<II', data)
                    item['saved_state_header'] = dict(flavor=flavor, count=words)
                    if (flavor, words) != (saved['flavor'], saved['count']):
                        raise ValueError('Actual saved-state header does not match arm64e layout')
                    cpsr = value(data, saved['cpsr'], 4)
                    item['cpsr'] = hex(cpsr)
                    if cpsr & 31:
                        continue
                    item.update(user_pc=hex(value(data, saved['pc'])),
                                user_lr=hex(value(data, saved['lr'])),
                                user_fp=hex(value(data, saved['fp'])),
                                user_sp=hex(value(data, saved['sp'])),
                                user_arguments=[hex(value(data, saved['arguments'] + 8 * i)) for i in range(8)],
                                user_frames=[], user_stack_complete=False)
                    fp, sp = int(item['user_fp'], 16), int(item['user_sp'], 16)
                    for _ in range(16):
                        if fp == 0:
                            item['user_stack_complete'] = True
                            break
                        if not sp <= fp < sp + 65536 or fp & 15:
                            raise ValueError('User frame exceeds bounded aligned stack window')
                        frame_raw = read_user(ttep,fp,16)
                        if len(frame_raw) != 16:
                            raise ValueError('Actual user frame is not resident')
                        next_fp, lr = struct.unpack('<QQ', frame_raw)
                        item['user_frames'].append(dict(fp=hex(fp), lr=hex(lr)))
                        if next_fp and next_fp <= fp:
                            raise ValueError('Non-increasing actual user frame chain')
                        fp = next_fp
                    item['user_stack_complete'] = fp == 0
                except (ValueError, RuntimeError) as error:
                    item['snapshot_error'] = str(error)
            row['complete'] = node == head and len(row['threads']) == count
            if not row['complete']:
                row['limit_or_queue_error'] = 'Queue incomplete, repeated, null or bounded thread limit reached'
        except (ValueError, RuntimeError) as error:
            row['error'] = str(error)
    return dict(native_sha256=plan['native_sha256'], read_only=True,
                source='Actual TTBR1 kernel reads and task-specific native 4K user page tables',
                snapshot_consistency=consistency,user_address_bits=user_bits,
                process_limit=16, threads_per_process_limit=64, frames_per_thread_limit=16,
                stack_window_bytes=65536, selected_processes=len(selected), processes=results,
                limits='Saved user state is the latest boundary, not proof of current wait duration or lock ownership')
