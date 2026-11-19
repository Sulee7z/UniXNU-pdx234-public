"""Bounded reads of the actual current mount-list mutex owner and saved stack.

Offsets come from current linked thread.o DWARF and matching generated assym.
No lock, register, thread or memory state is changed.
"""
import bisect
import struct


def capture_thread(read,symbols,process_layout,owner,*,va_bits,consistency):
    mask=(1<<va_bits)-1
    def kp(value):return (value&mask)|(((1<<64)-1)^mask) if value else 0
    def word(address,size=8):return int.from_bytes(read(address,size),'little')
    raw_thread=read(owner,1536)
    if len(raw_thread)!=1536:raise ValueError('Incomplete current thread span')
    result=dict(owner=hex(owner),thread_id=int.from_bytes(raw_thread[1520:1528],'little'),
        ctid=int.from_bytes(raw_thread[1528:1532],'little'),
        thread_state=int.from_bytes(raw_thread[648:652],'little'),
        wait_event=hex(int.from_bytes(raw_thread[32:40],'little')),
        continuation_raw=hex(int.from_bytes(raw_thread[224:232],'little')),
        read_only=True,snapshot_consistency=consistency)
    tro=kp(int.from_bytes(raw_thread[process_layout['thread_ro']:process_layout['thread_ro']+8],'little'))
    if kp(word(tro+process_layout['ro_owner']))!=owner:raise ValueError('Current thread read-only owner mismatch')
    proc=kp(word(tro+process_layout['ro_proc']))
    if proc:result['process']=dict(address=hex(proc),pid=word(proc+process_layout['pid'],4),
        name=read(proc+process_layout['comm'],17).split(b'\0')[0].decode('utf-8','replace'))
    stack=kp(int.from_bytes(raw_thread[240:248],'little'));context=kp(int.from_bytes(raw_thread[344:352],'little'))
    result.update(kernel_stack=hex(stack),saved_kernel_context=hex(context),kernel_frames=[])
    if not stack or not stack<=context<context+104<=stack+16384:
        result['stack_error']='Saved context outside actual16KiB kernel stack';return result
    saved=read(context,104);fp,lr,sp=struct.unpack_from('<3Q',saved,80)
    fp=kp(fp);sp=kp(sp)
    result.update(saved_lr_raw=hex(lr),saved_sp=hex(sp),saved_fp=hex(fp),
                  callee_saved={f'x{19+i}':hex(v) for i,v in enumerate(struct.unpack_from('<10Q',saved,0))})
    seen=set()
    while fp and fp not in seen and len(result['kernel_frames'])<24:
        if not stack<=fp<fp+16<=stack+16384 or fp&15:
            result['stack_error']='Kernel frame exceeds actual bounded stack';break
        seen.add(fp);nxt,ret=struct.unpack('<QQ',read(fp,16))
        result['kernel_frames'].append(dict(fp=hex(fp),lr_raw=hex(ret),lr=hex(kp(ret))))
        nxt=kp(nxt)
        if nxt and nxt<=fp:
            result['stack_error']='Non-increasing kernel frame';break
        fp=nxt
    names={}
    for name,value in symbols.items():names.setdefault(int(value,0) if isinstance(value,str) else value,[]).append(name)
    addresses=sorted(names)
    for item in result['kernel_frames']:
        address=int(item['lr'],16);index=bisect.bisect_right(addresses,address)-1
        if index>=0 and address-addresses[index]<65536:
            item.update(nearest_native_names=names[addresses[index]],offset=address-addresses[index])
    result['limits']='Latest saved kernel context; live samples are non-atomic and do not prove duration, deadlock or current PC'
    return result


def capture(read, symbols, process_layout, *, va_bits, consistency):
    mask=(1<<va_bits)-1
    def kp(value):return (value&mask)|(((1<<64)-1)^mask) if value else 0
    def symbol(name):
        value=symbols[name]
        return int(value,0) if isinstance(value,str) else value
    def word(address,size=8):
        data=read(address,size)
        if len(data)!=size:raise ValueError('Incomplete mount-lock capture')
        return int.from_bytes(data,'little')
    address=symbol('_mnt_list_mtx_lock');raw=read(address,16)
    state=int.from_bytes(raw[8:12],'little');ctid=state&0x0fffffff
    result=dict(address=hex(address),raw=raw.hex(),owner_ctid=ctid,state=hex(state),
                read_only=True,snapshot_consistency=consistency,owner_checked=False)
    if not ctid:return result
    if ctid>0xfffff:raise ValueError('Unexpected current mutex compact thread ID')
    nonce=word(symbol('_ctid_nonce'),4)&0xfffff
    cid=ctid^nonce
    if cid==0xfffff:cid=nonce
    slab=(cid|1023).bit_length()-10
    if not 0<=slab<12:raise ValueError('Compact ID slab outside bound')
    table=symbol('_ctid_table');array=kp(word(table+slab*8))
    if not array:raise ValueError('Mutex owner slab absent')
    owner=kp(word(array+cid*8))
    if not owner:raise ValueError('Mutex owner table entry absent')
    # Verified current thread.o layout: ctid follows thread_id at1520.
    raw_thread=read(owner,1536)
    if int.from_bytes(raw_thread[1528:1532],'little')!=ctid:
        result.update(owner=hex(owner),owner_changed_during_capture=True);return result
    result.update(capture_thread(read,symbols,process_layout,owner,va_bits=va_bits,consistency=consistency))
    result['owner_checked']=True
    state_after=word(symbol('_mnt_list_mtx_lock')+8,4)
    result['owner_unchanged_across_capture']=(state_after&0x0fffffff)==ctid
    return result
    result.update(owner=hex(owner),owner_checked=True,thread_id=int.from_bytes(raw_thread[1520:1528],'little'),
                  thread_state=int.from_bytes(raw_thread[648:652],'little'),
                  wait_event=hex(int.from_bytes(raw_thread[32:40],'little')),
                  continuation_raw=hex(int.from_bytes(raw_thread[224:232],'little')))
    tro=kp(int.from_bytes(raw_thread[process_layout['thread_ro']:process_layout['thread_ro']+8],'little'))
    if kp(word(tro+process_layout['ro_owner']))!=owner:raise ValueError('Mutex owner thread read-only owner mismatch')
    proc=kp(word(tro+process_layout['ro_proc']))
    if proc:result['process']=dict(address=hex(proc),pid=word(proc+process_layout['pid'],4),
        name=read(proc+process_layout['comm'],17).split(b'\0')[0].decode('utf-8','replace'))
    stack=kp(int.from_bytes(raw_thread[240:248],'little'));context=kp(int.from_bytes(raw_thread[344:352],'little'))
    result.update(kernel_stack=hex(stack),saved_kernel_context=hex(context),kernel_frames=[])
    if not stack or not stack<=context<context+104<=stack+16384:
        result['stack_error']='Saved context outside actual16KiB kernel stack';return result
    saved=read(context,104);fp,lr,sp=struct.unpack_from('<3Q',saved,80)
    fp=kp(fp);sp=kp(sp)
    result.update(saved_lr_raw=hex(lr),saved_sp=hex(sp),saved_fp=hex(fp),
                  callee_saved={f'x{19+i}':hex(v) for i,v in enumerate(struct.unpack_from('<10Q',saved,0))})
    seen=set()
    while fp and fp not in seen and len(result['kernel_frames'])<24:
        if not stack<=fp<fp+16<=stack+16384 or fp&15:
            result['stack_error']='Kernel frame exceeds actual bounded stack';break
        seen.add(fp);nxt,ret=struct.unpack('<QQ',read(fp,16))
        result['kernel_frames'].append(dict(fp=hex(fp),lr_raw=hex(ret),lr=hex(kp(ret))))
        nxt=kp(nxt)
        if nxt and nxt<=fp:
            result['stack_error']='Non-increasing kernel frame';break
        fp=nxt
    # Exact-address nearest names are retained with offsets and never used as
    # function extents. Large offsets remain explicitly unresolved for kexts.
    names={}
    for name,value in symbols.items():names.setdefault(int(value,0) if isinstance(value,str) else value,[]).append(name)
    addresses=sorted(names)
    for item in result['kernel_frames']:
        address=int(item['lr'],16);index=bisect.bisect_right(addresses,address)-1
        if index>=0 and address-addresses[index]<65536:
            item.update(nearest_native_names=names[addresses[index]],offset=address-addresses[index])
    state_after=word(symbol('_mnt_list_mtx_lock')+8,4)
    result['owner_unchanged_across_capture']=(state_after&0x0fffffff)==ctid
    result['limits']='Latest saved kernel context; live samples are non-atomic and do not prove duration, deadlock or current PC'
    return result
