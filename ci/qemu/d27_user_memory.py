"""Read-only TTBR0 adaptation of the pinned QEMU observer's 4K table walker."""


def kernel_pointer_view(pointer, tcr):
    bits = 64-((tcr >> 16) & 63)
    if (tcr >> 30) & 3 != 2 or not 25 <= bits <= 48:
        raise ValueError('Need actual 4K TTBR1 configuration')
    mask = (1 << bits)-1
    return (pointer & mask) | (((1 << 64)-1) ^ mask)


def read_user_memory(packet, registers, address, size):
    return _read_memory(packet, registers, address, size, kernel=False)


def read_kernel_memory(packet, registers, address, size):
    """Read TTBR1 mappings even when the stopped CPU is executing at EL0."""
    return _read_memory(packet, registers, address, size, kernel=True)


def read_native_pages(physical,root,address,size,*,bits,first_level,kernel=False):
    """Read explicit native4K tables; no architectural register sample is implied."""
    if not 25<=bits<=48 or first_level!=4-((bits-12+8)//9):
        raise ValueError('Invalid explicit native page-table geometry')
    root_bits=bits-(12+9*(3-first_level));alignment=1<<(root_bits+3)
    if not 0<root<1<<48 or root&(alignment-1):raise ValueError('Invalid explicit native root')
    low=(1<<64)-(1<<bits) if kernel else 1
    high=1<<64 if kernel else 1<<bits
    if not low<=address<address+size<=high or not 0<size<=4096:raise ValueError('Unbounded explicit native address')
    def raw(pa,count):
        data=physical(pa,count)
        if len(data)!=count:raise ValueError('Incomplete explicit physical read')
        return data
    output=b''
    while len(output)<size:
        va=address+len(output);table=root
        for level in range(first_level,4):
            shift=12+9*(3-level);index_mask=(1<<root_bits)-1 if level==first_level else 511
            descriptor=int.from_bytes(raw(table+((va>>shift)&index_mask)*8,8),'little')
            if not descriptor&1:raise ValueError('Actual task page is not resident')
            if level<3 and descriptor&3==3:table=descriptor&0x0000fffffffff000;continue
            if (level==3 and descriptor&3!=3) or (level<3 and (level==0 or descriptor&3!=1)):
                raise ValueError('Invalid explicit native translation leaf')
            pa=(descriptor&0x0000fffffffff000&~((1<<shift)-1))|(va&((1<<shift)-1));break
        count=min(size-len(output),4096-(va&4095));output+=raw(pa,count)
    return output


def _read_memory(packet, registers, address, size, *, kernel):
    tcr = registers['TCR_EL1']
    if kernel:
        bits = 64-((tcr >> 16) & 63)
        if (tcr >> 30) & 3 != 2 or not 25 <= bits <= 48:
            raise ValueError('Need actual 4K TTBR1 configuration')
        if not (1 << 64)-(1 << bits) <= address < address+size <= 1 << 64 or not 0 < size <= 4096:
            raise ValueError('Not a bounded canonical kernel VA')
    else:
        bits = 64-(tcr & 63)
        if (tcr >> 14) & 3 or not 25 <= bits <= 48:
            raise ValueError('Need actual 4K TTBR0 configuration')
        if not 0 < address < address+size <= 1 << bits or not 0 < size <= 4096:
            raise ValueError('Not a bounded untagged user VA')
    levels = (bits-12+8)//9
    first_level = 4-levels
    root_bits = bits-(12+9*(3-first_level))
    # T0SZ=26 uses a 256-entry, 2KiB-aligned initial table. Do not round
    # that TTBR down to 4KiB and silently select a different address space.
    root_alignment = 1 << (root_bits+3)
    ttbr = 'TTBR1_EL1' if kernel else 'TTBR0_EL1'
    root = registers[ttbr] & 0x0000ffffffffffff & ~(root_alignment-1)
    if not root:
        raise ValueError(f'{ttbr} is not initialized')
    capture = dict(address=hex(address), bytes='', translations=[],
                   root_table=hex(root), root_alignment=root_alignment,
                   source=f'QEMU physical debugger reads through actual {ttbr[:-4]}', read_only=True)

    def physical(pa, count):
        # QEMU8.2's GDB stub rejects a read larger than half PacketSize because
        # its reply is hexadecimal. Keep requests below the supported limit,
        # including a full4K page or a message-ring page.
        output = b''
        while len(output) < count:
            address = pa + len(output)
            length = min(count - len(output), 1024)
            raw = packet(f'm{address:x},{length:x}')
            if raw.startswith('E') or len(raw) != length*2:
                raise RuntimeError(f'Physical read unavailable at {address:#x}: {raw}')
            output += bytes.fromhex(raw)
        return output

    def translate(va):
        table, walk = root, []
        for level in range(first_level, 4):
            shift = 12+9*(3-level)
            index_mask = (1 << root_bits)-1 if level == first_level else 511
            slot = table+((va >> shift) & index_mask)*8
            descriptor = int.from_bytes(physical(slot, 8), 'little')
            walk.append(dict(level=level, descriptor_pa=hex(slot), descriptor=hex(descriptor)))
            if not descriptor & 1:
                return dict(virtual_address=hex(va), mapped=False, walk=walk)
            if level < 3 and descriptor & 3 == 3:
                table = descriptor & 0x0000fffffffff000
                continue
            if ((level == 3 and descriptor & 3 != 3) or
                    (level < 3 and (level == 0 or descriptor & 3 != 1))):
                raise RuntimeError('Invalid user translation leaf')
            pa = (descriptor & 0x0000fffffffff000 & ~((1 << shift)-1)) | (va & ((1 << shift)-1))
            return dict(virtual_address=hex(va), physical_address=hex(pa), mapped=True,
                        leaf_level=level, leaf_bytes=1 << shift, ap=(descriptor >> 6) & 3,
                        accessed=bool(descriptor & (1 << 10)), walk=walk)
        raise RuntimeError('No hardware translation leaf')

    old_mode = packet('qqemu.PhyMemMode')
    if old_mode not in ('0', '1') or packet('Qqemu.PhyMemMode:1') != 'OK':
        raise RuntimeError('QEMU physical debugger reads unavailable')
    try:
        while len(capture['bytes'])//2 < size:
            offset = len(capture['bytes'])//2
            va = address+offset
            resolved = translate(va)
            capture['translations'].append(resolved)
            if not resolved['mapped']:
                capture['read_error'] = 'Actual user page is not mapped'
                break
            length = min(size-offset, 4096-(va & 4095))
            capture['bytes'] += physical(int(resolved['physical_address'], 16), length).hex()
    finally:
        if packet('Qqemu.PhyMemMode:'+old_mode) != 'OK':
            raise RuntimeError('Cannot restore debugger memory mode')
    return capture
