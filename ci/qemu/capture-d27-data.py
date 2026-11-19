"""Save the paused guest's actual sparse Data pages as a new packed seed."""
import hashlib
from pathlib import Path
import struct
import json
import socket
from collections import OrderedDict
from d27_user_memory import read_kernel_memory,kernel_pointer_view
from d27_registry_memory import find_service


def capture(packet,registers,symbols,destination,*,maximum_resident=256*1024**2):
    names={key:int(value,16) if isinstance(value,str) else value for key,value in symbols.items()}
    def read(address,size):
        raw=bytes.fromhex(read_kernel_memory(packet,registers,address,size)['bytes'])
        if len(raw)!=size:raise ValueError('Incomplete stopped Data read')
        return raw
    def canonical(value):return kernel_pointer_view(value,registers['TCR_EL1']) if value else 0
    return capture_with_reader(read,canonical,names,destination,maximum_resident=maximum_resident)


def capture_qmp(registers,symbols,destination,*,maximum_resident=1024*1024**2):
    """Read the already stopped guest through QMP, caching physical64KiB runs."""
    destination=Path(destination)
    run=destination.parent.parent.resolve()
    matches=[]
    for proc in Path('/proc').iterdir():
        if not proc.name.isdecimal():continue
        try:args=(proc/'cmdline').read_bytes().split(b'\0')
        except OSError:continue
        if not args or not args[0].endswith(b'qemu-system-aarch64'):continue
        if not any(('fat:'+str(run/'esp')).encode() in value for value in args):continue
        at=args.index(b'-qmp');matches.append(args[at+1].decode().split('unix:',1)[1].split(',',1)[0])
    if len(matches)!=1:raise ValueError('Require exactly the selected stopped guest for Data capture')
    scratch=destination.with_suffix('.physical')
    if scratch.exists():raise ValueError('Preserve existing physical capture scratch')
    names={key:int(value,16) if isinstance(value,str) else value for key,value in symbols.items()}
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
        sock.settimeout(30);sock.connect(matches[0]);stream=sock.makefile('rwb',buffering=0);stream.readline()
        def qmp(command,**arguments):
            if command not in ('qmp_capabilities','query-status','pmemsave'):raise ValueError('Read-only snapshot commands required')
            stream.write((json.dumps(dict(execute=command,arguments=arguments))+'\n').encode())
            while True:
                line=stream.readline()
                if not line:raise RuntimeError('QMP disconnected during Data capture')
                reply=json.loads(line)
                if 'error' in reply:raise RuntimeError(str(reply['error']))
                if 'return' in reply:return reply['return']
        qmp('qmp_capabilities')
        if qmp('query-status')['running']:raise ValueError('Data capture requires an already stopped guest')
        pages=OrderedDict();physical_mode=False;physical_runs=0
        def packet(request):
            nonlocal physical_mode,physical_runs
            if request=='qqemu.PhyMemMode':return '1' if physical_mode else '0'
            if request.startswith('Qqemu.PhyMemMode:'):physical_mode=request.endswith('1');return 'OK'
            if not physical_mode or not request.startswith('m'):raise ValueError('Physical reads only')
            address,size=(int(x,16) for x in request[1:].split(','))
            if not 0<=address<address+size<=1<<48 or not 0<size<=1024:raise ValueError('Unbounded physical request')
            base=address&~65535
            if base not in pages:
                qmp('pmemsave',val=base,size=65536,filename=str(scratch))
                data=scratch.read_bytes()
                if len(data)!=65536:raise ValueError('Incomplete QMP physical page run')
                pages[base]=data
                physical_runs+=1
                if len(pages)>2048:pages.popitem(last=False)
            else:pages.move_to_end(base)
            if address+size>base+65536:raise ValueError('Read crosses physical capture cache run')
            return pages[base][address-base:address-base+size].hex()
        def read(address,size):
            raw=bytes.fromhex(read_kernel_memory(packet,registers,address,size)['bytes'])
            if len(raw)!=size:raise ValueError('Incomplete stopped Data read')
            return raw
        def canonical(value):return kernel_pointer_view(value,registers['TCR_EL1']) if value else 0
        try:
            result=capture_with_reader(read,canonical,names,destination,maximum_resident=maximum_resident)
            result.update(transport='Actual QMP physical reads through stopped TTBR1',physical_runs=physical_runs)
        finally:scratch.unlink(missing_ok=True)
    return result


def capture_with_reader(read,canonical,names,destination,*,maximum_resident=256*1024**2):
    service=find_service(read,canonical,names,names['__ZTV14NativeRamBlock']+16)
    address=service['address'];raw=read(address,0xd0)
    memory,capacity=struct.unpack_from('<QQ',raw,0x98)
    pages,logical,resident=struct.unpack_from('<QQQ',raw,0xb0)
    if memory or not pages or not 0<logical<=2*1024**3 or logical!=capacity*512 or logical&4095:
        raise ValueError('Require the actual bounded sparse NativeRamBlock Data provider')
    if not 0<resident<=maximum_resident:raise ValueError('Data resident pages exceed the bounded capture')
    table=canonical(pages);pointers=[]
    count=logical//4096
    for at in range(0,count*8,4096):
        pointers.extend(struct.unpack('<'+str(min(4096,count*8-at)//8)+'Q',read(table+at,min(4096,count*8-at))))
    selected=[(i,canonical(pointer)) for i,pointer in enumerate(pointers) if pointer]
    if len(selected)*4096!=resident:raise ValueError('Sparse Data page table/resident accounting differs')
    if not selected or selected[0][0]!=0:raise ValueError('Captured Data must include its actual container header')
    ranges=[]
    for index,pointer in selected:
        if ranges and ranges[-1][0]+ranges[-1][1]==index*4096:ranges[-1][1]+=4096
        else:ranges.append([index*4096,4096])
    if len(ranges)>65536:raise ValueError('Packed Data extent bound exceeded')
    encoded_bytes=32+16*len(ranges)+resident
    destination=Path(destination)
    if destination.exists():raise ValueError('Preserve the existing Data snapshot')
    packed_input=encoded_bytes<=256*1024**2
    if not packed_input:
        destination=destination.with_suffix('.raw')
        if destination.exists():raise ValueError('Preserve the existing raw Data snapshot')
    header=struct.pack('<8sIIQQ',b'DBRDISK1',1,4096,logical,len(ranges))+b''.join(struct.pack('<QQ',*row) for row in ranges)
    digest=hashlib.sha256();zero=bytes(4096);cursor=0
    with destination.open('xb') as output:
        if packed_input:output.write(header)
        else:output.truncate(logical)
        for index,pointer in selected:
            while cursor<index:digest.update(zero);cursor+=1
            page=read(pointer,4096)
            if index==0 and page[32:36]!=b'NXSB':raise ValueError('Actual captured Data lacks its APFS container header')
            if not packed_input:output.seek(index*4096)
            output.write(page);digest.update(page);cursor+=1
        while cursor<count:digest.update(zero);cursor+=1
    with destination.open('rb') as f:packed_sha=hashlib.file_digest(f,'sha256').hexdigest()
    if destination.stat().st_size!=(encoded_bytes if packed_input else logical):raise ValueError('Captured Data size differs from its sparse extent map')
    return dict(path=str(destination),packed_sha256=packed_sha if packed_input else None,
                artifact_sha256=packed_sha,format='DBRDISK1' if packed_input else 'sparse raw',
                current_loader_input_compatible=packed_input,
                raw_sha256=digest.hexdigest(),logical_bytes=logical,
                resident_bytes=resident,extents=len(ranges),native_ram_service=hex(address),
                registry_entries_read=service['registry_entries_read'],read_only=True,guest_stopped=True,
                guest_flushed=False,consistency='Paused actual block image; APFS must check/recover before reuse',
                original_seed_modified=False,device_operations=False)
