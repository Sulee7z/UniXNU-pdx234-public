"""Bounded read-only native IORegistry traversal using qualified compiler fields."""
import struct


def find_service(read, canonical, symbols, target_vtable, limit=2048):
    """Find one exact owned native service; never invoke a guest virtual method."""
    def word(address):
        raw=read(address,8)
        if len(raw)!=8:raise ValueError('Incomplete registry pointer')
        return int.from_bytes(raw,'little')
    def pointer(address):return canonical(word(address))
    plane=pointer(symbols['_gIOServicePlane'])
    child_key=pointer(plane+0x20)
    root=pointer(symbols['__ZL13gRegistryRoot'])
    pending=[root];seen=set();matches=[]
    while pending and len(seen)<limit:
        service=pending.pop()
        if not service or service in seen:continue
        seen.add(service)
        if pointer(service)==target_vtable:matches.append(service)
        dictionary=pointer(service+0x18)
        if not dictionary:continue
        count=int.from_bytes(read(dictionary+0x14,4),'little')
        capacity=int.from_bytes(read(dictionary+0x18,4),'little')
        if not 0<=count<=capacity<=1024:raise ValueError('Unbounded registry dictionary')
        entries=pointer(dictionary+0x20)
        children=0
        for offset in range(0,count*16,4096):
            data=read(entries+offset,min(4096,count*16-offset))
            for key,value in struct.iter_unpack('<QQ',data):
                if canonical(key)==child_key:children=canonical(value)
        if not children:continue
        count=int.from_bytes(read(children+0x14,4),'little')
        capacity=int.from_bytes(read(children+0x18,4),'little')
        if not 0<=count<=capacity<=2048:raise ValueError('Unbounded registry children array')
        array=pointer(children+0x20)
        for offset in range(0,count*8,4096):
            data=read(array+offset,min(4096,count*8-offset))
            pending.extend(canonical(v[0]) for v in struct.iter_unpack('<Q',data))
    if pending:raise ValueError('Registry traversal limit reached')
    if len(matches)!=1:raise ValueError('Require exactly one native service, found '+str(len(matches)))
    return dict(address=matches[0],registry_entries_read=len(seen),read_only=True)
