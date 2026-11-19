"""Bounded NGPUADD2 merge and append-only version2 trust module support."""
import hashlib
from pathlib import PurePosixPath
import struct
import uuid
import zlib

MAX_FILES=1024
MAX_TOTAL=128*1024**2
MAX_FILE=64*1024**2


def valid_name(name):
    if not isinstance(name,str):raise ValueError('Addon path must be a string')
    encoded=name.encode('utf-8');parts=PurePosixPath(name).parts
    # The actual kern_exec consumer has a160-byte terminated relative name and
    # a192-byte full path. Reject '..' anywhere exactly as that consumer does.
    if (not encoded or len(encoded)+1>160 or '\0' in name or '\\' in name or '..' in name or
            name.startswith('/') or not parts or any(part in ('.','..') for part in name.split('/')) or
            str(PurePosixPath(name))!=name):raise ValueError('Unsafe or unrepresentable addon path')
    return encoded


def decode(raw):
    if not 24<=len(raw)<=MAX_TOTAL:raise ValueError('Invalid addon length')
    magic,count,reserved,total=struct.unpack_from('<8sIIQ',raw)
    if magic!=b'NGPUADD2' or reserved or total!=len(raw) or not 0<count<=MAX_FILES:
        raise ValueError('Invalid addon header')
    result={};at=24;expanded=0
    for _ in range(count):
        if at+24>len(raw):raise ValueError('Truncated addon entry')
        plen,mode,length,packed=struct.unpack_from('<IIQQ',raw,at);at+=24
        if not 2<=plen<=160 or length>MAX_FILE or not packed or packed>MAX_TOTAL or mode&~0o777:
            raise ValueError('Invalid addon entry bounds/mode')
        name_padded=(plen+7)&-8;packed_padded=(packed+7)&-8
        if at+name_padded+packed_padded>len(raw):raise ValueError('Truncated addon content')
        encoded=raw[at:at+plen]
        if encoded[-1] or b'\0' in encoded[:-1]:raise ValueError('Invalid addon string terminator')
        try:name=encoded[:-1].decode('utf-8')
        except UnicodeDecodeError as error:raise ValueError('Invalid addon UTF8 path') from error
        valid_name(name)
        if name in result:raise ValueError('Duplicate addon path')
        at+=name_padded;decompressor=zlib.decompressobj()
        try:data=decompressor.decompress(raw[at:at+packed],length+1)
        except zlib.error as error:raise ValueError('Invalid compressed addon entry') from error
        if len(data)!=length or not decompressor.eof or decompressor.unconsumed_tail or decompressor.unused_data:
            raise ValueError('Addon expansion size/stream differs')
        expanded+=length
        if expanded>MAX_TOTAL:raise ValueError('Addon expanded size exceeds bound')
        at+=packed_padded;result[name]=dict(data=data,mode=mode)
    if at!=len(raw):raise ValueError('Trailing addon bytes')
    return result


def encode(files):
    if not 0<len(files)<=MAX_FILES:raise ValueError('Invalid addon member count')
    payload=bytearray();expanded=0
    for name,row in files.items():
        name=valid_name(name)+b'\0';data=row['data'];mode=row['mode']
        if not isinstance(data,bytes) or len(data)>MAX_FILE or not isinstance(mode,int) or mode&~0o777:
            raise ValueError('Invalid addon file bytes/mode')
        expanded+=len(data)
        if expanded>MAX_TOTAL:raise ValueError('Addon expansion exceeds bound')
        packed=zlib.compress(data,9);payload+=struct.pack('<IIQQ',len(name),mode,len(data),len(packed))
        payload+=name+bytes(-len(name)%8)+packed+bytes(-len(packed)%8)
        if len(payload)+24>MAX_TOTAL:raise ValueError('Encoded addon exceeds bound')
    return struct.pack('<8sIIQ',b'NGPUADD2',len(files),0,24+len(payload))+payload


def trust_modules(data):
    if len(data)<4:raise ValueError('Truncated trust header')
    count=struct.unpack_from('<I',data)[0]
    if not 0<count<32 or 4+4*count>=len(data):raise ValueError('Invalid trust module count')
    offsets=list(struct.unpack_from('<'+'I'*count,data,4))+[len(data)]
    if offsets[0]!=4+4*count or any(a>=b for a,b in zip(offsets,offsets[1:])):raise ValueError('Invalid trust module offsets')
    result=[]
    for a,b in zip(offsets,offsets[1:]):
        module=data[a:b]
        if len(module)<24 or struct.unpack_from('<I',module)[0]!=2 or len(module)!=24+24*struct.unpack_from('<I',module,20)[0]:
            raise ValueError('Invalid version2 trust module')
        hashes=[module[at:at+20] for at in range(24,len(module),24)]
        if hashes!=sorted(set(hashes)):raise ValueError('Unsorted or duplicate trust module identities')
        result.append(module)
    return result


def append_trust(data,cdhashes):
    modules=trust_modules(data);identities=[]
    for value in cdhashes:
        try:raw=bytes.fromhex(value)
        except (ValueError,TypeError) as error:raise ValueError('Invalid cdhash') from error
        if len(raw)!=20:raise ValueError('Trust identity must be20 bytes')
        identities.append(raw)
    identities=sorted(set(identities))
    if not identities:return data
    if len(modules)>=31:raise ValueError('Trust module capacity exceeded')
    identity=uuid.UUID(bytes=hashlib.sha256(b''.join(identities)).digest()[:16],version=5)
    module=struct.pack('<I16sI',2,identity.bytes,len(identities))+b''.join(value+b'\x02\0\0\0' for value in identities)
    modules.append(module);at=4+4*len(modules);offsets=[]
    for module in modules:offsets.append(at);at+=len(module)
    return struct.pack('<I'+'I'*len(offsets),len(offsets),*offsets)+b''.join(modules)
