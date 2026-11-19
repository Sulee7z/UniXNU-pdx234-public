"""Verify069 signatures including a daemon's embedded __info_plist special slot."""
import hashlib
from pathlib import Path
import plistlib
import struct


def inspect(path):
    path=Path(path);bundle=path.is_dir()
    target=path/plistlib.loads((path/'Info.plist').read_bytes())['CFBundleExecutable'] if bundle else path
    data=target.read_bytes()
    if len(data)<32 or struct.unpack_from('<I',data)[0]!=0xfeedfacf:raise ValueError('Expected thin Mach-O')
    at=32;signature=None;external={}
    for _ in range(struct.unpack_from('<I',data,16)[0]):
        kind,size=struct.unpack_from('<II',data,at)
        if size<8 or at+size>len(data):raise ValueError('Truncated load command')
        if kind==0x1d:
            off,length=struct.unpack_from('<II',data,at+8)
            if signature is not None or off+length>len(data):raise ValueError('Bad signature range')
            signature=data[off:off+length]
        if kind==0x19:
            for i in range(struct.unpack_from('<I',data,at+64)[0]):
                section=at+72+80*i
                if section+80>at+size:raise ValueError('Truncated Mach-O section')
                name=data[section:section+16].rstrip(b'\0');segment=data[section+16:section+32].rstrip(b'\0')
                if (segment,name)==(b'__TEXT',b'__info_plist'):
                    length,offset=struct.unpack_from('<QI',data,section+40)
                    if offset+length>len(data) or 1 in external:raise ValueError('Bad embedded Info.plist')
                    external[1]=data[offset:offset+length]
        at+=size
    if signature is None:raise ValueError('No Mach-O code signature')
    magic,length,count=struct.unpack_from('>III',signature)
    if magic!=0xfade0cc0 or length>len(signature) or 12+count*8>length:raise ValueError('Bad signature superblob')
    blobs={}
    for i in range(count):
        kind,offset=struct.unpack_from('>II',signature,12+i*8)
        if offset+8>length or kind in blobs:raise ValueError('Duplicate or truncated signature blob')
        _,size=struct.unpack_from('>II',signature,offset)
        if size<8 or offset+size>length:raise ValueError('Bad signature blob size')
        blobs[kind]=signature[offset:offset+size]
    cd=blobs[0]
    if struct.unpack_from('>I',cd)[0]!=0xfade0c02:raise ValueError('Invalid CodeDirectory')
    hash_offset,_,special,slots,limit=struct.unpack_from('>IIIII',cd,16)
    hash_size,hash_type,_,page=struct.unpack_from('>BBBB',cd,36)
    if (hash_size,hash_type,page)!=(32,2,12) or slots!=(limit+4095)//4096 or limit>len(data):
        raise ValueError('CodeDirectory hash/page ABI differs')
    if hash_offset<special*32 or hash_offset+slots*32>len(cd):raise ValueError('Bad CodeDirectory hash table')
    for i in range(slots):
        if cd[hash_offset+32*i:hash_offset+32*(i+1)]!=hashlib.sha256(data[i*4096:min(limit,(i+1)*4096)]).digest():
            raise ValueError('Code page digest mismatch')
    if bundle:
        external[1]=(path/'Info.plist').read_bytes();external[3]=(path/'_CodeSignature/CodeResources').read_bytes()
    for slot in range(1,special+1):
        wanted=cd[hash_offset-slot*32:hash_offset-(slot-1)*32];content=external.get(slot,blobs.get(slot))
        if content is None:
            if any(wanted):raise ValueError('Unverified external signature slot '+str(slot))
        elif hashlib.sha256(content).digest()!=wanted:raise ValueError('Special signature slot mismatch '+str(slot))
    if bundle:
        resources=plistlib.loads(external[3])
        for relative,entry in resources.get('files2',{}).items():
            source=path/relative
            if 'hash2' in entry:
                if hashlib.sha256(source.read_bytes()).digest()!=entry['hash2']:raise ValueError('Bundle resource digest differs')
            elif 'cdhash' in entry:
                if bytes.fromhex(inspect(source)['cdhash'])!=entry['cdhash']:raise ValueError('Nested code identity differs')
            elif 'symlink' in entry:
                if str(source.readlink())!=entry['symlink']:raise ValueError('Bundle symlink differs')
            else:raise ValueError('Unverified bundle resource')
    return dict(cdhash=hashlib.sha256(cd).hexdigest()[:40],pagesize=4096,
        entitlements=blobs.get(5,b'')[8:],verified_code_pages=slots)
