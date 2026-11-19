#!/usr/bin/env python3
"""Translate selected upstream codesign calls to real rcodesign and verify hashes."""
import hashlib
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import sys

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def executable(path):
    if path.is_dir():
        return path/plistlib.loads((path/'Info.plist').read_bytes())['CFBundleExecutable']
    return path


def inspect(path):
    target=executable(path);data=target.read_bytes()
    assert struct.unpack_from('<I',data)[0]==0xfeedfacf
    at=32;signature=None
    for _ in range(struct.unpack_from('<I',data,16)[0]):
        cmd,size=struct.unpack_from('<II',data,at)
        if cmd==0x1d:
            off,length=struct.unpack_from('<II',data,at+8);signature=data[off:off+length]
        at+=size
    assert signature is not None
    magic,length,count=struct.unpack_from('>III',signature)
    assert magic==0xfade0cc0 and length<=len(signature)
    blobs={}
    for i in range(count):
        kind,offset=struct.unpack_from('>II',signature,12+8*i)
        _,size=struct.unpack_from('>II',signature,offset)
        assert offset+size<=length
        blobs[kind]=signature[offset:offset+size]
    cd=blobs[0];assert struct.unpack_from('>I',cd)[0]==0xfade0c02
    hash_offset,ident,special,slots,limit=struct.unpack_from('>IIIII',cd,16)
    hash_size,hash_type,platform,page=struct.unpack_from('>BBBB',cd,36)
    assert hash_size==32 and hash_type==2 and page==12
    assert slots==(limit+4095)//4096 and limit<=len(data)
    for i in range(slots):
        digest=hashlib.sha256(data[i*4096:min(limit,(i+1)*4096)]).digest()
        assert cd[hash_offset+32*i:hash_offset+32*(i+1)]==digest, 'Code page digest mismatch'
    external={}
    if path.is_dir():
        external[1]=(path/'Info.plist').read_bytes()
        external[3]=(path/'_CodeSignature/CodeResources').read_bytes()
    for slot in range(1,special+1):
        value=cd[hash_offset-slot*32:hash_offset-(slot-1)*32]
        content=external.get(slot,blobs.get(slot))
        if content is not None:assert hashlib.sha256(content).digest()==value, 'Special slot digest mismatch'
        else:assert not any(value), 'Unverified external signature slot'
    if path.is_dir():
        resources=plistlib.loads(external[3])
        for rel,entry in resources.get('files2',{}).items():
            if 'hash2' in entry:assert hashlib.sha256((path/rel).read_bytes()).digest()==entry['hash2']
            elif 'cdhash' in entry:assert bytes.fromhex(inspect(path/rel)['cdhash'])==entry['cdhash']
            elif 'symlink' in entry:assert str((path/rel).readlink())==entry['symlink']
            else:raise ValueError('Unsupported sealed resource '+rel)
    return dict(cdhash=hashlib.sha256(cd).hexdigest()[:40],pagesize=4096,
                entitlements=blobs.get(5,b'')[8:],verified_code_pages=slots)


def main():
    args=sys.argv[1:];path=Path(args[-1]);exe=Path(json.loads((BASE/'user-signing-001/source.json').read_text())['executable'])
    if '--sign' in args:
        assert args[args.index('--sign')+1]=='-'
        assert args[args.index('--pagesize')+1]=='4096'
        cmd=[str(exe),'sign','--digest','sha256','--binary-identifier',args[args.index('--identifier')+1]]
        if path.is_dir():cmd+=['--shallow']
        if '--entitlements' in args:cmd+=['--entitlements-xml-file',args[args.index('--entitlements')+1]]
        subprocess.run([*cmd,str(path)],check=True)
        inspect(path)
    elif '--verify' in args:inspect(path)
    elif '--display' in args or '-d' in args:
        result=inspect(path)
        if '--entitlements' in args:sys.stdout.buffer.write(result['entitlements'])
        else:print('CDHash='+result['cdhash']+'\nPage size=4096',file=sys.stderr)
    else:raise SystemExit('Unsupported codesign invocation')


if __name__=='__main__':main()
