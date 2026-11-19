"""Read the port's exact PDXFAT02 transport without executing release checks.

Kept separate so a known-unbootable historical request can be examined without
turning off the new boot-argument gate or writing a misleading PASS receipt.
"""
import hashlib
import lzma
from pathlib import Path
import struct
import zlib


class BootTransport:
    def __init__(self,path,expected_sha256):
        self.raw=Path(path).read_bytes()
        if hashlib.sha256(self.raw).hexdigest()!=expected_sha256:raise ValueError('Unexpected boot image identity')
        if len(self.raw)<4096 or self.raw[:8]!=b'ANDROID!':raise ValueError('Expected Sony Android boot header')
        length=struct.unpack_from('<I',self.raw,8)[0]
        if not 80<length<=len(self.raw)-4096:raise ValueError('Truncated combined boot payload')
        self.combo=self.raw[4096:4096+length]
        fields=struct.unpack('<8sIIQQQIIQQQQ',self.combo[-80:])
        if fields[:3]!=(b'PXCBHOF1',2,80):raise ValueError('Unexpected Sony combo footer')
        offset,blob_length=fields[-2:]
        if offset<0x200000 or offset+blob_length>len(self.combo)-80:raise ValueError('Invalid FAT bundle range')
        self.blob=self.combo[offset:offset+blob_length]
        if len(self.blob)<45:raise ValueError('Truncated compressed bundle')
        magic,header,packed,logical,crc,reserved=struct.unpack_from('<8s4IQ',self.blob)
        if (magic,header,packed,reserved)!=(b'PDXFAT02',32,len(self.blob)-32,0) or not 0<logical<=256*1024**2:
            raise ValueError('Unexpected FAT bundle header')
        prop=self.blob[32];lc=prop%9;lp=(prop//9)%5;pb=prop//45
        dictionary=struct.unpack_from('<I',self.blob,33)[0]
        dec=lzma.LZMADecompressor(format=lzma.FORMAT_RAW,filters=[dict(id=lzma.FILTER_LZMA1,
            dict_size=dictionary,lc=lc,lp=lp,pb=pb)])
        self.fat=dec.decompress(self.blob[45:],max_length=logical+1)
        if len(self.fat)!=logical or not dec.eof or dec.unused_data or zlib.crc32(self.fat)!=crc:
            raise ValueError('Incomplete or corrupt FAT bundle')
        android_bytes=fields[4];self.android=self.combo[0x200000:0x200000+android_bytes]
        if len(self.android)!=android_bytes or len(self.android)<24:raise ValueError('Truncated retained Android')
        memory=struct.unpack_from('<Q',self.android,16)[0]
        self.fd=self.combo[0x200000+memory:0x200000+memory+0x300000]
        if len(self.fd)!=0x300000:raise ValueError('Truncated retained firmware')
        data=self.fat
        self.bps=struct.unpack_from('<H',data,11)[0];self.spc=data[13]
        self.reserved=struct.unpack_from('<H',data,14)[0];nf=data[16]
        roots=struct.unpack_from('<H',data,17)[0];self.fs=struct.unpack_from('<H',data,22)[0]
        total=struct.unpack_from('<H',data,19)[0] or struct.unpack_from('<I',data,32)[0]
        if self.bps not in (512,1024,2048,4096) or not self.spc or self.spc&(self.spc-1) or nf not in (1,2):
            raise ValueError('Invalid FAT geometry')
        rootsecs=(roots*32+self.bps-1)//self.bps
        if not self.fs:self.fs=struct.unpack_from('<I',data,36)[0]
        self.data_sec=self.reserved+nf*self.fs+rootsecs
        self.clusters=(total-self.data_sec)//self.spc
        self.bits=16 if self.clusters<65525 else 32
        if self.clusters<4085 or total*self.bps!=len(data):raise ValueError('Invalid FAT extent')
        start=(self.reserved+nf*self.fs)*self.bps
        self.root=data[start:start+rootsecs*self.bps] if self.bits==16 else self.chain(struct.unpack_from('<I',data,44)[0])

    def chain(self,cluster):
        result=bytearray();seen=set();end=0xfff8 if self.bits==16 else 0xffffff8
        while cluster<end:
            if cluster<2 or cluster>self.clusters+1 or cluster in seen:raise ValueError('Invalid or looping FAT chain')
            seen.add(cluster);at=(self.data_sec+(cluster-2)*self.spc)*self.bps;n=self.spc*self.bps
            if at+n>len(self.fat):raise ValueError('FAT cluster outside image')
            result+=self.fat[at:at+n]
            at=self.reserved*self.bps+cluster*(self.bits//8)
            if at+self.bits//8>(self.reserved+self.fs)*self.bps:raise ValueError('FAT entry outside table')
            cluster=struct.unpack_from('<H' if self.bits==16 else '<I',self.fat,at)[0]&(0xffff if self.bits==16 else 0xfffffff)
        return bytes(result)

    def get(self,path):
        data=self.root
        for part in path.split('/'):
            long={};found=None
            for at in range(0,len(data),32):
                entry=data[at:at+32]
                if len(entry)!=32 or not entry[0]:break
                if entry[0]==0xe5:long={};continue
                if entry[11]==15:
                    long[entry[0]&31]=(entry[1:11]+entry[14:26]+entry[28:32]).decode('utf-16-le');continue
                short=entry[:8].decode().strip()+('.'+entry[8:11].decode().strip() if entry[8:11].strip() else '')
                name=''.join(long[key] for key in sorted(long)).split('\0')[0].rstrip('\uffff') if long else short
                long={}
                if name.lower()==part.lower():found=entry;break
            if found is None:raise ValueError('Missing FAT path component: '+part)
            cluster=struct.unpack_from('<H',found,26)[0]+(struct.unpack_from('<H',found,20)[0]<<16)
            size=struct.unpack_from('<I',found,28)[0]
            data=self.chain(cluster) if cluster else b''
            if not found[11]&16:
                if size>len(data):raise ValueError('FAT file truncated: '+part)
                data=data[:size]
        return data

    def baseline_dict(self):
        return dict(raw=self.raw,android=self.android,fd=self.fd,fat=self.fat,get=self.get)
