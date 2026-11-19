import struct
LC_SEGMENT_64=0x19; LC_SYMTAB=0x2; LC_FILESET_ENTRY=0x80000035
class MachO:
    def __init__(self, data, off=0):
        self.data=data; self.off=off
        magic,cpu,sub,ftype,ncmds,sizeofcmds,flags,res=struct.unpack_from('<IiiIIIII',data,off)
        assert magic==0xfeedfacf, hex(magic)
        self.ftype=ftype; self.cmds=[]; self.segments=[]; self.entries=[]; self.symtab=None
        p=off+32
        for _ in range(ncmds):
            cmd,size=struct.unpack_from('<II',data,p)
            self.cmds.append((cmd,p,size))
            if cmd==LC_SEGMENT_64:
                name=data[p+8:p+24].split(b'\0')[0].decode()
                vmaddr,vmsize,fileoff,filesize,maxprot,initprot,nsects,flg=struct.unpack_from('<QQQQiiII',data,p+24)
                sects=[]
                for i in range(nsects):
                    q=p+72+i*80
                    sn=data[q:q+16].split(b'\0')[0].decode(); sg=data[q+16:q+32].split(b'\0')[0].decode()
                    addr,size2,offset,align,reloff,nreloc,sflags=struct.unpack_from('<QQIIIII',data,q+32)
                    sects.append(dict(sect=sn,seg=sg,addr=addr,size=size2,offset=offset,flags=sflags))
                self.segments.append(dict(name=name,vmaddr=vmaddr,vmsize=vmsize,fileoff=fileoff,filesize=filesize,sects=sects,cmdoff=p))
            elif cmd==LC_FILESET_ENTRY:
                vmaddr,fileoff,stroff=struct.unpack_from('<QQI',data,p+8)
                name=data[p+stroff:p+size].split(b'\0')[0].decode()
                self.entries.append(dict(name=name,vmaddr=vmaddr,fileoff=fileoff))
            elif cmd==LC_SYMTAB:
                self.symtab=struct.unpack_from('<IIII',data,p+8)
            p+=size
    def symbols(self, base=0):
        if not self.symtab: return {}
        symoff,nsyms,stroff,strsize=self.symtab
        out={}
        for i in range(nsyms):
            q=base+symoff+i*16
            strx,ntype,nsect,ndesc,value=struct.unpack_from('<IBBHQ',self.data,q)
            if ntype & 0xe0: continue  # stab
            if (ntype & 0x0e)==0x0e:
                s=self.data[base+stroff+strx:self.data.index(b'\0',base+stroff+strx)].decode('latin1')
                out.setdefault(s,value)
        return out
    def va2off(self, va):
        for s in self.segments:
            if s['vmaddr']<=va<s['vmaddr']+s['filesize']:
                return s['fileoff']+(va-s['vmaddr'])
        return None
