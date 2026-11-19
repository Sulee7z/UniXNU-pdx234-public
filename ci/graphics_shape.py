"""Analysis-only normalization of complete compiler PAC checks and entry BTI."""
import struct
from kc_image import scan, signed


def shape(code, pc):
    words = list(struct.unpack('<'+'I'*(len(code)//4), code))
    removed = {0} if words and words[0] == 0xd503245f else set()
    checks = ([0xaa1003f1,0xdac147f1,0xeb11021f,0x54000040,0xd4388e40],
              [0xaa1003f1,0xdac143f1,0xeb11021f,0x54000040,0xd4388e00])
    for i in range(1,len(words)):
        for sequence in checks:
            # AUTDA/AUTIA x16,Xn; the modifier need not be x17.
            auth = 0xdac11810 if sequence is checks[0] else 0xdac11010
            if words[i:i+5] == sequence and words[i-1] & ~0x3e0 == auth:
                removed.update(range(i,i+5))
        if words[i:i+3] == [0xca1e07d0,0xb6f00050,0xd4388e20] and i+3<len(words) and words[i+3]&0xfc000000==0x14000000:
            removed.update(range(i,i+3))
    calls, refs, scanned = scan(code,pc)
    positions={i*4:j*4 for j,i in enumerate(i for i in range(len(words)) if i not in removed)}
    normalized=[]
    for i,word in enumerate(words):
        if i in removed:continue
        value=scanned[i]
        bits,shift=(26,0) if word&0x7c000000==0x14000000 else (19,5) if word&0xff000010==0x54000000 or word&0x7e000000==0x34000000 else (14,5) if word&0x7e000000==0x36000000 else (0,0)
        if bits:
            mask=(1<<bits)-1;target=i*4+signed((word>>shift)&mask,bits)*4
            if 0<=target<len(code):
                if target not in positions:return None
                value=(word&~(mask<<shift))|((((positions[target]-positions[i*4])//4)&mask)<<shift)
        normalized.append(value)
    return tuple(normalized)
