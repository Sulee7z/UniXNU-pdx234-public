"""Source-qualified removal of XBOOT-only coin-cell setup after ABL handoff."""
import hashlib
import struct

ORIGINAL_SHA='59156fc095abb5bc739edc63b6b02034727096eb29a2dbe61262dd744c8da1fb'
RVA=0x127a4
TARGET=0x127bc
EXPECTED=bytes.fromhex('c2a88252e0031f2a21008052e3031f2a53d4ff977302002a')


def adapt_source(text):
    old='''#ifdef FEATURE_XBOOT
  err_flag |= pm_comm_write_byte_ex(0, 1, 0x1546, 0x00); // Put PM8550 VREG_COIN to 0x0
#endif /* FEATURE_XBOOT */'''
    if text.count(old)!=1:raise ValueError('Unknown Sony coin-cell source')
    return text.replace(old,'''/* The original XBOOT already handled VREG_COIN before ABL. This
   * secondary UEFI preserves that state; remaining PMIC init errors propagate. */''')


def adapt_pe(data):
    if hashlib.sha256(data).hexdigest()!=ORIGINAL_SHA or data[RVA:RVA+len(EXPECTED)]!=EXPECTED:
        raise ValueError('Unknown Sony PmicDxe binary')
    # This captured PE has equal raw/RVA offsets for .text; verify, do not assume.
    pe=struct.unpack_from('<I',data,0x3c)[0]
    start=pe+24+struct.unpack_from('<H',data,pe+20)[0]
    for i in range(struct.unpack_from('<H',data,pe+6)[0]):
        at=start+40*i
        size,va,rawsize,offset=struct.unpack_from('<4I',data,at+8)
        if va<=RVA<TARGET<va+rawsize:
            if va!=offset:raise ValueError('Unexpected PE section offsets')
            break
    else:raise ValueError('Missing code section')
    result=bytearray(data)
    struct.pack_into('<I',result,RVA,0x14000000|((TARGET-RVA)//4))
    return bytes(result)
