"""Secondary UEFI must not repeat original XBOOT ownership teardown."""
import hashlib
import struct

INPUT_SHA='caf9aefc29a8138be340f4f5667093818dd0c8605a96f64cf25c7b7b6c850889'

def adapt_pe(data):
    if hashlib.sha256(data).hexdigest()!=INPUT_SHA:raise ValueError('Unknown post-ABL PMIC PE')
    if data[0x4104:0x4124]!=bytes.fromhex('69390094f303002a373a00941300132aa73200947302002aec3900946902002a'):
        raise ValueError('Unknown exit cleanup sequence')
    result=bytearray(data)
    result[0x410c:0x4110]=bytes.fromhex('e903132a') # mov w9,w19: target cleanup result
    struct.pack_into('<I',result,0x4110,0x14000000|((0x4124-0x4110)//4))
    return bytes(result)

def adapt_source(text):
    for call in ['pm_utils_irq_disable_clr_all','pm_config_lock_by_bit','pm_revoke_channel_access']:
        old='  err_flag |= '+call+'();'
        if text.count(old)!=1:raise ValueError('Unknown exit source '+call)
        text=text.replace(old,'  /* Post-ABL: preserve inherited state; omit '+call+'. */')
    return text
