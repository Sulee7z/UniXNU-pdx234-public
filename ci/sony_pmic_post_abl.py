"""Preserve charger and PS_HOLD policy handed off by Sony XBOOT/ABL."""
import hashlib
import struct

INPUT_SHA='92166009d3908a7ed5532a272333508a1366613fd221085c35785fd1728c6684'

def adapt_pe(data):
    if hashlib.sha256(data).hexdigest()!=INPUT_SHA:raise ValueError('Unknown coin-cell-adapted PMIC PE')
    def branch(at,target):return struct.pack('<I',0x14000000|(((target-at)//4)&0x3ffffff))
    expected={0x1694:bytes.fromhex('e00314aa'),0x1698:bytes.fromhex('e10313aa'),
              0x16b0:bytes.fromhex('40008052'),0x16b4:struct.pack('<I',0x94000000|((0x19078-0x16b4)//4))}
    for at,value in expected.items():
        if data[at:at+4]!=value:raise ValueError('Unexpected PMIC policy code')
    result=bytearray(data)
    # pm_post_pmic_initialization is first-boot charging/board policy.
    # Keep the error accumulated by the preceding power-key check in w21.
    result[0x1694:0x1698]=bytes.fromhex('f603152a')  # mov w22,w21
    result[0x1698:0x169c]=branch(0x1698,0x16a4)
    # Omit FEATURE_XBOOT PS_HOLD reconfiguration; retained init errors in w22
    # still determine EFI status. ADC entrypoint remains called.
    result[0x16b0:0x16b4]=bytes.fromhex('f5031f2a')  # mov w21,wzr
    result[0x16b4:0x16b8]=branch(0x16b4,0x16bc)
    return bytes(result)

def adapt_source(text):
    old='    err_flag |= pm_post_pmic_initialization(ImageHandle, SystemTable);'
    if text.count(old)!=1:raise ValueError('Unknown post-init source')
    text=text.replace(old,'    /* Secondary UEFI preserves charger/board policy established before ABL. */')
    old='''#ifdef FEATURE_XBOOT
  err_flag |= pm_app_pon_pshold_cfg(PM_APP_PON_CFG_NORMAL_SHUTDOWN);
#endif /* FEATURE_XBOOT */'''
    if text.count(old)!=1:raise ValueError('Unknown PS_HOLD source')
    return text.replace(old,'  /* Preserve the inherited PS_HOLD policy after ABL. */')
