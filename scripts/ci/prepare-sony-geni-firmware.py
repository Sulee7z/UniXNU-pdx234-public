#!/usr/bin/env python3
"""Validate the Sony/Kailua SEFW image and bind every init register to its OEM HAL."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

PROJECT=Path(__file__).resolve().parents[4]
BOARD=PROJECT/'references/sony-touch-board-20261118'
REGISTERS=PROJECT/'references/sony-geni-registers-20261118'
SUB=Path('yodo-1.2.0-rel_amss/BOOT.MXF.2.1.1/boot_images/boot/QcomPkg')
FW=BOARD/SUB/'SocPkg/Kailua/Settings/I2C/i2c_geni_fw.c'
SE=REGISTERS/SUB/'Library/I2CLib/HALqupv3SeHwio.h'
COMMON=REGISTERS/SUB/'Library/I2CLib/HALqupv3CommonHwio.h'


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    for directory in (BOARD,REGISTERS):
        provenance=json.loads((directory/'provenance.json').read_text())
        for path,row in provenance['files'].items():
            if sha(directory/path)!=row['sha256']:raise ValueError('Sony reference source changed: '+path)
    body=FW.read_text().split('qup_v3_9_i2c_fw[]',1)[1].split('{',1)[1].split('}',1)[0]
    data=bytes(int(v,16) for v in re.findall(r'0x([0-9a-fA-F]{2})\b',body))
    if hashlib.sha256(data).hexdigest()!='0840aa323be767f134050cf8ff365b9e4675063863a8a34adc18343b978224e4':
        raise ValueError('Kailua I2C image identity differs')
    fields=struct.unpack_from('<III8H',data)
    if fields[:3]!=(0x57464553,1,0x30090000) or fields[3:]!=(3,0x103,9,303,28,69,1516,1240):
        raise ValueError('Unexpected SEFW header')
    # Bind exact definitions instead of inventing offsets from the read-only mirrors.
    se=SE.read_text();common=COMMON.read_text()
    expected={
      'QUPV3_SEn_REG_BASE_OFFS':'0x00080000',
      'QUPV3_SEn_GENI4_IMAGE_REG_BASE_OFFS':'0x00081000',
      'QUPV3_SEn_GENI4_IMAGE_REGS_REG_BASE_OFFS':'0x00080100',
      'QUPV3_SEn_QUPV3_SEC_REG_BASE_OFFS':'0x00082000',
      'HWIO_QUPV3_SEn_GENI_CGC_CTRL_PROG_RAM_SCLK_OFF_BMSK':'0x200',
      'HWIO_QUPV3_SEn_GENI_CGC_CTRL_PROG_RAM_HCLK_OFF_BMSK':'0x100',
      'HWIO_QUPV3_SEn_SE_HW_PARAM_2_GEN_USE_MINICORES_BMSK':'0x1000'
    }
    for key,value in expected.items():
        if not re.search(r'^#define\s+'+re.escape(key)+r'\s+'+re.escape(value)+r'\s*$',se,re.M):
            raise ValueError('OEM HAL definition differs: '+key)
    for key,at in [('HWIO_QUPV3_QUPV3_COMMON_CFG_ADDR',0x120),('HWIO_QUPV3_QUPV3_SE_AHB_M_CFG_ADDR',0x118)]:
        line=re.search(r'^#define\s+'+key+r'\(x\)[^\n]+',common,re.M)
        if not line or f'0x{at:08x}' not in line[0]:raise ValueError('QUP wrapper definition differs')
    args.out.mkdir(parents=True,exist_ok=False)
    (args.out/'sony-geni-i2c.bin').write_bytes(data)
    text='/* OEM firmware data, extracted unmodified from Sony archive; reference provenance in result.json. */\n'
    text+='#include <stdint.h>\nextern "C" {\nconst uint8_t native_sony_geni_firmware[]={\n'
    text+='\n'.join(','.join(f'0x{v:02x}' for v in data[i:i+16])+',' for i in range(0,len(data),16))
    text+='\n};\nconst uint32_t native_sony_geni_firmware_size=sizeof(native_sony_geni_firmware);\n}\n'
    # C++ const data needs external linkage, not a local unreferenced array.
    text=text.replace('const uint8_t native_sony','extern const uint8_t native_sony').replace('const uint32_t native_sony','extern const uint32_t native_sony')
    generated=args.out/'SonyGeniFirmware.cpp';generated.write_text(text)
    record={'passed':True,'firmware_bytes':len(data),'firmware_sha256':hashlib.sha256(data).hexdigest(),
            'source':str(FW),'source_sha256':sha(FW),'se_hal_sha256':sha(SE),'wrapper_hal_sha256':sha(COMMON),
            'oem_hal_definitions':expected,'generated':str(generated),'generated_sha256':sha(generated),
            'firmware_target':'QUP3.9+ Kailua I2C serial engine RAM; NOT sensor flash',
            'serial_protocol':3,'instruction_words':303,'configuration_pairs':69,
            'hardware_verified':False,'secure_alias_access_runtime_verified':False}
    (args.out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))


if __name__=='__main__':main()
