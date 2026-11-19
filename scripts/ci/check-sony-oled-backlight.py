#!/usr/bin/env python3
"""Run the production Sony OLED policy/DSI state core with ASan+UBSan."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import re

ROOT = Path(__file__).resolve().parents[2]

def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--reference', type=Path, default=Path('/mnt/f/UniXNU-Port-artifacts/platform067-20261118/backlight-reference'))
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    driver = ROOT / 'drivers/SonyOledBacklight'
    sources = [ROOT/'tests/sony_oled_host.c', driver/'SonyDsi.c', driver/'SonyOledPolicy.c']
    provenance=json.loads((args.reference/'provenance.json').read_text())
    member='yodo-1.2.0-rel/vendor/qcom/opensource/display-drivers/msm/dsi/dsi_panel_driver_hw.c'
    vendor=args.reference/'source'/member
    if sha(vendor)!=next(r['sha256'] for r in provenance['selected'] if r['member']==member):
        raise ValueError('Sony brightness reference differs')
    vendor_text=vendor.read_text()
    vendor_text='\n'.join(line for line in vendor_text.splitlines() if not line.startswith('#include'))
    vendor_unit=args.out/'verbatim-sony-policy.c'
    hal_member='yodo-1.2.0-rel_amss/BOOT.MXF.2.1.1/boot_images/boot/QcomPkg/Library/HALDSILib/HALdsi.c'
    hal=args.reference/'source'/hal_member
    if sha(hal)!=next(r['sha256'] for r in provenance['selected'] if r['member']==hal_member):
        raise ValueError('Sony DSI ECC reference differs')
    hal_text=hal.read_text();start=hal_text.index('uint8 HAL_DSI_CalculateECC(uint8 *pData)');end=hal_text.index('\n}',start)+2
    ecc_text=hal_text[start:end]
    vendor_unit.write_text('''#include <stdint.h>
typedef uint32_t u32;
typedef uint8_t uint8;
enum {HMD_OFF=0,HMD_ON=1};
struct dsi_backlight_config {u32 bl_min_level,bl_max_level,brightness_max_level;};
struct dsi_panel_specific_pdata {int hmd_mode;};
struct dsi_panel {struct dsi_backlight_config bl_config;struct dsi_panel_specific_pdata *spec_pdata;};
'''+vendor_text+'\n'+ecc_text+'''
uint8_t sony_oled_vendor_ecc(uint8_t type,uint8_t data0,uint8_t data1) {
    uint8_t data[3]={type,data0,data1};return HAL_DSI_CalculateECC(data);
}
uint16_t sony_oled_vendor_reference(uint32_t level) {
    struct dsi_panel_specific_pdata data={HMD_OFF};
    struct dsi_panel panel={{1,4095,4095},&data};
    if(!level)return 0;
    return (uint16_t)dsi_panel_driver_adjust_brightness_type1(&panel,(level*1720+4095/2)/4095);
}
''')
    command = ['clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
               '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-I', str(driver),
               '-DSONY_OLED_VENDOR_DIFF', *map(str, sources),str(vendor_unit), '-o', str(args.out/'sony-oled-host')]
    subprocess.run(command, check=True, timeout=90)
    done = subprocess.run([str(args.out/'sony-oled-host')], capture_output=True, text=True, timeout=30)
    (args.out/'run.log').write_text(done.stdout + done.stderr)
    if done.returncode:
        raise RuntimeError(done.stdout + done.stderr)
    # Remove platform-only includes and the compile-feature gate, not methods or
    # state. The exact resulting source is retained beside the fixture binary.
    wrapper=driver/'SonyOledBacklight.cpp';text=wrapper.read_text()
    text=re.sub(r'^#include [<"].*[>"]\n','',text,flags=re.M)
    gate='''#if !__has_feature(ptrauth_calls) || !__has_feature(ptrauth_signed_block_descriptors)
#error Sony OLED native wrapper requires D27 native PAC and signed Block descriptors
#endif'''
    if text.count(gate)!=1:raise ValueError('Native wrapper compile guard differs')
    (args.out/'actual-wrapper.inc').write_text(text.replace(gate,''))
    model=sources[0].read_text().split('#ifdef SONY_OLED_VENDOR_DIFF',1)[0]
    model=re.sub(r'^#include [<"].*[>"]\n','',model,flags=re.M)
    model=model.replace('Model *m=p;','Model *m=static_cast<Model *>(p);')
    # The wrapper calls production state methods, not the host convenience loop.
    model=model.split('static int finish(SonyDsi *s)',1)[0]
    (args.out/'actual-model.inc').write_text(model)
    wrapper_test=ROOT/'tests/sony_oled_wrapper.cpp'
    cpp_command=['clang++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function',
                 '-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(driver),'-I',str(args.out),
                 str(wrapper_test),'-x','c++',str(driver/'SonyDsi.c'),str(driver/'SonyOledPolicy.c'),
                 '-o',str(args.out/'sony-oled-wrapper')]
    subprocess.run(cpp_command,check=True,timeout=90)
    outputs=[done.stdout]
    for flags in ([],['missing-meta'],['no-control'],['allocation-fail'],['timeout']):
        run=subprocess.run([str(args.out/'sony-oled-wrapper'),*flags],capture_output=True,text=True,timeout=30)
        (args.out/('wrapper'+('-'+flags[0] if flags else '')+'.log')).write_text(run.stdout+run.stderr)
        if run.returncode:raise RuntimeError(run.stdout+run.stderr)
        outputs.append(run.stdout)
    files = [*sources,wrapper,wrapper_test,*driver.glob('*.h')]
    record = dict(passed=True, command=command, sources={str(p):sha(p) for p in files},
                  wrapper_command=cpp_command,vendor_reference_sha256=sha(vendor),vendor_ecc_reference_sha256=sha(hal),
                  vendor_verbatim_unit_sha256=sha(vendor_unit),
                  sanitizers=['address', 'undefined'], output=''.join(outputs),
                  hardware_verified=False, native_wrapper_executed=True, native_wrapper_iokit_mocked=True,
                  physical_mmio_provider_installed=False, device_operations=False)
    (args.out/'result.json').write_text(json.dumps(record, indent=2)+'\n')
    print(''.join(outputs), end='')

if __name__ == '__main__':
    main()
