#!/usr/bin/env python3
"""Check selected Sony inputs against retained DT and actual linked archives."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    dt=Path('/mnt/g/UniXNU-Port/evidence/Xperia-XQ-DQ72/20261110T051320Z/live.dtb')
    assert sha(dt)=='90c943fdb63ace5b5421f3ad1eaa98d72681a1bd2f4c73a0fc10429360aa1290'
    rows=[]
    def cells(node,prop):
        return [int(x,16) for x in subprocess.check_output(['fdtget','-t','x',str(dt),node,prop],text=True).split()]
    def check(name,node,prop,expected):
        actual=cells(node,prop)
        if actual!=expected:raise ValueError(name+' differs: '+repr(actual))
        rows.append(dict(name=name,node=node,property=prop,cells=actual))
    check('Sony splash reservation','/reserved-memory/splash_region','reg',[0,0xb8000000,0,0x2b00000])
    check('Sony ZAP reservation','/reserved-memory/gpu_micro_code_region@9b09a000','reg',[0,0x9b09a000,0,0x2000])
    check('Sony command database','/reserved-memory/aop_cmd_db_region@81c60000','reg',[0,0x81c60000,0,0x20000])
    smmu='/soc/kgsl-smmu@3da0000'
    provider=cells(smmu,'phandle')[0]
    check('GPU SMMU register windows',smmu,'reg',[0x3da0000,0x40000,0x3de6000,0x40])
    for name,sid in [('gfx3d_user',0),('gfx3d_lpac',1),('gfx3d_secure',2)]:
        check(name,'/soc/qcom,kgsl-iommu@3da0000/'+name,'iommus',[provider,sid,0])
    check('GMU SID','/soc/qcom,gmu@3d69000','iommus',[provider,5,0])
    check('EPSS windows','/soc/qcom,cpufreq-hw','reg',[0x17d91000,0x1000,0x17d92000,0x1000,0x17d93000,0x1000])
    native=json.loads((BASE/'native-usb-reset-002/result.json').read_text())
    archives={}
    for key in ['display_source','gpu_source']:
        item=native[key];archive=Path(item['archive'])
        assert sha(archive)==item['sha256']
        archives[key]=dict(path=str(archive),sha256=item['sha256'])
    generated=[]
    for relative in ['build/sheng-gmu/ShengGmuSource.h','build/sheng-gmu/ShengGmuVotesSource.h',
                     'build/sheng-gmu/ShengGmuCommandDbSource.h','build/sheng-gpu-smmu/ShengGpuSmmuSource.h']:
        old=BASE/'gpu-sony-generated-001'/relative
        new=BASE/'gpu-sony-generated-002'/relative
        linked=BASE/'gpu-source-006'/relative
        assert old.read_bytes()==new.read_bytes()==linked.read_bytes()
        generated.append(dict(path=relative,sha256=sha(new)))
    firmware=json.loads((BASE/'gpu-sony-generated-002/result.json').read_text())['firmware']
    for item in firmware:
        assert item['repository']=='TheMuppets/proprietary_vendor_sony_pdx234'
        assert sha(Path(item['path']))==item['sha256']
    display=(BASE/'display-source-008/kits/sheng/LegacyDisplayProbe.cpp').read_text()
    late=display.split('void native_legacy_display_late_probe(void) {',1)[1]
    excluded=['native_touch_probe','sheng_wifi_probe','sheng_bluetooth_probe','sheng_usb_probe',
              'sheng_adsp_probe','sheng_battery_probe','sheng_audio_probe','sheng_buttons_probe',
              'sheng_backlight_probe','sheng_keyboard_probe','sheng_dpu_probe']
    assert all(name+'(' not in late for name in excluded)
    nabu=BASE/'reference-nabu-usb-cdc-001'
    pin=subprocess.check_output(['git','-C',str(nabu),'rev-parse','HEAD'],text=True).strip()
    assert pin=='721dad1b1e2bcf1a12bd48674d960eab1de96217'
    report=dict(passed=True,scope='listed source inputs only; not a complete semantic/hardware audit',
        sony_dtb_sha256=sha(dt),dt_checks=rows,linked_archives=archives,
        regenerated_headers_identical=generated,sony_gpu_firmware=firmware,
        tablet_initializers_absent=excluded,nabu_pin=pin,
        nabu_files={rel:sha(nabu/rel) for rel in ['module/soc/Sm8150.h','module/soc/QcomUsbPrepare.c',
            'module/soc/QcomUsbBypass.c','module/usb/Dwc3.c']},
        findings=[
            'GPU SID/range generator previously copied constants without checking Sony phandles; now resolves DT and regenerates identical headers',
            'GOP direct scanout retains tablet stride0x2fa0;051 explicitly selects dpu-scanout=0',
            '294dpi/3048x2032 code is macOS-only; current iOS GOP uses PE_current_console',
            'Sony brightness service and27 calibration integration are absent; desktop causality unproven',
            'nabu uses SM8150 femto PHY/SID140; Sony uses eUSB2/SID40; no bypass/PHY substitution justified',
            '051 retains049 UEFI startup regression; GPU flag change cannot repair failure before XNU'],
        hardware_verified=False,desktop_verified=False)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(report,indent=2)+'\n')
    print('PASS',len(rows),'Sony DT checks;',len(generated),'identical generated headers; linked archive identities')

if __name__=='__main__':main()
