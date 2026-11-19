#!/usr/bin/env python3
"""Verify Sony preparation resources against saved DT and pinned source."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sources',type=Path,required=True)
    p.add_argument('--stock',type=Path,required=True)
    p.add_argument('--dt',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    assert sha(a.dt)=='90c943fdb63ace5b5421f3ad1eaa98d72681a1bd2f4c73a0fc10429360aa1290'
    manifest=json.loads((a.sources/'sources.json').read_text())
    for row in manifest['files']:assert sha(Path(row['local']))==row['sha256']
    def cells(node,key):
        return [int(x,16) for x in subprocess.check_output(['fdtget','-t','x',str(a.dt),node,key],text=True).split()]
    hs='/soc/hsphy@88e3000';rptr='/soc/qcom,spmi@c42d000/qcom,pm8550b@7/eusb2-repeater@fd00'
    assert cells(hs,'reg')==[0x88e3000,0x154,0x88e2000,4,0xc276000,4]
    assert cells(hs,'usb-repeater')==cells(rptr,'phandle')
    assert cells(rptr,'reg')==[0xfd00]
    assert cells('/soc/qcom,spmi@c42d000/qcom,pm8550b@7','reg')==[7,0]
    tuning=cells(rptr,'qcom,param-override-seq')
    assert tuning==[0xf,0x51,3,0x54,7,0x57,6,0x53]
    clocks=cells(hs,'clocks');assert clocks==[0x3c,27,0x54,4]
    assert cells('/soc/apps_rsc@17a00000/drv@2/clock-controller','phandle')==[clocks[0]]
    assert cells('/soc/clock-controller@1fc0000','phandle')==[clocks[2]]
    xo=cells('/soc/clocks/xo_board','clock-frequency')[0];assert xo==76800000
    rpmh=(a.sources/'clk-rpmh.c').read_text()
    assert 'DEFINE_CLK_RPMH_ARC(kalama, xo_pad, xo_pad_ao, "xo.lvl", 0x03, 2)' in rpmh
    assert 'return prate / r->div;' in rpmh and '.name = "xo_board"' in rpmh
    assert '[RPMH_CXO_PAD_CLK]      = &kalama_xo_pad.hw' in rpmh
    hwio=next(a.stock.rglob('HalusbHWIO.h'))
    stock_manifest=json.loads((a.stock/'sources.json').read_text())
    assert sha(hwio)==next(r['sha256'] for r in stock_manifest if r['path'].endswith('/HalusbHWIO.h'))
    definition=next(line for line in hwio.read_text().splitlines() if line.startswith('#define HWIO_USB3_PRI_GENERAL_CFG_PIPE3_SET_PHYSTATUS_SW_BMSK '))
    mask=int(definition.split()[-1],16);assert mask==0x200
    result=dict(passed=True,dt_sha256=sha(a.dt),linux_repository=manifest['repository'],linux_pin=manifest['pin'],
        hs_phy_base=0x88e3000,repeater_sid=7,repeater_base=0xfd00,repeater_tuning=tuning,
        reference_clock_source_hz=xo,reference_clock_divisor=2,derived_reference_clock_hz=xo//2,
        pipe3_set_phystatus_mask=mask,hwio_sha256=sha(hwio),
        limits='Source/DT contract only. Does not verify live rails, clock rate, permissions, DMA or UEFI shutdown cause.',hardware_verified=False)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))

if __name__=='__main__':main()
