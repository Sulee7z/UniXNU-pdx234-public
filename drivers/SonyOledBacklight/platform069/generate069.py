#!/usr/bin/env python3
"""Resolve all board-owned display resources from captured Sony FDT."""
import argparse,hashlib,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
SNAP=Path('/mnt/f/UniXNU-Port-artifacts/platform069-20261118')
DT=SNAP/'device-post068-readonly-001/live.dtb'
def main():
    p=argparse.ArgumentParser();p.add_argument('--out',required=True,type=Path);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(SNAP/'UniXNU/scripts'));from unixnu.devicetree import read_fdt
    raw=DT.read_bytes();digest=hashlib.sha256(raw).hexdigest()
    if digest!='6ab06c177a7131338cd8cc374b304838738497bf0d709a48ed50f0282c03bb8a':raise ValueError('Sony post068 liveDT differs')
    def path(n):return path(n.parent).rstrip('/')+'/'+n.name if n.parent else '/'
    nodes={path(n):n for n in read_fdt(raw).walk()};ph={n.scalar('phandle'):n for n in nodes.values() if 'phandle' in n.properties}
    display=nodes['/soc/qcom,dsi-display-primary'];mdp=nodes['/soc/qcom,mdss_mdp@ae00000'];panel=ph[display.scalar('qcom,dsi-default-panel')]
    specs=[]
    for node,key in [(display,'vddio-supply'),(display,'vci-supply'),(display,'vddr-supply'),
                     (nodes['/soc/qcom,mdss_dsi_ctrl0@ae94000'],'vdda-1p2-supply'),
                     (nodes['/soc/qcom,mdss_dsi_phy0@ae95500'],'vdda-0p9-supply')]:
        regulator=ph[node.scalar(key)];resource=regulator.parent.strings('qcom,resource-name')[0]
        uv=regulator.scalar('qcom,init-voltage');minimum=regulator.scalar('regulator-min-microvolt');maximum=regulator.scalar('regulator-max-microvolt')
        if not minimum<=uv<=maximum or uv%1000:raise ValueError('Invalid exact Sony voltage')
        specs.append(dict(resource=resource,kind='D69Vrm',voltage_mv=uv//1000,corner=0,enable=1,mode=7,
                          regulator=regulator.strings('regulator-name')[0],min_uv=minimum,max_uv=maximum))
    for key in ['vdd_mm-supply','vdd_mxa-supply']:
        regulator=ph[nodes['/soc/clock-controller@af00000'].scalar(key)]
        specs.append(dict(resource=regulator.parent.strings('qcom,resource-name')[0],kind='D69Arc',voltage_mv=0,
                          corner=regulator.scalar('qcom,init-voltage-level'),enable=1,mode=0))
    regions=[(0x100000,0x80000),(0xaf00000,0x20000),(0xae00000,0x84000),(0xae94000,0x1000),(0xae96000,0x1000),
             (0xae95000,0xa00),(0xae97000,0xa00),(0xae95500,0x400),(0xae97500,0x400)]
    expected_ctrl=[]
    for h in range(2):
        n=nodes[f'/soc/qcom,mdss_dsi_ctrl{h}@{0xae94000+0x2000*h:x}'];regs=n.cells('reg')
        if regs[:2]!=list(regions[3+h]) or regs[4:]!=[0xae36000+h*0x1000,0x300]:raise ValueError('DSI/INTF board resources differ')
        expected_ctrl.append(regs)
    modes=[]
    for timing in next(n for n in panel.children if n.name=='qcom,mdss-dsi-display-timings').children:
        modes.append(dict(id=int(timing.name.split('@')[1]),width=timing.scalar('qcom,mdss-dsi-panel-width')*2,
                          height=timing.scalar('qcom,mdss-dsi-panel-height'),hz=timing.scalar('qcom,mdss-dsi-panel-framerate'),
                          bitclk=timing.scalar('qcom,mdss-dsi-panel-clockrate'),
                          mdp_transfer_time_us=timing.scalar('qcom,mdss-mdp-transfer-time-us'),
                          phy=timing.properties['qcom,mdss-dsi-panel-phy-timings'].hex()))
    if any(not m['mdp_transfer_time_us'] for m in modes):raise ValueError('Panel timing lacks source MDP transfer budget')
    header='// Generated from exactpost068SonyDT; no board guesses.\n#pragma once\n#include "Display069.h"\n#include "Resources069.h"\n'
    header+='static const uint64_t kD69Base[]={'+','.join(hex(b) for b,n in regions)+'};\n'
    header+='static const uint32_t kD69Bytes[]={'+','.join(hex(n) for b,n in regions)+'};\n'
    header+='static const D69VoteSpec kD69Votes[]={\n'+''.join('{"'+s['resource']+'",'+s['kind']+','+','.join(str(s[k]) for k in ['voltage_mv','corner','enable','mode'])+'},\n' for s in specs)+'};\n'
    arrays={'ctl':mdp.cells('qcom,sde-ctl-off'),'dsc':mdp.cells('qcom,sde-dsc-off'),'dsc_enc':mdp.cells('qcom,sde-dsc-enc'),'pp':mdp.cells('qcom,sde-pp-off'),'intf':[0x36000,0x37000]}
    for k,v in arrays.items():header+='static const uint32_t kD69_'+k+'[]={'+','.join(hex(x) for x in v)+'};\n'
    header+='static const uint32_t kD69XoBoard='+str(nodes['/soc/clocks/xo_board'].scalar('clock-frequency'))+';\n'
    header+='static const uint8_t kD69Phy[]={'+','.join(str(x) for x in bytes.fromhex(modes[0]['phy']))+'};\n'
    header+='typedef struct D69TimingBudget {uint32_t width,height,hz,transfer_us;} D69TimingBudget;\n'
    header+='static const D69TimingBudget kD69TimingBudgets[]={'+','.join(
        '{%d,%d,%d,%d}'%(m['width'],m['height'],m['hz'],m['mdp_transfer_time_us']) for m in modes)+'};\n'
    (a.out/'SonyDisplay069.generated.h').write_text(header)
    result=dict(live_dtb=str(DT),sha256=digest,regions=regions,votes=specs,modes=modes,arrays=arrays,
                header_sha256=hashlib.sha256(header.encode()).hexdigest(),raw_actual_brightness_is_not_dbv=True)
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
