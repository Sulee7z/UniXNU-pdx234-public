#!/usr/bin/env python3
"""Qualify exact Sony panel mode inputs without MMIO or device access."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

SNAP=Path('/mnt/f/UniXNU-Port-artifacts/platform067-20261118')
LIVE=Path('/mnt/g/UniXNU-Port/evidence/Xperia-XQ-DQ72/20261118-platform-post066-readonly-001/live.dtb')
LIVE_SHA='9dc4b4512490d77ef0e6230815ceb731937bcd65b74397e718970f2ab91c37ef'


def digest(data):return hashlib.sha256(data).hexdigest()


def decode_commands(raw):
    result=[];at=0
    while at<len(raw):
        if len(raw)-at<7:raise ValueError('truncated DSI packet header')
        dtype,last,vc,ack,wait=raw[at:at+5];size=struct.unpack_from('>H',raw,at+5)[0]
        start=at;at+=7
        if at+size>len(raw):raise ValueError('truncated DSI packet payload')
        data=raw[at:at+size];at+=size
        result.append(dict(offset=start,type=hex(dtype),last=last,vc=vc,ack=ack,wait_ms=wait,
                           bytes=size,data=data.hex(),sha256=digest(data)))
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    if digest(LIVE.read_bytes())!=LIVE_SHA:raise ValueError('Require exact saved Sony live DT')
    a.out.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(SNAP/'UniXNU/scripts'))
    from unixnu.devicetree import read_fdt
    def path(n):return path(n.parent).rstrip('/')+'/'+n.name if n.parent else '/'
    nodes={path(n):n for n in read_fdt(LIVE.read_bytes()).walk()}
    panel=nodes['/soc/qcom,mdss_mdp@ae00000/somc,1_panel']
    modes={}
    def value(k,v):
        if not v:return True
        if any(n in k for n in ('-command','-phy-timings')) and not k.endswith('-state') and k!='qcom,mdss-dsi-te-dcs-command':
            row=dict(bytes=len(v),hex=v.hex(),sha256=digest(v))
            if k.endswith('-command'):row['packets']=decode_commands(v)
            return row
        if any(v) and v[-1:]==b'\0' and all(x==0 or 32<=x<127 for x in v):
            return v[:-1].decode().split('\0')
        if len(v)%4==0:return list(struct.unpack('>'+str(len(v)//4)+'I',v))
        return dict(hex=v.hex(),sha256=digest(v))
    for n in panel.children:
        if n.name=='qcom,mdss-dsi-display-timings':
            for mode in n.children:
                modes[mode.name]={k:value(k,v) for k,v in mode.properties.items()}
    info=dict(live_dtb=str(LIVE),sha256=digest(LIVE.read_bytes()),
              panel={k:value(k,v) for k,v in panel.properties.items()},modes=modes)
    timing_nodes=next(n for n in panel.children if n.name=='qcom,mdss-dsi-display-timings').children
    info['mode_property_hashes']={n.name:digest(b''.join(k.encode()+b'\0'+struct.pack('>I',len(v))+v
                                for k,v in sorted(n.properties.items()))) for n in timing_nodes}
    for before,after in ((0,2),(1,3)):
        x,y=(modes['timing@'+str(n)] for n in (before,after))
        stable=[k for k in x if ('dsc-' in k or 'phy-timings' in k or 'porch' in k or
                'pulse-width' in k or k in ('qcom,display-topology','qcom,mdss-dsi-panel-width',
                'qcom,mdss-dsi-panel-height','qcom,mdss-dsi-panel-clockrate'))]
        if any(x[k]!=y[k] for k in stable):raise ValueError('Unexpected same-resolution mode hardware delta')
    for n,pin in ((2,'d124a28ed8a4a47dbdecc5a5e03b5fb49310a86ead8461edde96dd5e91dd17e4'),
                  (3,'acd51bc0e20aeae72cff491b772c756ec178ec0057f73ba5e7e9c48d121007cb')):
        cmd=modes['timing@'+str(n)]['qcom,mdss-dsi-timing-switch-command']
        if cmd['bytes']!=72 or cmd['sha256']!=pin or len(cmd['packets'])!=7:raise ValueError('Unpinned Sony HS timing command set')
    info['hardware']={}
    for n in nodes.values():
        p=path(n)
        if p in ('/chosen','/soc/qcom,mdss_mdp@ae00000','/soc/qcom,mdss_dsi_ctrl0@ae94000','/soc/qcom,mdss_dsi_ctrl1@ae96000') or n.name in ('qcom,dsi-display-primary','qcom,dsi-display-secondary'):
            wanted=('reg','reg-names','compatible','qcom,sde-intf-off','qcom,sde-intf-type','qcom,sde-intf-tear-irq-off',
                    'qcom,sde-pp-off','qcom,sde-dsc-off','qcom,sde-ctl-off','qcom,sde-dsc-enc','qcom,sde-dsc-ctl',
                    'qcom,sde-off','qcom,dsi-ctrl','qcom,dsi-phy','qcom,dsi-panel','qcom,dsi-display-active',
                    'qcom,cmd-sync-wait-broadcast','qcom,cmd-sync-wait-trigger','qcom,display-type',
                    'qcom,dsi-display-type','qcom,mdp-transfer-time-us','bootargs')
            info['hardware'][p]={k:value(k,v) for k,v in n.properties.items() if k in wanted}
    (a.out/'modes.json').write_text(json.dumps(info,indent=2)+'\n')
    summary={}
    for pair in [('timing@0','timing@2'),('timing@1','timing@3')]:
        x,y=(modes[k] for k in pair);changes={k:dict(before=x.get(k),after=y.get(k)) for k in sorted(x.keys()|y.keys()) if x.get(k)!=y.get(k)}
        (a.out/(pair[0]+'-to-'+pair[1]+'.json')).write_text(json.dumps(changes,indent=2)+'\n')
        summary['-to-'.join(pair)]={k:{side:(dict(bytes=v['bytes'],sha256=v['sha256'],packets=len(v.get('packets',[])))
                   if isinstance(v,dict) and 'bytes' in v else v) for side,v in row.items()} for k,row in changes.items()}
    (a.out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(dict(modes=str(a.out/'modes.json'),summary=summary,hardware=info['hardware']),indent=2))


if __name__=='__main__':main()
