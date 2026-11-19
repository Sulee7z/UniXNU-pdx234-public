#!/usr/bin/env python3
import argparse,hashlib,json,tarfile
from pathlib import Path
def main():
    p=argparse.ArgumentParser();p.add_argument('--out',required=True,type=Path);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    names={
        'yodo-1.2.0-rel/kernel_platform/msm-kernel/drivers/clk/qcom/gdsc.c',
        'yodo-1.2.0-rel/kernel_platform/msm-kernel/drivers/clk/qcom/gdsc-regulator.c',
        'yodo-1.2.0-rel/kernel_platform/msm-kernel/drivers/interconnect/qcom/kalama.c',
        'yodo-1.2.0-rel/kernel_platform/msm-kernel/drivers/interconnect/qcom/bcm-voter.c',
        'yodo-1.2.0-rel/kernel_platform/msm-kernel/include/dt-bindings/interconnect/qcom,kalama.h',
        'yodo-1.2.0-rel/vendor/qcom/opensource/display-drivers/msm/sde_power_handle.c',
        'yodo-1.2.0-rel/vendor/qcom/opensource/display-drivers/msm/sde_rsc.c',
        'yodo-1.2.0-rel/vendor/qcom/opensource/display-drivers/msm/dsi/dsi_ctrl_hw_cmn.c',
        'yodo-1.2.0-rel/vendor/qcom/opensource/display-drivers/msm/dsi/dsi_ctrl.c',
    }
    rows=json.loads(Path('/mnt/g/UniXNU-Port/references/xperia-67.2.A.3.141-hardware/archive-index.json').read_text())
    sizes={r['path']:r['bytes'] for r in rows if r['path'] in names}
    if sizes.keys()!=names:raise ValueError('Incomplete indexed Sony GDSC/NoC reference set')
    with tarfile.open('/mnt/f/UniXNU-Port-artifacts/source-archives/67.2.A.3.141.tar_.bz2','r|bz2') as stream:
        found=[]
        for m in stream:
            if m.name not in sizes:continue
            if not m.isfile()or m.size!=sizes[m.name]:raise ValueError('Reference/index mismatch: '+m.name)
            target=a.out/Path(m.name.replace('/','__')).name
            data=stream.extractfile(m).read();target.write_bytes(data)
            found.append(dict(member=m.name,bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),path=str(target)))
            if len(found)==len(sizes):break
        if len(found)!=len(sizes):raise ValueError('Indexed reference members missing: '+repr(sorted(set(sizes)-{x['member'] for x in found})))
    (a.out/'result.json').write_text(json.dumps(dict(reference_only=True,files=found),indent=2)+'\n');print('Extracted indexed Sony display GDSC/NoC references',len(found))
if __name__=='__main__':main()
