#!/usr/bin/env python3
import argparse,hashlib,json,tarfile
from pathlib import Path
def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    vendor='yodo-1.2.0-rel/vendor/qcom/opensource/display-drivers/msm/'
    kernel='yodo-1.2.0-rel/kernel_platform/msm-kernel/'
    names={vendor+n for n in {'sde/sde_hw_dsc_1_2.c','sde/sde_hw_catalog.c','sde/sde_hw_catalog.h','sde/sde_hw_top.c','sde/sde_hw_top.h',
           'sde/sde_hw_ctl.c','sde/sde_hw_intf.c','sde_power_handle.c','sde_power_handle.h','sde_rsc.c',
           'sde/sde_encoder_phys_cmd.c','sde/sde_encoder.c','sde/sde_core_perf.c','sde/sde_hw_mdss.h',
           'dsi/dsi_ctrl_hw_cmn.c','dsi/dsi_ctrl.c'}}
    names|={kernel+n for n in {'drivers/interconnect/qcom/kalama.c','drivers/interconnect/qcom/bcm-voter.c',
           'include/dt-bindings/interconnect/qcom,kalama.h'}}
    rows=json.loads(Path('/mnt/g/UniXNU-Port/references/xperia-67.2.A.3.141-hardware/archive-index.json').read_text())
    wanted={r['path']:r['bytes'] for r in rows if r['path'] in names};found=[]
    with tarfile.open('/mnt/f/UniXNU-Port-artifacts/source-archives/67.2.A.3.141.tar_.bz2','r|bz2') as stream:
        for m in stream:
            if m.name not in wanted:continue
            if not m.isfile() or m.size!=wanted[m.name]:raise ValueError('Indexed member differs')
            relative=m.name.removeprefix('yodo-1.2.0-rel/').replace('/','__')
            t=a.out/relative;t.write_bytes(stream.extractfile(m).read());found.append(dict(member=m.name,sha256=hashlib.sha256(t.read_bytes()).hexdigest(),path=str(t)))
            if len(found)==len(wanted):break
    if len(found)!=len(names):raise ValueError('Incomplete reference')
    (a.out/'result.json').write_text(json.dumps(dict(reference_only=True,files=found),indent=2)+'\n');print('Extracted',len(found),'indexedSDE files')
if __name__=='__main__':main()
