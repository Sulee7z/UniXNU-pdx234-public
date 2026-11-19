#!/usr/bin/env python3
"""Generate sheng GPU inputs from the retained Sony DT and pinned shared sources."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import urllib.request

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
LIVE=Path('/mnt/g/UniXNU-Port/evidence/Xperia-XQ-DQ72/20261110T051320Z/live.dtb')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    for directory in ('scripts/data','kits/sheng','build/adreno-firmware','.cache'):(out/directory).mkdir(parents=True,exist_ok=True)
    pins=json.loads((BASE/'gpu-inputs-001/scripts/data/adreno-inputs.json').read_text())
    (out/'.cache/adreno-source').symlink_to(BASE/'gpu-inputs-001/.cache/adreno-source',target_is_directory=True)
    gpu='/soc/qcom,kgsl-3d0@3d00000';gmu='/soc/qcom,gmu@3d69000'
    def prop(node,name,kind='x'):
        return subprocess.check_output(['fdtget','-t',kind,str(LIVE),node,name],text=True).strip().split()
    def cells(node,name):return [int(v,16) for v in prop(node,name)]
    def windows(node):
        reg=cells(node,'reg');names=prop(node,'reg-names','s')
        if len(reg)!=2*len(names):raise ValueError('Unexpected Sony reg layout')
        return dict(zip(names,[dict(base=reg[i],bytes=reg[i+1]) for i in range(0,len(reg),2)]))
    gw,mw=windows(gpu),windows(gmu)
    # Resolve the Sony IOMMU provider and stream cells, rather than copying the
    # sheng generator's expected values into a purported Sony input report.
    smmu='/soc/kgsl-smmu@3da0000'
    sw=windows(smmu)
    provider=cells(smmu,'phandle')[0]
    assert cells(smmu,'#iommu-cells')==[2]
    def stream(node):
        binding=cells(node,'iommus')
        if len(binding)!=3 or binding[0]!=provider or binding[2]!=0:
            raise ValueError('Unexpected Sony GPU IOMMU binding: '+node)
        return binding[1]
    gpu_streams=[stream('/soc/qcom,kgsl-iommu@3da0000/'+name) for name in ('gfx3d_user','gfx3d_lpac')]
    gmu_stream=stream(gmu)
    if gpu_streams!=[0,1] or gmu_stream!=5 or sw['base']!=dict(base=0x3da0000,bytes=0x40000):
        raise ValueError('Sony GPU binding unsupported by selected generator')
    assert cells('/reserved-memory/gpu_micro_code_region@9b09a000','reg')==[0,0x9b09a000,0,0x2000]
    assert cells('/reserved-memory/aop_cmd_db_region@81c60000','reg')==[0,0x81c60000,0,0x20000]
    assert gw['kgsl_3d0_reg_memory']==dict(base=0x3d00000,bytes=0x40000)
    assert gw['rscc']==dict(base=0x3d50000,bytes=0x10000)
    assert gw['cx_misc']==dict(base=0x3d9e000,bytes=0x1000)
    assert mw['gmu']==dict(base=0x3d68000,bytes=0x37000)
    assert mw['gmu_pdc']==dict(base=0xb280000,bytes=0x10000)
    # The mainline register API exposes the CM3 subwindow at+0x2000. This
    # interval is wholly inside the Sony GMU range; the same translated window
    # is consumed by the shared ShengGmu and board power implementations.
    core=dict(base=mw['gmu']['base']+0x2000,bytes=mw['gmu']['bytes']-0x2000)
    ddr=cells(gpu,'qcom,bus-table-ddr');bins=[]
    for name in subprocess.check_output(['fdtget','-l',str(LIVE),gpu+'/qcom,gpu-pwrlevel-bins'],text=True).split():
        path=gpu+'/qcom,gpu-pwrlevel-bins/'+name;entries=[]
        for child in subprocess.check_output(['fdtget','-l',str(LIVE),path],text=True).split():
            q=path+'/'+child;hz=cells(q,'qcom,gpu-freq')[0];level=cells(q,'qcom,level')[0];bw=cells(q,'qcom,bus-freq')[0]
            entries.append((hz,level,ddr[bw]))
        bins.append(set(entries))
    # No unmeasured speed-bin selection: choose only exact OPP tuples present
    # in every recorded bin. ACD remains off as in sheng's current cold start.
    common=sorted(set.intersection(*bins))
    if not common:raise ValueError('No common Sony GPU OPPs')
    gmufreq=cells(gmu,'qcom,gmu-freq-table')
    gpu_opps='\n'.join(f'opp-{hz} {{opp-hz=/bits/ 64 <{hz}>; opp-level=<{level}>; opp-peak-kBps=<{bw}>;}};' for hz,level,bw in common)
    gmu_opps='\n'.join(f'opp-{gmufreq[i]} {{opp-hz=/bits/ 64 <{gmufreq[i]}>; opp-level=<{gmufreq[i+1]}>;}};' for i in range(0,len(gmufreq),2))
    dts=f'''/dts-v1/;
/ {{ #address-cells=<2>; #size-cells=<2>;
 reserved-memory {{ #address-cells=<2>; #size-cells=<2>; ranges;
  aop-cmd-db-region@81c60000 {{ compatible="qcom,cmd-db"; reg=<0 0x81c60000 0 0x20000>; no-map; }};
 }};
 soc {{ #address-cells=<2>; #size-cells=<2>; ranges;
  gpu@3d00000 {{ reg=<0 0x3d00000 0 0x40000 0 0x3d9e000 0 0x1000>;
   reg-names="kgsl_3d0_reg_memory","cx_mem"; operating-points-v2=<&gopp>;
   gopp: opp-table {{ compatible="operating-points-v2"; {gpu_opps} }};
  }};
  gmu@3d6a000 {{ reg=<0 {core['base']} 0 {core['bytes']} 0 0x3d50000 0 0x10000 0 0xb280000 0 0x10000>;
   reg-names="gmu","rscc","gmu_pdc"; operating-points-v2=<&mopp>;
   mopp: opp-table {{ compatible="operating-points-v2"; {gmu_opps} }};
  }};
 }};
}};
'''
    (out/'build/adreno-firmware/sony.dts').write_text(dts)
    subprocess.run(['dtc','-I','dts','-O','dtb','-o',str(out/'build/adreno-firmware/sheng.dtb'),str(out/'build/adreno-firmware/sony.dts')],check=True,capture_output=True)
    platform=dict(resources=dict(gpu=dict(node='/soc/gpu@3d00000',ranges=[gw['kgsl_3d0_reg_memory'],gw['cx_misc']]),
                                 gmu=dict(node='/soc/gmu@3d6a000',ranges=[core,gw['rscc'],mw['gmu_pdc']]),
                                  smmu=dict(ranges=[sw['base']])),gpu_streams=gpu_streams,gmu_stream=gmu_stream,
                  live_dtb_sha256=hashlib.sha256(LIVE.read_bytes()).hexdigest(),common_opps=common)
    (out/'build/adreno-firmware/sheng-platform.json').write_text(json.dumps(platform,indent=2)+'\n')
    # Use Sony ZAP, not the reference tablet's signed binary. GMU is identical
    # in the two independently discovered Sony firmware repositories.
    discovered=json.loads((BASE/'sony-gpu-inputs-001/TheMuppets-tree.json').read_text())
    firmware=[]
    for name in ('a740_sqe.fw','gmu_gen70200.bin','a740_zap.mbn'):
        item=next(row for row in discovered['hits'] if row['path'].endswith('/'+name))
        req=urllib.request.Request(item['url'],headers={'User-Agent':'pdx234-port'})
        payload=json.load(urllib.request.urlopen(req,timeout=30));data=base64.b64decode(payload['content'])
        if len(data)!=item['size'] or hashlib.sha1(('blob '+str(len(data))+'\0').encode()+data).hexdigest()!=item['sha']:
            raise ValueError('Sony firmware blob identity')
        key='qcom/sm8550/sheng/a740_zap.mbn' if name=='a740_zap.mbn' else 'qcom/'+name
        dst=out/'.cache/firmware/sheng-gpu'/key;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(data)
        digest=hashlib.sha256(data).hexdigest();pins['firmware']['files'][key]=dict(bytes=len(data),sha256=digest,git_blob_sha1=item['sha'])
        firmware.append(dict(name=name,path=str(dst),sha256=digest,git_blob_sha1=item['sha'],repository=discovered['repo'],tree=discovered['tree']))
    pins['firmware']['repository']='https://github.com/'+discovered['repo']
    pins['firmware']['tree_sha']=discovered['tree']
    pins['board']['repository']='local-retained-Sony-device-tree';pins['board']['commit']=platform['live_dtb_sha256']
    (out/'scripts/data/adreno-inputs.json').write_text(json.dumps(pins,indent=2)+'\n')
    adaptations=[]
    for name in ('prepare-sheng-gmu.py','prepare-sheng-gmu-votes.py','prepare-sheng-gpu-smmu.py'):
        original=(BASE/'sources/sheng/scripts'/name).read_text()
        marker=" subprocess.run([sys.executable,ROOT/'kits/sheng/audit-adreno-platform.py'],check=True,timeout=30)"
        if original.count(marker)!=1:raise ValueError('Upstream platform invocation changed')
        text=original.replace(marker," # Platform inputs were generated above from the hash-recorded Sony live DT.")
        (out/'scripts'/name).write_text(text)
        subprocess.run(['python3','-B',str(out/'scripts'/name)],check=True)
        adaptations.append(dict(name=name,original_sha256=hashlib.sha256(original.encode()).hexdigest(),adapted_sha256=hashlib.sha256(text.encode()).hexdigest()))
    result=dict(platform=platform,firmware=firmware,generators=adaptations,source='Sony saved live DT and pinned shared catalog',hardware_verified=False,device_operations=False)
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print('PASS Sony GPU inputs',len(common),'common OPPs,',len(firmware),'Sony firmware images')


if __name__=='__main__':main()
