#!/usr/bin/env python3
"""Extract Sony CPU/L3 policy references read-only from the pinned source archive."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile

ROOT='yodo-1.2.0-rel/kernel_platform/msm-kernel/'
NAMES=('drivers/soc/qcom/dcvs/dcvs_epss.c','drivers/soc/qcom/dcvs/memlat.c',
       'drivers/soc/qcom/dcvs/dcvs.c','drivers/interconnect/qcom/osm-l3.c',
       'drivers/cpufreq/qcom-cpufreq-hw.c')
A=Path('/mnt/f/UniXNU-Port-artifacts/source-archives/67.2.A.3.141.tar_.bz2')
INDEX=Path('/mnt/g/UniXNU-Port/references/xperia-67.2.A.3.141-hardware/archive-index.json')


def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    a.out.mkdir(parents=True,exist_ok=False)
    wanted={ROOT+n for n in NAMES};index={r['path']:r['bytes'] for r in json.loads(INDEX.read_text()) if r['path'] in wanted}
    if wanted!=index.keys():raise ValueError('Incomplete Sony index')
    files=[]
    with tarfile.open(A,'r|bz2') as stream:
        for member in stream:
            if member.name not in wanted:continue
            if not member.isfile() or member.size!=index[member.name]:raise ValueError('Invalid indexed source')
            target=a.out/Path(member.name).name;target.write_bytes(stream.extractfile(member).read())
            files.append(dict(member=member.name,path=str(target),bytes=member.size,sha256=sha(target)))
            print(member.name,flush=True)
            if len(files)==len(wanted):break
    if len(files)!=len(wanted):raise ValueError('Missing Sony policy reference')
    result=dict(archive=str(A),archive_sha256_from_prior_reference='cc91361a2aaec52b94ef2f9da29fb489e02fd8383bb12535446fc6945bf659da',
                rehashed_archive_this_run=False,index_sha256=sha(INDEX),reference_only=True,files=files)
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':main()
