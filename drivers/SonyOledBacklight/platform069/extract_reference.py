#!/usr/bin/env python3
"""Extract indexed Sony clock/regulator references into a new audit directory."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile

ARCHIVE=Path('/mnt/f/UniXNU-Port-artifacts/source-archives/67.2.A.3.141.tar_.bz2')
INDEX=Path('/mnt/g/UniXNU-Port/references/xperia-67.2.A.3.141-hardware/archive-index.json')
PREFIX='yodo-1.2.0-rel/kernel_platform/msm-kernel/'
FILES=['drivers/clk/qcom/dispcc-kalama.c','drivers/clk/qcom/clk-branch.c','drivers/clk/qcom/clk-regmap.c',
       'drivers/clk/qcom/gdsc.c','drivers/regulator/rpmh-regulator.c','drivers/clk/qcom/gcc-kalama.c',
       'include/dt-bindings/clock/qcom,dispcc-kalama.h']
def sha(p):
    with p.open('rb') as s:return hashlib.file_digest(s,'sha256').hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',required=True,type=Path);a=p.parse_args()
    a.out.mkdir(parents=True,exist_ok=False)
    index=json.loads(INDEX.read_text());wanted={PREFIX+n for n in FILES};rows={r['path']:r for r in index if r['path'] in wanted}
    if len(rows)!=len(wanted):raise ValueError('Incomplete indexed files '+repr(wanted-rows.keys()))
    found=[]
    with tarfile.open(ARCHIVE,'r|bz2') as archive:
        for member in archive:
            if member.name not in rows:continue
            if not member.isfile() or member.size!=rows[member.name]['bytes']:raise ValueError('Member/index mismatch')
            target=a.out/Path(member.name).name;target.write_bytes(archive.extractfile(member).read())
            found.append(dict(member=member.name,path=str(target),bytes=member.size,sha256=sha(target)))
            if len(found)==len(wanted):break
    if len(found)!=len(wanted):raise ValueError('Incomplete extraction')
    result=dict(archive=str(ARCHIVE),archive_sha256_from_prior_provenance='cc91361a2aaec52b94ef2f9da29fb489e02fd8383bb12535446fc6945bf659da',
                archive_rehashed=False,index=str(INDEX),index_sha256=sha(INDEX),files=found,reference_only=True)
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print('Extracted indexed clock/regulator files',len(found))
if __name__=='__main__':main()
