#!/usr/bin/env python3
"""Extract only extra SDE timing references; reuse display owner's DSI reference read-only."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile

ARCHIVE=Path('/mnt/f/UniXNU-Port-artifacts/source-archives/67.2.A.3.141.tar_.bz2')
INDEX=Path('/mnt/g/UniXNU-Port/references/xperia-67.2.A.3.141-hardware/archive-index.json')
ROOT='yodo-1.2.0-rel/vendor/qcom/opensource/display-drivers/msm/sde/'
NAMES=('sde_encoder_phys_cmd.c','sde_hw_intf.c','sde_hw_pingpong.c','sde_hw_dsc.c','sde_hw_ctl.c')


def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    a.out.mkdir(parents=True,exist_ok=False)
    rows=json.loads(INDEX.read_text())
    wanted={r['path']:r['bytes'] for r in rows if r['path'] in {ROOT+n for n in NAMES}}
    if len(wanted)!=len(NAMES):raise ValueError('Incomplete Sony index')
    # The display-owner reference receipt hashes this exact immutable archive.
    provenance=Path('/mnt/f/UniXNU-Port-artifacts/platform067-20261118/backlight-reference/provenance.json')
    receipt=json.loads(provenance.read_text())
    if receipt['archive']!=str(ARCHIVE) or receipt['archive_sha256']!='cc91361a2aaec52b94ef2f9da29fb489e02fd8383bb12535446fc6945bf659da':
        raise ValueError('Sony archive provenance differs')
    files=[]
    with tarfile.open(ARCHIVE,'r|bz2') as stream:
        for member in stream:
            if member.name not in wanted:continue
            if not member.isfile() or member.size!=wanted[member.name]:raise ValueError('Indexed size mismatch')
            dst=a.out/Path(member.name).name
            dst.write_bytes(stream.extractfile(member).read())
            files.append(dict(member=member.name,path=str(dst),bytes=member.size,sha256=sha(dst)))
            print(member.name,member.size,flush=True)
            if len(files)==len(wanted):break
    if len(files)!=len(wanted):raise ValueError('Missing SDE reference')
    result=dict(reference_only=True,archive=str(ARCHIVE),archive_sha256_from_prior_hash=receipt['archive_sha256'],
                archive_rehashed_this_run=False,prior_provenance=str(provenance),prior_provenance_sha256=sha(provenance),
                index_sha256=sha(INDEX),files=files)
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':main()
