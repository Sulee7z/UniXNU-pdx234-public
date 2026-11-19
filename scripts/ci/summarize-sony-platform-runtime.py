#!/usr/bin/env python3
"""Summarize an already decoded handset log without device I/O or inferred FPS."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'ci'))
from platform067.runtime import summarize


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--decoded',type=Path,required=True,help='One boot directory with header/msgbuf/slots text')
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    if args.out.exists():raise ValueError('Preserve previous runtime report')
    files=[args.decoded/name for name in ('header.txt','slots.txt','msgbuf.txt')]
    for path in files:
        if not path.is_file() or path.stat().st_size>64*1024**2:raise ValueError('Missing or oversized decoded input: '+str(path))
    header={}
    for line in files[0].read_text().splitlines():
        key,sep,value=line.partition('=')
        if sep:
            if key in header:raise ValueError('Duplicate boot header field')
            header[key]=value
    if header.get('magic')!='SHLOG001':raise ValueError('Not a decoded UniXNU handset boot log')
    # Texts have distinct capture roles; do not deduplicate differing observations
    # or count their overlapping tail as unique events.
    result=dict(boot_header=header,sections={},sources={},device_operations=False)
    for path in files:
        raw=path.read_bytes();result['sources'][str(path)]=hashlib.sha256(raw).hexdigest()
        if path.name!='header.txt':result['sections'][path.name]=summarize(raw.decode(errors='replace'))
    result.update(hardware_test_result=True,all_features_accepted=False,
        limits='Boot header and msgbuf can reflect different snapshot times. Counts are per section and may overlap.')
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,indent=2)+'\n')
    summary=dict(tag=header.get('tag'),boot_id=header.get('boot_id'),
        counts={key:value['line_counts'] for key,value in result['sections'].items()},
        rate_samples=sum(len(v['rate_samples']) for v in result['sections'].values()),
        touch=result['sections']['msgbuf.txt']['touch_last_sample'],panel_refresh_verified=False)
    print(json.dumps(summary,indent=2))


if __name__=='__main__':main()
