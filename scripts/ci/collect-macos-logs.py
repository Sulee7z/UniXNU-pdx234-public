#!/usr/bin/env python3
"""Resolve the official output directory and publish only redacted text logs."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sys


def selected_work(mainline):
    sys.path.insert(0,str(mainline/'scripts'))
    from unixnu.cli import parser
    from unixnu.config import Context
    options=parser().parse_args(['status','--json','-D',os.environ['DEVICE_DIR'],
                               '--local-module','kit:XnuPrelink='+os.environ['COMPONENT_DIR']])
    return Context(options).work


def redact(text):
    for key in ['GITHUB_TOKEN','GH_TOKEN','UNIXNU_UNIQUE_CHIP_ID']:
        value=os.environ.get(key)
        if value:text=text.replace(value,'***')
    return re.sub(r'https?://[^\s"\']*[?&](?:token|sig|signature|key|X-Amz-Signature)=[^\s"\']*',
                  '***',text,flags=re.I)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mainline',required=True,type=Path)
    parser.add_argument('--destination',type=Path)
    parser.add_argument('--selection-only',action='store_true')
    parser.add_argument('--cleanup',action='store_true')
    args=parser.parse_args()
    mainline=args.mainline.resolve(strict=True)
    if args.cleanup:
        if os.environ.get('GITHUB_ACTIONS')!='true':raise RuntimeError('Cleanup is restricted to the Actions workspace')
        for relative in ['out/ipsw','out/feeds']:
            target=mainline/relative
            if target.is_symlink():raise RuntimeError('Refuse cleanup through an external symlink')
            if target.exists():shutil.rmtree(target)
        return
    if args.selection_only:
        work=selected_work(mainline)
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'],'a') as output:output.write('work='+str(work)+'\n')
        print('Resolved output:',work)
        return
    if args.destination is None:parser.error('--destination is required for log collection')
    args.destination.mkdir(parents=True,exist_ok=True)
    try:work=selected_work(mainline)
    except Exception as error:
        (args.destination/'collection-error.log').write_text(redact(str(error))+'\n')
        return
    paths=list((work/'logs').glob('*.log'))
    paths+=list((work/'tree/build/xnu/fileset-reference').glob('**/*-build.log'))
    # A strict failure preserves its report as kernel/kernel.failed.json; earlier
    # revisions left the same record beside the candidate in a hidden .prelink-*
    # staging directory. Both carry the unresolved targets the next binding pass
    # needs, so collect either layout.
    for name in ['kernel.json','kernel.map.json','kernel.failed.json','kernel.macho.crypto-hmac.json']:
        paths+=list(work.glob('**/'+name))
    paths+=list(work.glob('**/.prelink*/**/kernel.json'))
    copied=[]
    for index,path in enumerate(sorted(set(paths))):
        if not path.is_file():continue
        data=path.read_bytes()
        if b'\0' in data:continue
        name=f'{index:03d}-'+path.name+'.log'
        (args.destination/name).write_text(redact(data.decode('utf-8',errors='replace')))
        copied.append({'source':str(path.relative_to(work)),'log':name})
    (args.destination/'collected-files.log').write_text(json.dumps(copied,indent=2)+'\n')
    print(f'{len(copied)} redacted text diagnostics collected; no binaries')


if __name__=='__main__':main()
