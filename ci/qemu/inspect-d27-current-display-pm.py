#!/usr/bin/env python3
"""Read exact final PM call fixups and compare them with current native names."""
import argparse
import bisect
import json
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'ci/XnuPrelink'))
from kc_image import Image

def main():
    p=argparse.ArgumentParser();p.add_argument('--kernel',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();raw=a.kernel.read_bytes();collection=Image(raw);native=Image(raw,collection.entries['com.apple.kernel'][1])
    symbols=native.symbols();byname={name:address for address,names in symbols.items() for name in names};addresses=sorted(symbols)
    table=byname['__ZTV19NativeLegacyDisplay'];fixups=collection.fixups();result={}
    for name,offset in (('PMinit',0x480),('PMstop',0x488),('joinPMtree',0x490),('registerPowerDriver',0x498)):
        site=table+16+offset;target,*pac=fixups[site]
        index=bisect.bisect_right(addresses,target)-1
        result[name]=dict(site=hex(site),target=hex(target),native_names=symbols.get(target),nearest=symbols[addresses[index]],offset=target-addresses[index],pac=pac)
    a.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))

if __name__=='__main__':main()
