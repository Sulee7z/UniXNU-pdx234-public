#!/usr/bin/env python3
"""Resolve one saved current guest stop against its own linked native symbols."""
import argparse
import bisect
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'ci/XnuPrelink'))
from kc_image import Image
sys.path.insert(0,str(ROOT/'ci/qemu'))
from d27_user_memory import kernel_pointer_view

def main():
    p=argparse.ArgumentParser();p.add_argument('--run',type=Path,required=True);a=p.parse_args()
    inp=json.loads((a.run/'inputs.json').read_text());obs=json.loads((a.run/'observation/gdb-stop.json').read_text())
    data=(a.run/'esp/EFI/UniXNU/Payloads/kernel.macho').read_bytes();collection=Image(data)
    image=Image(data,collection.entries['com.apple.kernel'][1]);symbols=image.symbols();addresses=sorted(symbols)
    tcr=int(obs['system_registers']['TCR_EL1'],16)
    def resolve(value):
        address=kernel_pointer_view(int(value,16),tcr)
        index=bisect.bisect_right(addresses,address)-1
        return dict(address=hex(address),names=symbols[addresses[index]],offset=address-addresses[index]) if index>=0 else dict(address=hex(address))
    result=dict(pc=resolve(obs['pc']),lr=resolve(obs['x30']),process=obs.get('actual_process'),
                process_count=len(obs.get('process_list',[])),frames=[resolve(frame['lr']) for frame in obs.get('frame_chain',[])])
    for reg in ('x0','x1','x2','x3','x4','x5'):
        address=int(obs[reg],16)
        try:
            text=image.cstring(address)
            if text:result[reg+'_string']=text
        except ValueError:pass
    result['argument_memory']=obs.get('argument_memory')
    (a.run/'stop-analysis.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))

if __name__=='__main__':main()
