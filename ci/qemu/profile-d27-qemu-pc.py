#!/usr/bin/env python3
"""Sample the selected running guest's actual PC without stopping or steering it."""
import argparse
import bisect
from collections import Counter
import json
from pathlib import Path
import re
import socket
import time
import sys


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--samples',type=int,default=256)
    a=p.parse_args()
    if not 16<=a.samples<=1024:raise ValueError('Bounded PC sample count required')
    run=a.run.resolve();matches=[]
    for proc in Path('/proc').iterdir():
        if not proc.name.isdecimal():continue
        try:args=(proc/'cmdline').read_bytes().split(b'\0')
        except OSError:continue
        if not args or not args[0].endswith(b'qemu-system-aarch64'):continue
        if not any(('fat:'+str(run/'esp')).encode() in arg for arg in args):continue
        at=args.index(b'-qmp');matches.append(args[at+1].decode().split('unix:',1)[1].split(',',1)[0])
    if len(matches)!=1:raise ValueError('Require exactly the selected running guest')
    symbols=json.loads((run/'symbols.json').read_text())
    ordered=sorted((int(address,16),name) for name,address in symbols.items())
    addresses=[address for address,_ in ordered]
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'XnuPrelink'))
    from kc_image import Image
    collection=Image((run/'esp/EFI/UniXNU/Payloads/kernel.macho').read_bytes())
    executable=[]
    for identifier,(_,at) in collection.entries.items():
        image=Image(collection.data,at)
        for section in image.sections:
            if section['segment']=='__TEXT_EXEC':executable.append((section['va'],section['va']+section['size'],identifier))
    a.out.mkdir(parents=True,exist_ok=False)
    events=[];counts=Counter()
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
        sock.settimeout(10);sock.connect(matches[0]);stream=sock.makefile('rwb',buffering=0);stream.readline()
        def qmp(command,**arguments):
            if command not in ('qmp_capabilities','human-monitor-command'):raise ValueError('Read-only profile commands required')
            if arguments and arguments!={'command-line':'info registers'}:raise ValueError('Register reads only')
            stream.write((json.dumps(dict(execute=command,arguments=arguments))+'\n').encode())
            while True:
                line=stream.readline()
                if not line:raise RuntimeError('QMP disconnected')
                reply=json.loads(line)
                if 'error' in reply:raise RuntimeError(str(reply['error']))
                if 'return' in reply:return reply['return']
        qmp('qmp_capabilities');start=time.monotonic()
        for _ in range(a.samples):
            text=qmp('human-monitor-command',**{'command-line':'info registers'})
            match=re.search(r'\bPC=([0-9a-fA-F]+)',text)
            if not match:raise ValueError('QEMU omitted actual PC')
            pc=int(match[1],16);row=dict(elapsed=time.monotonic()-start,pc=hex(pc))
            if pc>=0xfffffff000000000:
                owner=next((identifier for low,high,identifier in executable if low<=pc<high),None)
                row['image']=owner
                if owner=='com.apple.kernel':
                    at=bisect.bisect_right(addresses,pc)-1
                    row.update(symbol=ordered[at][1],offset=pc-addresses[at]);counts[row['symbol']]+=1
                else:counts[owner or 'unresolved kernel PC']+=1
            else:counts['user EL0']+=1
            events.append(row);time.sleep(0.01)
    report=dict(source='Actual running guest PC observations',read_only=True,guest_stopped=False,
        consistency='live/non-atomic',events=events,counts=counts.most_common(),elapsed=time.monotonic()-start,
        limits='Periodic PC observations are approximate; one sample does not establish a prolonged wait')
    (a.out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(samples=len(events),elapsed=report['elapsed'],counts=report['counts']),indent=2))


if __name__=='__main__':main()
