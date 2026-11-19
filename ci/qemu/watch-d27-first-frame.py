#!/usr/bin/env python3
"""Observe actual guest frame counters until first presentation or VM exit."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import socket
import time


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--seconds',type=int,default=7200)
    a=p.parse_args()
    if not 60<=a.seconds<=14400:raise ValueError('Bounded guest observation deadline required')
    run=a.run.resolve();a.out.mkdir(parents=True,exist_ok=False)
    names={name:int(address,16) for name,address in json.loads((run/'symbols.json').read_text()).items()}
    inputs=json.loads((run/'inputs.json').read_text())
    fields=inputs['fields'];deadline=time.monotonic()+a.seconds;count=0
    output=a.out/'samples.jsonl'
    while time.monotonic()<deadline:
        candidates=[]
        for proc in Path('/proc').iterdir():
            if not proc.name.isdecimal():continue
            try:args=(proc/'cmdline').read_bytes().split(b'\0')
            except OSError:continue
            if not args or not args[0].endswith(b'qemu-system-aarch64'):continue
            if not any(('fat:'+str(run/'esp')).encode() in arg for arg in args):continue
            index=args.index(b'-qmp');candidates.append(args[index+1].decode().split('unix:',1)[1].split(',',1)[0])
        if not candidates:
            print(json.dumps(dict(run=str(run),vm_exited=True,first_frame_observed=False,samples=count)),flush=True);return
        if len(candidates)!=1:raise ValueError('Require only the selected actual guest')
        scratch=a.out/'physical.bin';row=dict(time=time.time(),read_only=True,consistency='live/non-atomic')
        try:
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
                sock.settimeout(15);sock.connect(candidates[0]);stream=sock.makefile('rwb',buffering=0);stream.readline()
                def qmp(command,**arguments):
                    if command not in ('qmp_capabilities','query-status','pmemsave','screendump'):raise ValueError('Read-only frame observations only')
                    stream.write((json.dumps(dict(execute=command,arguments=arguments))+'\n').encode())
                    while True:
                        line=stream.readline()
                        if not line:raise RuntimeError('QMP disconnected')
                        reply=json.loads(line)
                        if 'error' in reply:raise RuntimeError(str(reply['error']))
                        if 'return' in reply:return reply['return']
                qmp('qmp_capabilities');row['status']=qmp('query-status')
                uart=(run/'observation/gdb-uart.log').read_text()
                match=re.search(r'kernel +va 0x([0-9A-Fa-f]+) +pa 0x([0-9A-Fa-f]+)',uart)
                if not match:raise ValueError('Actual loader mapping unavailable')
                va,pa=(int(x,16) for x in match.groups())
                def read_scalar(name,width):
                    address=pa+names[name]-va
                    qmp('pmemsave',val=address,size=width,filename=str(scratch))
                    raw=scratch.read_bytes()
                    if len(raw)!=width:raise ValueError('Incomplete actual scalar')
                    return int.from_bytes(raw,'little')
                row['values']={name:read_scalar(name,fields[name]['bytes']) for name in
                    ('_native_legacy_frame_count','_native_legacy_copy_n','_native_legacy_retirement_calls',
                     '_native_legacy_pm_callbacks','_native_virtio_read_failures','_native_virtio_read_requests') if name in fields}
                frames=row['values'].get('_native_legacy_frame_count',0)
                if frames:
                    image=a.out/'first-frame.png';qmp('screendump',filename=str(image),format='png')
                    row.update(first_frame_observed=True,screen=str(image),screen_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),desktop_verified=False)
                    (a.out/'first-frame.json').write_text(json.dumps(row,indent=2)+'\n')
                    print(json.dumps(row,indent=2),flush=True);return
        except (ValueError,RuntimeError,OSError) as error:row['observation_error']=str(error)
        finally:scratch.unlink(missing_ok=True)
        with output.open('a') as stream:stream.write(json.dumps(row)+'\n')
        count+=1
        time.sleep(min(60,max(0,deadline-time.monotonic())))
    print(json.dumps(dict(run=str(run),first_frame_observed=False,observation_deadline=True,samples=count)),flush=True)


if __name__=='__main__':main()
