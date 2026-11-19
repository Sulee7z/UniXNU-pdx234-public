#!/usr/bin/env python3
"""Send one actual bounded touch/Home action to the explicitly selected guest."""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import struct
import time


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--action',choices=('tap','unlock-swipe','home'),required=True)
    a=p.parse_args();run=a.run.resolve();matches=[]
    for proc in Path('/proc').iterdir():
        if not proc.name.isdecimal():continue
        try:args=(proc/'cmdline').read_bytes().split(b'\0')
        except OSError:continue
        if not args or not args[0].endswith(b'qemu-system-aarch64'):continue
        if not any(('fat:'+str(run/'esp')).encode() in value for value in args):continue
        if b'virtio-tablet-device' not in args or b'virtio-keyboard-device' not in args:
            raise ValueError('Actual QEMU input devices must be attached')
        at=args.index(b'-qmp');target=args[at+1].decode().split('unix:',1)[1].split(',',1)[0]
        matches.append((int(proc.name),target))
    if len(matches)!=1:raise ValueError('Require exactly the selected virtual guest')
    a.out.mkdir(parents=True,exist_ok=False)
    record=dict(qemu_pid=matches[0][0],action=a.action,started=time.time(),
                source='Actual QMP input events through the attached VirtIO devices',
                guest_memory_or_register_writes=False,device_operations=False,events=[])
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
        sock.settimeout(15);sock.connect(matches[0][1]);stream=sock.makefile('rwb',buffering=0);stream.readline()
        def qmp(command,**arguments):
            if command not in ('qmp_capabilities','query-status','screendump','input-send-event','send-key'):
                raise ValueError('Only bounded input and screen observations are permitted')
            stream.write((json.dumps(dict(execute=command,arguments=arguments))+'\n').encode())
            while True:
                reply=json.loads(stream.readline())
                if 'error' in reply:raise RuntimeError(str(reply['error']))
                if 'return' in reply:return reply['return']
        qmp('qmp_capabilities');record['status']=qmp('query-status')
        before=a.out/'before.png';qmp('screendump',filename=str(before),format='png')
        raw=before.read_bytes()
        if raw[:8]!=b'\x89PNG\r\n\x1a\n':raise ValueError('Actual QMP PNG required')
        width,height=struct.unpack_from('>II',raw,16);record['screen_size']=[width,height]
        def position(x,y):
            return [dict(type='abs',data=dict(axis='x',value=round(x*32767/(width-1)))),
                    dict(type='abs',data=dict(axis='y',value=round(y*32767/(height-1))))]
        def button(down):return dict(type='btn',data=dict(button='left',down=down))
        def send(events):
            qmp('input-send-event',events=events)
            record['events'].append(dict(time=time.time(),events=events))
        if a.action=='home':
            qmp('send-key',keys=[dict(type='qcode',data='home')],**{'hold-time':100})
        else:
            x=(width-1)/2;y0=(height-2 if a.action=='unlock-swipe' else (height-1)/2)
            try:
                send(position(x,y0)+[button(True)])
                if a.action=='unlock-swipe':
                    for step in range(1,17):
                        time.sleep(0.05)
                        send(position(x,y0+((height-1)*0.2-y0)*step/16))
                else:time.sleep(0.15)
            finally:
                send([button(False)])
        after=a.out/'after.png';qmp('screendump',filename=str(after),format='png')
    record.update(finished=time.time(),before_sha256=hashlib.sha256(before.read_bytes()).hexdigest(),
                  after_sha256=hashlib.sha256(after.read_bytes()).hexdigest(),desktop_verified=False)
    (a.out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))


if __name__=='__main__':main()
