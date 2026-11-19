#!/usr/bin/env python3
"""Stop exactly one owned observation VM for the connected GDB capture."""
import argparse
import json
from pathlib import Path
import socket

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',type=Path,required=True)
    p.add_argument('--reason',default='Save this owned guest checkpoint and its actual process/PM/framebuffer state')
    a=p.parse_args();run=a.run.resolve();matches=[]
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal():continue
        try:values=(entry/'cmdline').read_bytes().split(b'\0')
        except OSError:continue
        if not values or not values[0].endswith(b'qemu-system-aarch64'):continue
        if not any(('fat:'+str(run/'esp')).encode() in item for item in values):continue
        at=values.index(b'-qmp');target=values[at+1].decode().split('unix:',1)[1].split(',',1)[0]
        matches.append((int(entry.name),target))
    if len(matches)!=1:raise ValueError('Require exactly the explicitly selected running guest')
    pid,target=matches[0]
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
        sock.settimeout(10);sock.connect(target);stream=sock.makefile('rwb',buffering=0);stream.readline()
        def send(command):
            if command not in ('qmp_capabilities','query-status','stop'):raise ValueError('Debugger stop only')
            stream.write((json.dumps(dict(execute=command))+'\n').encode())
            while True:
                reply=json.loads(stream.readline())
                if 'error' in reply:raise RuntimeError(str(reply))
                if 'return' in reply:return reply['return']
        send('qmp_capabilities');before=send('query-status');send('stop')
    result=dict(qemu_pid=pid,host_debugger_stop_requested=True,prior_status=before,
                guest_memory_or_register_values_written=False,reason=a.reason)
    (run/'requested-observation-stop.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))

if __name__=='__main__':main()
