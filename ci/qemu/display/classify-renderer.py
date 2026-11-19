#!/usr/bin/env python3
"""Classify genuine UI snapshot frames against qualified original D27 functions.

A stack hit is an observation of the captured call path, not proof that a frame
completed or that the desktop is visible. Cache slide must be present in each
actual process snapshot. PAC is removed from user code-pointer address bits only
for lookup; raw addresses remain in the report. No guest address-space changes.
"""
import argparse
import json
from pathlib import Path

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def classify(snapshot, functions, user_bits):
    if not 25<=user_bits<=48:raise ValueError('Require actual TCR-derived user address width')
    mask=(1<<user_bits)-1
    rows=[]
    for process in snapshot.get('processes',[]):
        slide=process.get('cache_slide')
        if isinstance(slide,str):slide=int(slide,0)
        identity=process.get('process',{})
        row=dict(process=identity,cache_slide=slide,observed_functions=[])
        rows.append(row)
        if slide is None or slide<0 or slide&4095:
            row['error']='Actual process shared-region slide unavailable';continue
        for thread in process.get('threads',[]):
            pointers=[('saved_pc',thread.get('user_pc')),('saved_lr',thread.get('user_lr'))]
            pointers += [('frame_lr',frame.get('lr')) for frame in thread.get('user_frames',[])]
            for kind,raw in pointers:
                if raw is None:continue
                raw_value=int(raw,0) if isinstance(raw,str) else raw
                canonical=raw_value&mask
                # Frame LR names the following instruction. Test that exact
                # address; no nearest-symbol inference outside a function span.
                address=canonical-slide
                for function in functions:
                    if function['function_start']<=address<function['function_end']:
                        row['observed_functions'].append(dict(thread=thread['thread'],kind=kind,raw_pointer=hex(raw_value),
                            canonical=hex(canonical),unslid=hex(address),name=function['name'],
                            offset=address-function['function_start'],function_sha256=function.get('sha256')))
    return dict(schema='d27-compositor-snapshot-classification-v1',read_only=True,processes=rows,
                user_address_bits=user_bits,desktop_verified=False,
                limits='Saved user boundary/stack only; no wait-duration, successful draw, completed swap or desktop claim')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--snapshot',type=Path,required=True)
    p.add_argument('--functions',type=Path,default=BASE/'qemu-renderer-d27-001/functions.json')
    p.add_argument('--user-bits',type=int,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();functions=json.loads(a.functions.read_text())
    if any(not f.get('sha256') for f in functions):raise ValueError('Require the hash-qualified original D27 function manifest')
    result=classify(json.loads(a.snapshot.read_text()),functions,a.user_bits)
    a.out.write_text(json.dumps(result,indent=2)+'\n')
    print('Classified original D27 compositor stack ranges:',a.out)


if __name__=='__main__':main()
