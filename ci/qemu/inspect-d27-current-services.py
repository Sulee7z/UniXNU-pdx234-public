#!/usr/bin/env python3
"""Resolve real current UI service-wait frames with bounded original-cache slices."""
import argparse
import bisect
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
ROOT=Path(__file__).resolve().parents[2]
EXTRACT=ROOT/'evidence/photo057-widget-trap/extract_original.py'

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--run',type=Path,required=True)
    p.add_argument('--snapshot',type=Path,help='Explicit saved live/non-atomic phase snapshot')
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    obs=json.loads((a.snapshot or a.run/'observation/gdb-stop.json').read_text());snap=obs['ui_thread_snapshots']
    index=json.loads((BASE/'photo026-cache-002/index.json').read_text())
    images=index['images']
    bits=obs['user_table_geometry']['address_bits'] if a.snapshot else 64-(int(obs['system_registers']['TCR_EL1'],16)&63)
    mask=(1<<bits)-1
    targets=[]
    for proc in snap['processes']:
        if proc['process']['name'] not in ('SpringBoard','backboardd','chronod','liveactivitiesd','lsd'):continue
        slide=proc.get('cache_slide')
        if slide is None:continue
        # At most the first eight real UI threads and their existing bounded frames.
        for thread in proc['threads'][:16]:
            pointers=[thread.get('user_pc'),thread.get('user_lr')]+[f['lr'] for f in thread.get('user_frames',[])]
            for raw in pointers:
                if not raw:continue
                va=(int(raw,0)&mask)-slide
                found=[image for image in images if image['va']<=va<image['va']+image['size']]
                if len(found)!=1:continue
                image=found[0]
                if not any(word in image['path'] for word in ('CoreServices','ControlCenterServices','Foundation.framework','SessionCore','SessionPush','CarKit','BoardServices','ActivityKit','InstalledContentLibrary','libdispatch','libsystem_c')):continue
                targets.append(dict(process=proc['process']['name'],thread_id=thread['thread_id'],raw=raw,unslid=va,image=image['path'],image_va=image['va']))
    wanted={t['image']:next(image for image in images if image['path']==t['image']) for t in targets}
    if len(wanted)>16:raise ValueError('Bounded service image limit exceeded')
    rows=[]
    for folder in (BASE/'qemu-renderer-d27-001',a.out):
        for batch in sorted(folder.glob('batch-*')):
            if not (batch/'receipt.json').is_file():continue
            receipt=json.loads((batch/'receipt.json').read_text())
            if not receipt.get('original_systemos_readonly') or receipt['main_cache_sha256']!='21d3a213c3a1a62cf37325cebf2335f75cbf1e7a4d9548049c7cee2695903b40':raise ValueError('Wrong original cache slices')
            for i,row in enumerate(receipt['ranges']):
                data=(batch/f'slice-{i:03d}.bin').read_bytes()
                if hashlib.sha256(data).hexdigest()!=row['sha256']:raise ValueError('Original slice changed')
                rows.append((row,data))
    def data(filename,offset,length):
        result=b''
        while len(result)<length:
            at=offset+len(result)
            found=[(row,chunk) for row,chunk in rows if row['file']==filename and row['offset']<=at<row['offset']+row['bytes']]
            if not found:return None
            row,chunk=max(found,key=lambda item:item[0]['offset']+item[0]['bytes'])
            delta=at-row['offset'];result+=chunk[delta:delta+min(length-len(result),len(chunk)-delta)]
        return result
    def location(va,length):
        return next((h['file'],m['offset']+va-m['va']) for h in index['headers'] for m in h['maps'] if m['va']<=va and va+length<=m['va']+m['size'])
    requests=[]
    def request(name,filename,offset,length):
        if data(filename,offset,length) is not None:return
        low=offset&~4095;size=((offset+length+4095)&~4095)-low
        if size>8<<20:raise ValueError('Single original service slice exceeds8MiB')
        requests.append(dict(name=name,file=filename,offset=low,bytes=size))
    local=16384;filename='dyld_shared_cache_arm64e.symbols'
    info=data(filename,local,24)
    if info is None:request('local-info',filename,local,65536)
    metadata={}
    if info:
        nlistoff,nlistcount,stringsoff,stringssize,entriesoff,entrycount=struct.unpack('<6I',info)
        entries=data(filename,local+entriesoff,entrycount*16)
        if entries is None:request('image-entry-table',filename,local+entriesoff,entrycount*16)
        else:
            spec=importlib.util.spec_from_file_location('slice_macho',ROOT/'evidence/photo057-widget-trap/analyze_slices.py')
            analysis=importlib.util.module_from_spec(spec);spec.loader.exec_module(analysis)
            for path,image in wanted.items():
                entry=[(start,count) for off,start,count in struct.iter_unpack('<QII',entries) if off==image['va']-0x180000000]
                if len(entry)!=1:raise ValueError('No unique original local-image entry '+path)
                start,count=entry[0];offset=local+nlistoff+start*16
                nl=data(filename,offset,count*16)
                if nl is None:request(path+' nlist',filename,offset,count*16);continue
                headerfile,headeroff=location(image['va'],16384);header=data(headerfile,headeroff,16384)
                if header is None:request(path+' header',headerfile,headeroff,16384);continue
                meta=analysis.macho(header);f=meta['function_starts'];ff,fo=location(f['va'],f['bytes']);starts=data(ff,fo,f['bytes'])
                if starts is None:request(path+' starts',ff,fo,f['bytes']);continue
                symbols=[]
                boundaries=[];value=shift=0;cursor=image['va']
                for byte in starts:
                    value|=(byte&127)<<shift
                    if byte<128:
                        if not value:break
                        cursor+=value;boundaries.append(cursor);value=shift=0
                    else:shift+=7
                referenced=[]
                for target in [t for t in targets if t['image']==path]:
                    i=bisect.bisect_right(boundaries,target['unslid'])-1
                    if i<0 or i+1>=len(boundaries):continue
                    target.update(function_start=boundaries[i],function_end=boundaries[i+1])
                selected={t['function_start'] for t in targets if t['image']==path and 'function_start' in t}
                for ix,typ,sect,desc,va in struct.iter_unpack('<IBBHQ',nl):
                    if not va or not ix or va not in selected:continue
                    off=local+stringsoff+ix;chunk=data(filename,off,512)
                    if chunk is None:request(path+' symbol-name',filename,off,512);continue
                    name=chunk.split(b'\0')[0].decode('utf-8','replace');symbols.append(dict(name=name,address=va))
                metadata[path]=dict(symbols=symbols)
    # Merge overlapping requested pages and keep the extraction bounded.
    grouped={}
    for req in requests:grouped.setdefault(req['file'],[]).append(req)
    merged=[]
    for file,items in grouped.items():
        for req in sorted(items,key=lambda r:r['offset']):
            if merged and merged[-1]['file']==file and req['offset']<=merged[-1]['offset']+merged[-1]['bytes'] and max(req['offset']+req['bytes'],merged[-1]['offset']+merged[-1]['bytes'])-merged[-1]['offset']<=8<<20:
                merged[-1]['bytes']=max(req['offset']+req['bytes'],merged[-1]['offset']+merged[-1]['bytes'])-merged[-1]['offset']
            else:merged.append(dict(req))
    if merged:
        if sum(r['bytes'] for r in merged)>16<<20:raise ValueError('Original service extraction exceeds16MiB')
        requestfile=a.out/'requests.json';requestfile.write_text(json.dumps(merged,indent=2)+'\n')
        batch=a.out/f'batch-{len(list(a.out.glob("batch-*")))+1:02d}'
        subprocess.run([sys.executable,'-B',str(EXTRACT),'--out',str(batch),'--requests',str(requestfile)],check=True)
        print('Service slices exported; repeat until no missing pages',flush=True);return
    for target in targets:
        symbols=metadata.get(target['image'],{}).get('symbols',[])
        names=[s['name'] for s in symbols if s['address']==target.get('function_start')]
        target['symbols']=names;target['addend']=target['unslid']-target.get('function_start',target['unslid'])
    result=dict(source_run=str(a.run),source_snapshot=str(a.snapshot) if a.snapshot else None,
        snapshot_consistency=obs.get('snapshot_consistency','stopped guest'),
        original_files_modified=False,original_cache_only=True,targets=targets)
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    unique={(t['image'],t['function_start']):t for t in targets if t.get('symbols')}
    print(json.dumps(list(unique.values()),indent=2),flush=True)

if __name__=='__main__':main()
