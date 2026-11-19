#!/usr/bin/env python3
"""Summarize saved real UI boundaries using original D27 image/function spans."""
import argparse
import importlib.util
import json
from pathlib import Path

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
ROOT=Path(__file__).resolve().parents[2]

def main():
    p=argparse.ArgumentParser();p.add_argument('--run',type=Path,required=True);a=p.parse_args()
    obs=json.loads((a.run/'observation/gdb-stop.json').read_text())
    result=json.loads((a.run/'result.json').read_text())
    index=json.loads((BASE/'photo026-cache-002/index.json').read_text())
    images=index['images'];snap=obs.get('ui_thread_snapshots',{})
    bits=64-(int(obs['system_registers']['TCR_EL1'],16)&63);mask=(1<<bits)-1
    def resolve(raw,slide):
        address=(int(raw,0)&mask)-slide
        found=[item for item in images if item['va']<=address<item['va']+item['size']]
        return dict(raw=raw,unslid=hex(address),image=found[0]['path'] if len(found)==1 else None,
                    image_offset=address-found[0]['va'] if len(found)==1 else None)
    rows=[]
    for process in snap.get('processes',[]):
        if process['process']['name'] not in ('SpringBoard','backboardd','chronod','liveactivitiesd','launchd'):continue
        row=dict(process=process['process'],complete=process['complete'],threads=[],cache_slide=process.get('cache_slide'))
        rows.append(row);slide=process.get('cache_slide')
        if slide is None:continue
        for thread in process['threads']:
            row['threads'].append(dict(thread_id=thread['thread_id'],state=thread['state'],
                pc=resolve(thread['user_pc'],slide) if thread.get('user_pc') else None,
                lr=resolve(thread['user_lr'],slide) if thread.get('user_lr') else None,
                arguments=thread.get('user_arguments'),frames=[resolve(item['lr'],slide) for item in thread.get('user_frames',[])],
                error=thread.get('snapshot_error')))
    out=dict(process_count=len(result.get('processes',[])),elapsed_seconds=result['elapsed_seconds'],
             requested_host_stop=(a.run/'requested-observation-stop.json').exists(),
             pc=result['pc'],kernel_log_error=obs.get('kernel_log_error'),ui=rows,desktop_verified=False)
    (a.run/'ui-summary.json').write_text(json.dumps(out,indent=2)+'\n')
    spec=importlib.util.spec_from_file_location('classify',ROOT/'ci/qemu/display/classify-renderer.py')
    classifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(classifier)
    functions=json.loads((BASE/'qemu-renderer-d27-001/functions.json').read_text())
    classified=classifier.classify(snap,functions,bits)
    (a.run/'renderer-classification.json').write_text(json.dumps(classified,indent=2)+'\n')
    compact=dict(process_count=out['process_count'],elapsed_seconds=out['elapsed_seconds'],requested_host_stop=out['requested_host_stop'],
        kernel_log_error=out['kernel_log_error'],ui=[dict(process=item['process'],threads=len(item['threads']),
        main=item['threads'][0] if item['threads'] else None) for item in rows],renderer_hits=[item for item in classified['processes'] if item['observed_functions']])
    print(json.dumps(compact,indent=2))

if __name__=='__main__':main()
