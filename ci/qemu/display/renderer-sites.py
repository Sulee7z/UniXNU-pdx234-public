#!/usr/bin/env python3
"""Create original-byte-qualified D27 compositor trace sites and bind a plan.

The site manifest is independent of a candidate kernel. --layout-plan and
--kernel/--prelink-report additionally bind it to the coordinator's actual
compiler-qualified process layout and final kernel symbols. Never changes
guest code or registers and never treats an entrypoint as successful drawing.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence',type=Path,default=BASE/'qemu-renderer-d27-001')
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--mode',choices=('frame-path','gates'),default='frame-path')
    p.add_argument('--layout-plan',type=Path)
    p.add_argument('--kernel',type=Path)
    p.add_argument('--prelink-report',type=Path)
    a=p.parse_args()
    functions=json.loads((a.evidence/'functions.json').read_text())
    byva={f['function_start']:f for f in functions}
    index=json.loads((BASE/'photo026-cache-002/index.json').read_text())
    slices=[]
    for batch in sorted(a.evidence.glob('batch-*')):
        if not (batch/'receipt.json').is_file():continue
        receipt=json.loads((batch/'receipt.json').read_text())
        if (receipt['main_cache_sha256']!='21d3a213c3a1a62cf37325cebf2335f75cbf1e7a4d9548049c7cee2695903b40' or
            not receipt['original_systemos_readonly']):raise ValueError('Wrong original D27 extraction')
        for i,row in enumerate(receipt['ranges']):
            data=(batch/f'slice-{i:03d}.bin').read_bytes()
            if hashlib.sha256(data).hexdigest()!=row['sha256']:raise ValueError('Changed extracted bytes')
            slices.append((row,data))

    def read(va,size):
        filename,offset=next((h['file'],m['offset']+va-m['va']) for h in index['headers'] for m in h['maps']
                             if m['va']<=va and va+size<=m['va']+m['size'])
        for row,data in slices:
            at=offset-row['offset']
            if row['file']==filename and 0<=at and at+size<=len(data):return data[at:at+size]
        raise ValueError(f'Original bytes not exported: {va:x}+{size:x}')

    def site(name,base,delta=0,reads=()):
        parent=byva[base]
        body=read(base,parent['function_bytes'])
        if hashlib.sha256(body).hexdigest()!=parent['sha256']:raise ValueError('Original function hash changed')
        return dict(name=name,address=base+delta,prefix=read(base+delta,16).hex(),max_hits=8,
                    parent_function=dict(name=parent['name'],address=base,length=len(body),sha256=parent['sha256']),
                    memory_reads=[dict(register=reg,offset=offset,size=size,indirect=indirect) for reg,offset,size,indirect in reads])

    # These exact branch encodings are part of the fallback evidence, not
    # inferred from matching symbol names or the community's iPadOS17 result.
    def branch(pc,expected,link=False):
        word=int.from_bytes(read(pc,4),'little')
        if word&0xfc000000!=(0x94000000 if link else 0x14000000):raise ValueError('Expected direct branch')
        offset=word&0x3ffffff
        if offset&0x2000000:offset-=1<<26
        if pc+4*offset!=expected:raise ValueError('D27 fallback branch target changed')
    branch(0x184457640,0x18477c5d0)
    branch(0x18477c5e8,0x18477c34c,True)
    branch(0x18477c624,0x1844570cc)
    if read(0x18477c4a0,4)!=bytes.fromhex('ff0f5fd6'):raise ValueError('Actual software-renderer RETAB changed')
    frames=[
        site('base_render_update',0x18477c5d0,reads=((0,96,8,False),(0,200,16,False))),
        site('software_renderer_return',0x18477c34c,0x154,((0,0,104,False),)),
        site('render_display',0x1844570cc,reads=((1,0,104,False),)),
        site('software_draw_elements',0x1846c6300,reads=((0,16,32,False),(0,2656,16,False))),
    ]
    gates=[
        site('ignore_update',0x18445c17c,reads=((0,696,8,False),(0,816,8,True),(0,30032,80,False),(1,320,32,False))),
        site('can_update',0x184435238,reads=((0,816,8,True),(0,696,8,False),(0,30000,48,False),(0,952,4,False))),
        site('is_ready',0x18441fbac,reads=((0,816,8,True),)),
        site('base_render_update',0x18477c5d0,reads=((0,96,8,False),(0,200,16,False))),
    ]
    manifest=dict(schema='d27-original-compositor-trace-v1',profile='iPhone14,7 D27AP iOS27 24A446',
                  original_main_cache_sha256='21d3a213c3a1a62cf37325cebf2335f75cbf1e7a4d9548049c7cee2695903b40',
                  extraction_index_sha256=sha(BASE/'photo026-cache-002/index.json'),trace_sets={'frame-path':frames,'gates':gates},
                  direct_fallback_branches_verified=True,read_only=True,original_code_modified=False,
                  renderer_presence_verified=True,renderer_runtime_verified=False,springboard_desktop=False)
    if any((a.layout_plan,a.kernel,a.prelink_report)):
        if not all((a.layout_plan,a.kernel,a.prelink_report)):p.error('Supply --layout-plan, --kernel and --prelink-report together')
        plan=json.loads(a.layout_plan.read_text());report=json.loads(a.prelink_report.read_text())
        required=('native_sha256','original_files_modified','main_import_offset','unslid_import','max_slide','cache_uuid','process_layout')
        missing=[key for key in required if key not in plan]
        if missing:raise ValueError('Original D27 observer layout/binding fields missing: '+', '.join(missing))
        if plan['native_sha256']!=report['native_sha256'] or sha(a.kernel)!=report['candidate_sha256']:
            raise ValueError('Compiler process layout does not match selected final kernel')
        if plan['original_files_modified'] is not False:raise ValueError('Original images must be unchanged')
        text=subprocess.check_output(['/usr/lib/llvm-23/bin/llvm-nm','--defined-only',str(a.kernel)],text=True)
        names={m[2]:int(m[1],16) for m in re.finditer(r'^([0-9a-f]+)\s+\S\s+(\S+)$',text,re.M)}
        activation=[names[name] for name in ('_shared_region_check_np','_shared_region_map_and_slide_2_np')]
        for key in ('port_checkpoint','reply_checkpoint','main_display','displays','cas_request_id','original_mode_initializer_sha256'):
            plan.pop(key,None)
        plan.update(mode='user-trace',expected_process='backboardd',process_activation=activation,max_activation_events=2048,
                    query=frames[0]['address'],query_prefix=frames[0]['prefix'],trace_sites=manifest['trace_sets'][a.mode],
                    candidate_sha256=report['candidate_sha256'],purpose='Read-only original D27 QuartzCore composition and gates',
                    d27_compositor_manifest=manifest)
        manifest=plan
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(manifest,indent=2)+'\n')
    print('PASS D27 original compositor fallback branch/code qualification;',a.out)


if __name__=='__main__':main()
