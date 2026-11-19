#!/usr/bin/env python3
"""Bounded read-only original D27 QuartzCore symbol/code investigation.

Uses the existing APFS Linux extraction helper. All observations are tied to
the original SystemOS cache; no iPadOS17 addresses or renderer flags are used.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
DEVICE = Path(__file__).resolve().parents[3]
EXTRACT = DEVICE / 'evidence/photo057-widget-trap/extract_original.py'


def load(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def disassemble(code,address):
    # Preserve every original address even when an instruction needs a newer
    # ISA decoder. Unknown words remain explicit evidence, never dropped.
    lines=[' '.join(f'0x{byte:02x}' for byte in code[i:i+4]) for i in range(0,len(code),4)]
    result=subprocess.run(['/usr/lib/llvm-23/bin/llvm-mc','--disassemble','--triple=aarch64',
                           '--mattr=+v9.6a,+fullfp16'],input='\n'.join(lines)+'\n',text=True,capture_output=True,check=True)
    unknown={int(v)-1 for v in re.findall(r'<stdin>:(\d+):1: warning: invalid instruction encoding',result.stderr)}
    decoded=iter(line.strip() for line in result.stdout.splitlines() if line.startswith('\t') and line.strip()!='.text')
    output=[]
    for i in range(len(lines)):
        instruction=f'.word 0x{int.from_bytes(code[i*4:i*4+4],"little"):08x}' if i in unknown else next(decoded)
        output.append(f'{address+i*4:016x} {code[i*4:i*4+4].hex()} {instruction}')
    assert next(decoded,None) is None
    return output


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('step',choices=('headers','symbols','names','code','analyze'))
    parser.add_argument('--out',type=Path,default=BASE/'qemu-renderer-d27-001')
    args=parser.parse_args();root=args.out;root.mkdir(parents=True,exist_ok=True)
    index=json.loads((BASE/'photo026-cache-002/index.json').read_text())
    image=next(row for row in index['images'] if row['path']=='/System/Library/Frameworks/QuartzCore.framework/QuartzCore')
    rows=[]
    for batch in sorted(root.glob('batch-*')):
        if not (batch/'receipt.json').is_file():continue
        for i,row in enumerate(json.loads((batch/'receipt.json').read_text())['ranges']):
            rows.append((row,(batch/f'slice-{i:03d}.bin').read_bytes()))

    def data(filename,offset,length):
        for row,content in rows:
            at=offset-row['offset']
            if row['file']==filename and 0<=at and at+length<=len(content):return content[at:at+length]
        return None

    def location(va,length):
        return next((h['file'],m['offset']+va-m['va']) for h in index['headers'] for m in h['maps']
                    if m['va']<=va and va+length<=m['va']+m['size'])

    def getva(va,length):return data(*location(va,length),length)

    requests=[]
    def request(name,filename,offset,length,**extra):
        if data(filename,offset,length) is not None:return
        low=offset&~4095;high=(offset+length+4095)&~4095
        if (filename,low,high-low) in {(r['file'],r['offset'],r['bytes']) for r in requests}:return
        requests.append(dict(name=name,file=filename,offset=low,bytes=high-low,exact_offset=offset,exact_bytes=length,**extra))
    def requestva(name,va,length):request(name,*location(va,length),length,va=va)

    local=16384
    if args.step=='headers':
        requestva('QuartzCore-header',image['va'],16384)
        request('local-symbols-info','dyld_shared_cache_arm64e.symbols',local,65536)
    else:
        analysis=load('slice_analysis',DEVICE/'evidence/photo057-widget-trap/analyze_slices.py')
        header=getva(image['va'],16384);assert header is not None
        metadata=analysis.macho(header)
        info=data('dyld_shared_cache_arm64e.symbols',local,24)
        nlistoff,nlistcount,stringsoff,stringssize,entriesoff,entrycount=struct.unpack('<6I',info)
        entries=data('dyld_shared_cache_arm64e.symbols',local+entriesoff,entrycount*16)
        if entries is None:
            assert entrycount<=16384
            request('local-image-entry-table','dyld_shared_cache_arm64e.symbols',local+entriesoff,entrycount*16)
            requestfile=root/(args.step+'-entries-requests.json')
            requestfile.write_text(json.dumps(requests,indent=2)+'\n')
            batch=root/f'batch-{len(list(root.glob("batch-*")))+1:02d}'
            subprocess.run([sys.executable,str(EXTRACT),'--out',str(batch),'--requests',str(requestfile)],check=True)
            print('Local image entry table exported; repeat',args.step,flush=True)
            return
        # dyld_cache_local_symbols_entry_64 uses the image's shared-region
        # offset as dylibOffset, followed by the nlist range for that image.
        found=[]
        for dylib,start,count in struct.iter_unpack('<QII',entries):
            if dylib==image['va']-0x180000000:found.append((start,count))
        assert len(found)==1,found
        start,count=found[0];assert start+count<=nlistcount
        offset=local+nlistoff+start*16
        if args.step=='symbols':
            request('QuartzCore-local-nlist','dyld_shared_cache_arm64e.symbols',offset,count*16,nlist_count=count)
            requestva('QuartzCore-function-starts',metadata['function_starts']['va'],metadata['function_starts']['bytes'])
        else:
            nl=data('dyld_shared_cache_arm64e.symbols',offset,count*16);assert nl is not None
            if args.step=='names':
                # Common names can be deduplicated into distant string runs.
                # Export only the pages referenced by this image's nlists.
                indices=[s for s,t,sect,d,v in struct.iter_unpack('<IBBHQ',nl) if s and v]
                pages=sorted({page for s in indices for page in ((local+stringsoff+s)&~4095,
                                                                (local+stringsoff+s+511)&~4095)})
                spans=[]
                for page in pages:
                    if spans and spans[-1][1]==page and page-spans[-1][0]<(4<<20):spans[-1][1]=page+4096
                    else:spans.append([page,page+4096])
                assert sum(high-low for low,high in spans)<=16<<20
                for i,(low,high) in enumerate(spans):
                    request(f'QuartzCore-local-strings-{i}','dyld_shared_cache_arm64e.symbols',low,high-low)
            else:
                symbols=[]
                for string_index,typ,section,desc,va in struct.iter_unpack('<IBBHQ',nl):
                    if not va:continue
                    raw=data('dyld_shared_cache_arm64e.symbols',local+stringsoff+string_index,512)
                    if raw is None:continue
                    name=raw.split(b'\0')[0].decode(errors='backslashreplace')
                    if any(word in name for word in ('sw_renderer','SWContext','SoftwareRenderer','ignore_update_p',
                        'render_for_time','can_update','is_ready','render_display','create_renderer','IOMFBDisplay',
                        'render_update','framebuffer_swap_end','OGL2SW')):
                        symbols.append(dict(name=name,va=va,type=typ,section=section))
                (root/'symbols.json').write_text(json.dumps(symbols,indent=2)+'\n')
                starts=getva(metadata['function_starts']['va'],metadata['function_starts']['bytes'])
                assert starts is not None
                boundaries=[];value=shift=0;cursor=image['va']
                for byte in starts:
                    value|=(byte&127)<<shift
                    if byte<128:
                        if not value:break
                        cursor+=value;boundaries.append(cursor);value=shift=0
                    else:shift+=7
                chosen=[]
                import bisect
                for symbol in symbols:
                    if any(word in symbol['name'] for word in ('sw_renderer','draw_elements','ignore_update_p','can_update','is_ready',
                        'render_for_time','render_update','render_display','update_framebuffer_locked','SWContextC','ContextC2')):
                        at=bisect.bisect_right(boundaries,symbol['va'])-1
                        if at<0 or at+1>=len(boundaries):continue
                        low,high=boundaries[at:at+2]
                        if not 0<high-low<=65536:continue
                        row=dict(symbol,function_start=low,function_end=high,function_bytes=high-low)
                        chosen.append(row);requestva(symbol['name'],low,high-low)
                        if args.step=='analyze':
                            code=getva(low,high-low)
                            if code is None:continue
                            row['sha256']=hashlib.sha256(code).hexdigest()
                            (root/(f'{low:x}.asm')).write_text('\n'.join(disassemble(code,low))+'\n')
                (root/'functions.json').write_text(json.dumps(chosen,indent=2)+'\n')
                print(json.dumps([dict(name=r['name'],va=hex(r['va']),bytes=r['function_bytes'],sha256=r.get('sha256'))
                                  for r in chosen if 'block_invoke' not in r['name'] and '__function' not in r['name']],indent=2))
    (root/(args.step+'-requests.json')).write_text(json.dumps(requests,indent=2)+'\n')
    if requests:
        batch=root/f'batch-{len(list(root.glob("batch-*")))+1:02d}'
        print(f'Extracting {len(requests)} original ranges, {sum(r["bytes"] for r in requests)} bytes',flush=True)
        subprocess.run([sys.executable,str(EXTRACT),'--out',str(batch),'--requests',str(root/(args.step+'-requests.json'))],check=True)
    print('Done',args.step,'D27 original QuartzCore',hex(image['va']),flush=True)


if __name__=='__main__':main()
