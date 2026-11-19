#!/usr/bin/env python3
"""Report the first unmapped call of an experimental fileset image.

Official prelink rules: strict emission stops on missing mappings; --allow-missing
exists only to keep bring-up moving, unmatched calls branch to
unixnu_fileset_unmapped, and reviewed fixture anchors plus the JSON report are the
supported way to close each gap. This probe reads which import slot was used, so
the next reviewed identity can be written from evidence instead of guessing.

At the stub, x17 still holds the thunk's slot address and x16 the stub itself
(`adrp x17; add x17; ldr x16,[x17]; braa x16,x17`). The same slot in the original
collection names the function the retained kext asked for.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def sha256(path):
    with path.open('rb') as source:return hashlib.file_digest(source,'sha256').hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel',required=True,type=Path)
    parser.add_argument('--original',required=True,type=Path)
    parser.add_argument('--esp',required=True,type=Path)
    parser.add_argument('--control',required=True,type=Path,help='Directory holding the audited gdb-stop.py')
    parser.add_argument('--sealer',required=True,type=Path)
    parser.add_argument('--work',required=True,type=Path)
    parser.add_argument('--firmware',default='/usr/share/AAVMF/AAVMF_CODE.fd')
    parser.add_argument('--timeout',type=int,default=90)
    args=parser.parse_args()
    repo=Path(__file__).resolve().parents[2]
    project=repo.parents[1]
    sys.path.insert(0,str(project/'references/pdx234-XnuPrelink-20261108'))
    from kc_image import Image
    import os
    import tomllib

    args.work.mkdir(parents=True,exist_ok=True)
    esp=args.esp.resolve()
    payload=esp/'EFI/UniXNU/Payloads/kernel.macho'
    payload.write_bytes(args.kernel.read_bytes())
    boot_args=tomllib.loads((esp/'EFI/UniXNU/unixnu.toml').read_text())['entry'][0]['args']
    env=dict(**__import__('os').environ,UNIXNU_XNU_ARCH='arm64e',UNIXNU_IOS_VERSION='27.0')
    seal=[sys.executable,'-B',str(args.sealer),str(payload),'--kernel-args',boot_args]
    sealed=subprocess.run(seal,env=env,capture_output=True,text=True)
    if sealed.returncode:
        sys.exit('POST seal failed: '+sealed.stdout[-800:]+sealed.stderr[-800:])

    data=payload.read_bytes();cache=Image(data);member=Image(data,cache.entries['com.apple.kernel'][1])
    names={n:a for a,values in member.symbols().items() for n in values}
    stub=names['_unixnu_fileset_unmapped']
    command=[sys.executable,'-B',str(args.control/'gdb-stop.py'),hex(stub),'--esp',str(esp),
             '--kernel',str(payload),'--fixture',str(args.work),'--gic-version','3','--qemu-memory-mib','4096',
             '--system-registers','--firmware',args.firmware,'--timeout',str(args.timeout)]
    (args.work/'inputs.json').write_text(json.dumps({'command':command,'kernel_sha256':sha256(payload),
        'stub':hex(stub),'boot_args':boot_args},indent=2)+'\n')
    run=subprocess.run(command,capture_output=True,text=True,env=env)
    report=json.loads((args.work/'gdb-stop.json').read_text()) if (args.work/'gdb-stop.json').exists() else {}
    result={'stub':hex(stub),'stopped_at_stub':report.get('pc')==hex(stub),
            'timed_out':report.get('bounded_timeout_interrupted',None),'exit_code':run.returncode}
    if result['stopped_at_stub']:
        slot=int(report['x17'],16)
        original=Image(args.original.read_bytes())
        fix=original.fixups().get(slot)
        owner=None
        for name,(_,at) in original.entries.items():
            entry=Image(original.data,at)
            if any(s['va']<=slot<s['va']+s['size'] for s in entry.segments):owner=name;break
        target=fix[0] if fix else None
        result.update({'slot':hex(slot),'owner':owner,'original_target':hex(target) if target else None,
                       'native_import_value':hex(int(report['x16'],16)&~0xffff000000000000) if report.get('x16') else None,
                       'caller':report.get('x30')})
        if target:
            kernel=Image(original.data,original.entries['com.apple.kernel'][1])
            starts=sorted(kernel.function_starts())
            from bisect import bisect_right
            i=bisect_right(starts,target)-1
            head=starts[i] if i>=0 else None
            end=starts[i+1] if i+1<len(starts) else head
            if head is not None:
                result.update({'target_function':hex(head),'offset_in_function':target-head,
                               'function_bytes':end-head,
                               'function_sha256':hashlib.sha256(kernel.read(head,end-head)).hexdigest()})
    text=json.dumps(result,indent=2)+'\n'
    (args.work/'probe.json').write_text(text)
    print(text,end='')
    raise SystemExit(0 if result['stopped_at_stub'] else 1)


if __name__=='__main__':main()
