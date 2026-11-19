#!/usr/bin/env python3
"""Relink physical058 with the qualified generic PM and three upstream repairs."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
sys.path.insert(0,str(ROOT/'ci'))
from compile_dependencies import valid
from native_source_overlays import validate_overlays
from qemu.workloop_event_classification import adapt_source as adapt_pm


def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    if shutil.disk_usage('/mnt/g').free<8*1024**3:raise ValueError('G reserve below8GiB')
    original=BASE/'native-first-frame-058-001'
    before=json.loads((original/'result.json').read_text())
    if sha(original/'native.macho')!=before['native_sha256'] or before['native_sha256']!='2ce2ed908371689c5d41e4da9c2cf8d23c96450084c91718aaa5dc440c9ff1e8':
        raise ValueError('Require the exact full physical058 native')
    validate_overlays(before,sha)
    parity_dir=BASE/'qemu-current-20261118-017'
    parity=json.loads((parity_dir/'native/result.json').read_text())
    records=parity['official_upstream_parity']['source_and_object_hashes']
    for unit,row in records.items():
        for path,digest in ((row['original_source'],row['original_sha256']),
                            (row['input_source'],row['input_source_sha256']),
                            (row['adapted_source'],row['adapted_sha256']),
                            (row['object'],row['object_sha256']),
                            (row['dependency_receipt'],row['dependency_sha256'])):
            if sha(path)!=digest:raise ValueError('Qualified upstream source/object differs: '+unit)
        if not valid(json.loads(Path(row['dependency_receipt']).read_text())):
            raise ValueError('Upstream compile dependencies differ: '+unit)
    pm_path=BASE/'qemu-current-20261117-010/classification-qualification.json'
    pm=json.loads(pm_path.read_text())
    obj=Path(pm['object']);src=obj.with_name('IOWorkLoop.cpp')
    baseline_plan=json.loads((BASE/'native-screen007-055-001/plan.json').read_text())
    job=next(row for row in baseline_plan['jobs'] if Path(row['source']).name=='IOWorkLoop.cpp')
    if (sha(obj)!=pm['object_sha256'] or sha(src)!=pm['adapted_source_sha256'] or
            sha(job['source'])!=pm['source_sha256'] or src.read_text()!=adapt_pm(Path(job['source']).read_text()) or
            sha(pm['dependency_receipt'])!=pm['dependency_sha256'] or
            not valid(json.loads(Path(pm['dependency_receipt']).read_text()))):
        raise ValueError('The runtime-qualified PM implementation differs')
    # Bind the generic fix to the handset's own authenticated tables too.
    sys.path.insert(0,str(ROOT/'ci/XnuPrelink'))
    from kc_image import Image
    image=Image((BASE/'strict-first-frame-058-001/kernel.macho').read_bytes())
    native=Image(image.data,image.entries['com.apple.kernel'][1]);fixups=image.fixups()
    names={name:address for address,values in native.symbols().items() for name in values}
    tables=[]
    for row in pm['vtable_slots']:
        at=names[row['table']]+16+16*8;target,auth,key,div,address=fixups[at]
        if (auth,key,div,address)!=(1,0,0x234e,1):raise ValueError('Handset PM vtable schema differs')
        tables.append(dict(table=row['table'],slot=16,diversity='0x234e',target=hex(target)))
    if tables[0]['target']!=tables[1]['target'] or any(x['target']==tables[0]['target'] for x in tables[2:]):
        raise ValueError('Handset active/passive implementations differ from the qualified contract')
    a.out.mkdir(parents=True,exist_ok=False)
    out=a.out.resolve();command=json.loads((original/'native-link.command.json').read_text())
    files=Path(command[command.index('-filelist')+1]).read_text().splitlines()
    changes={row['replaces']:row['object'] for row in records.values()}
    changes[job['output']]=str(obj)
    for old,new in changes.items():
        if files.count(old)!=1:raise ValueError('Unique physical replacement required: '+old)
        files[files.index(old)]=new
    filelist=out/'link.filelist';filelist.write_text('\n'.join(files)+'\n')
    command[command.index('-filelist')+1]=str(filelist)
    command[command.index('-o')+1]=str(out/'native.macho')
    archives=[value.split('-Wl,-force_load,',1)[1] for value in command if value.startswith('-Wl,-force_load,')]
    if (not any(Path(x).name=='libShengUfs.a' for x in archives) or
            not any(Path(x).name=='libNativeLegacyDisplay.late.a' for x in archives) or
            any('qemu-' in x.lower() or 'QemuD27' in x for x in archives)):
        raise ValueError('Physical Sony storage/display archive selection required')
    for archive in archives:
        if not Path(archive).is_file():raise ValueError('Physical archive missing: '+archive)
    for key in ('display_source','gpu_source','boot_screen'):
        if sha(before[key]['archive'])!=before[key]['sha256']:raise ValueError('Physical implementation changed: '+key)
    save(out/'native-link.command.json',command)
    env=dict(os.environ,CROSS_CLANG=baseline_plan['compiler'],CROSS_EXTRA_FLAGS=before['pac_flag'],
        DARWIN_TRIPLE='arm64e-apple-ios27.0',TMPDIR=str(out),PYTHONDONTWRITEBYTECODE='1')
    env['PATH']=str(Path(command[0]).parent)+':'+env['PATH']
    with (out/'native-link.log').open('x') as stream:done=subprocess.run(command,env=env,stdout=stream,stderr=subprocess.STDOUT,timeout=360)
    if done.returncode:raise RuntimeError((out/'native-link.log').read_text()[-10000:])
    result=copy.deepcopy(before)
    replaced_names={Path(row['original_source']).name for row in records.values()}
    result['native_source_patches']=[row for row in result['native_source_patches'] if Path(row['original_source']).name not in replaced_names]
    for row in parity['native_source_patches']:
        if Path(row['original_source']).name in replaced_names:result['native_source_patches'].append(row)
    result['native_source_patches'].append(dict(native_source_patch='qemu-workloop-event-classification',
        original_source=job['source'],original_source_sha256=pm['source_sha256'],source=str(src),source_sha256=sha(src)))
    result.update(native=str(out/'native.macho'),native_sha256=sha(out/'native.macho'),
        qemu_workloop_event_classification=True,official_upstream_parity=parity['official_upstream_parity'],
        physical_058_derived=True,physical_storage_display_retained=True,virtual_backends_selected=False,
        runtime_qualified=False,handset_test_authorized=True,device_operations=False)
    validate_overlays(result,sha)
    save(out/'result.json',result)
    receipt=dict(native_sha256=result['native_sha256'],physical_058_native_sha256=before['native_sha256'],
        object_replacements=changes,selected_archives={path:sha(path) for path in archives},
        official_parity_receipt=str(parity_dir/'parity-qualification.json'),
        official_parity_receipt_sha256=sha(parity_dir/'parity-qualification.json'),
        pm_receipt=str(pm_path),pm_receipt_sha256=sha(pm_path),handset_pm_slots=tables,
        full_058_driver_selection=True,physical_storage_display_retained=True,
        virtual_backends_selected=False,device_operations=False,handset_runtime_verified=False)
    save(out/'handset-qualification.json',receipt)
    print(json.dumps(dict(native=result['native'],native_sha256=result['native_sha256'],
        physical_archives=len(archives),objects_replaced=len(changes),virtual_backends_selected=False),indent=2))


if __name__=='__main__':main()
