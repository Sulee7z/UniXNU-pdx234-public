#!/usr/bin/env python3
"""Relink the real current QEMU native with the checked virt-only D27 display."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')

def sha(path):
    with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def save(path,data):path.write_text(json.dumps(data,indent=2)+'\n')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--from-work',type=Path,default=BASE/'qemu-current-20261117-005')
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    if shutil.disk_usage('/mnt/g').free<8*1024**3:raise RuntimeError('G reserve below8GiB')
    previous=a.from_work/'native';before=json.loads((previous/'result.json').read_text())
    if sha(previous/'native.macho')!=before['native_sha256'] or not before['qemu_current_verified']:
        raise ValueError('Require completed current QEMU native')
    summary=json.loads((ROOT/'ci/qemu/display/result.json').read_text())
    report_path=Path(summary['build_receipt']);display=json.loads(report_path.read_text())
    if (sha(display['archive'])!='f0e9159f701e5a47806a0c780443c6500e1983b7f99e89b733317d4cabb4ba92' or
        summary['archive_sha256']!=display['sha256'] or display['authenticated_vtable_slots_verified']!=379 or
        not display['original_vtable_bindings_unchanged'] or not display['reused_members_match_qualified_archive']):
        raise ValueError('Qualified D27 QEMU display archive required')
    for member,digest in display['members'].items():
        if sha(member)!=digest:raise ValueError('Display member changed: '+member)
    for key in ('observation_tests','pm_forwarding_tests'):
        test=summary[key]
        if sha(test['receipt'])!=test['sha256'] or test['asan_ubsan']!='pass':raise ValueError('Display tests differ')
    for source in before['qemu_current_sources']:
        if sha(source['source'])!=source['source_sha256'] or sha(source['object'])!=source['object_sha256']:
            raise ValueError('Real QEMU storage source/object changed')
    if sha(before['qemu_storage_archive'])!=before['qemu_storage_archive_sha256']:
        raise ValueError('QEMU storage archive changed')
    a.out.mkdir(parents=True,exist_ok=False);native=a.out/'native';native.mkdir()
    command=json.loads((previous/'native-link.command.json').read_text())
    old='-Wl,-force_load,'+before['display_source']['archive']
    if command.count(old)!=1:raise ValueError('Physical display selection is not unique')
    command[command.index(old)]='-Wl,-force_load,'+display['archive']
    cpufreq=BASE/'display-source-009/build/native-legacy-display/CpuFreqProbe.o'
    member=subprocess.check_output(['/usr/lib/llvm-18/bin/llvm-ar','p',before['display_source']['archive'],'CpuFreqProbe.o'])
    if hashlib.sha256(member).hexdigest()!=sha(cpufreq):raise ValueError('Original cpufreq diagnostic provider differs')
    # Current boot-screen diagnostics imports these real symbols. This object
    # has no startup initializer; its poll returns before mapping/MMIO while
    # gMode/gLock remain zero. The QEMU display omits its probe call entirely.
    command.append(str(cpufreq))
    command[command.index('-o')+1]=str(native/'native.macho')
    selected=Path(command[command.index('-filelist')+1]).read_text().splitlines()
    receipts=json.loads((previous/'reused-object-identities.json').read_text())
    for record in receipts:
        if record['path'] in selected and record['path'].endswith('/bsd_init.o'):
            # This slot is the old source object, replaced in the selected list.
            continue
        if record['path'] in selected and sha(record['path'])!=record['sha256']:
            raise ValueError('Cached selected object changed')
    for value in command:
        if value.startswith('-Wl,-force_load,') and 'libNativeLegacyDisplay' in value:
            raise ValueError('Physical display archive still linked')
    save(native/'native-link.command.json',command)
    compiler='/root/unixnu-build/pdx234-pac-toolchain/llvm/bin/clang-24'
    env=dict(os.environ,CROSS_CLANG=compiler,DARWIN_TRIPLE='arm64e-apple-ios27.0',
             CROSS_EXTRA_FLAGS=before['pac_flag'],TMPDIR=str(native),PYTHONDONTWRITEBYTECODE='1')
    env['PATH']=str(Path(command[0]).parent)+':'+env['PATH']
    with (native/'native-link.log').open('x') as f:done=subprocess.run(command,stdout=f,stderr=subprocess.STDOUT,env=env,timeout=300)
    if done.returncode:raise RuntimeError((native/'native-link.log').read_text()[-10000:])
    result=copy.deepcopy(before)
    result.update(native=str(native/'native.macho'),native_sha256=sha(native/'native.macho'),
        qemu_display=summary,qemu_display_build_receipt_sha256=sha(report_path),
        inactive_cpufreq_provider=dict(object=str(cpufreq),sha256=sha(cpufreq),
            source=str(BASE/'display-source-009/kits/sheng/CpuFreqProbe.cpp'),
            source_sha256=sha(BASE/'display-source-009/kits/sheng/CpuFreqProbe.cpp'),
            startup_caller_selected=False,poll_guards_zero_mode_lock=True),
        relinked_from=before['native_sha256'],runtime_qualified=False,device_operations=False)
    result['display_source']=dict(display,physical_archive_selected=False,virtual_only=True)
    save(native/'result.json',result)
    save(a.out/'display-integration.json',dict(native_sha256=result['native_sha256'],
         prior_native_sha256=before['native_sha256'],qemu_display_archive_sha256=display['sha256'],
         physical_display_archive_removed_from_link=True,all379display_pac_slots_verified=True,
         storage_archive_sha256=before['qemu_storage_archive_sha256'],device_operations=False))
    print(json.dumps(json.loads((a.out/'display-integration.json').read_text()),indent=2),flush=True)

if __name__=='__main__':main()
