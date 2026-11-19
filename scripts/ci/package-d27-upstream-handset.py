#!/usr/bin/env python3
"""Package the physical060 source repairs over the independently verified058 IMG."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tomllib

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
BASELINE_SHA='45baa2f1799bc1ddda81dd3236b7d20ea78aeb8c0aec635697e29a5096b36331'


def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(filename))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('release','native','strict','verification','work','out'):p.add_argument('--'+key,type=Path,required=True)
    a=p.parse_args()
    helpers=load('handset_package_helpers','package-d27-reviewed-native.py')
    release=load('handset_release_helpers','release-d27-pac-abi.py')
    transport=load('handset_transport_helpers','package-d27-metal-refresh.py')
    helpers.require_space()
    if a.work.exists() or a.out.exists():raise ValueError('Require new package/output directories')
    a.work.mkdir(parents=True);work=a.work.resolve()
    baseline=helpers.readback(a.release,work/'baseline-readback.log');prior=baseline['j']
    if prior['sha256']!=BASELINE_SHA or not prior['gpu_enabled'] or not prior['cdc_disabled']:
        raise ValueError('Require the exact physical058 GPU-on/CDC-off baseline')
    n=json.loads((a.native/'result.json').read_text());s=json.loads((a.strict/'result.json').read_text())
    k=json.loads((a.strict/'kernel.json').read_text());v=json.loads(a.verification.read_text())
    if (sha(a.native/'native.macho')!=n['native_sha256'] or n['native_sha256']!=s['native_sha256'] or
            sha(a.strict/'kernel.macho')!=s['candidate_sha256'] or s['candidate_sha256']!=k['candidate_sha256'] or
            k['missing'] or k['stubbed'] or k['allow_missing'] or not k['candidate_written'] or
            not s['pac_enabled'] or s['pac_metadata_adapters'] or s['auth_instruction_patches'] or
            not v['passed'] or v['native_sha256']!=n['native_sha256'] or v['strict_sha256']!=s['candidate_sha256']):
        raise ValueError('Require exact physical native/strict/instruction verification')
    if not n['physical_058_derived'] or n['virtual_backends_selected'] is not False:
        raise ValueError('QEMU backend is not a handset candidate')
    sys.path.insert(0,str(ROOT/'ci'));from native_source_overlays import validate_overlays
    validate_overlays(n,sha)
    for key in ('display_source','gpu_source','boot_screen','framebuffer_call_trace','usb_sources','selected_profile'):
        if s[key]!=prior[key]:raise ValueError('Physical058 implementation/profile changed: '+key)
    for key in ('display_source','gpu_source','boot_screen'):
        if sha(s[key]['archive'])!=s[key]['sha256']:raise ValueError('Linked physical archive changed: '+key)
    if not all((v['pm_authenticated_vptr_and_slot'],v['par_translation_synchronized'],
                v['kernel_pac_restored_on_el0_entry'],v['arm64_user_pac_transition'],v['root_union_statfs_identity'])):
        raise ValueError('Required actual instruction checks incomplete')
    if (v['full_profile_roots'],v['closure_entries'],v['matching_personalities'],v['original_kmod_pac_fields'])!=(19,38,32,36):
        raise ValueError('Full058/PAC selection differs')
    original=baseline['get']('EFI/UniXNU/unixnu.toml').decode()
    if prior['kernel_args'].split().count('build-tag=PDX058')!=1:raise ValueError('Unexpected058 build tag')
    arguments=prior['kernel_args'].replace('build-tag=PDX058','build-tag=PDX060')
    title=prior['menu_title'].replace('PAC-ABI-058','PAC-ABI-060')
    text=release.replace_config_arguments(original,prior['kernel_args'],arguments)
    if text.count(json.dumps(prior['menu_title']))!=1:raise ValueError('Ambiguous menu title')
    text=text.replace(json.dumps(prior['menu_title']),json.dumps(title))
    before,after=tomllib.loads(original),tomllib.loads(text);expected=copy.deepcopy(before)
    expected['ui']['title']=title;next(e for e in expected['entry'] if e['id']=='xnu')['args']=arguments
    if after!=expected or after['boot']['timeout']!=-1 or after['boot']['default']!='xnu':raise ValueError('Unexpected configuration delta')
    if 'confirm' in next(e for e in after['entry'] if e['id']=='xnu'):raise ValueError('Default-entry confirmation conflict')
    # A bounded application-only menu check. It never starts XNU or runs a long
    # QEMU guest, and records only configuration parsing/default selection.
    menu=work/'menu';menu.mkdir();esp=menu/'esp';(esp/'EFI/BOOT').mkdir(parents=True);(esp/'EFI/UniXNU').mkdir()
    app=BASE/'tmp/first-frame-menu058/esp/EFI/BOOT/BOOTAA64.EFI'
    if sha(app)!='3327e1b7a84fc0e6cd796c54acf63620d9d2add99e78b6a4032d99c9dd9d25c3':raise ValueError('Qualified menu application changed')
    (esp/'EFI/BOOT/BOOTAA64.EFI').write_bytes(app.read_bytes())
    (esp/'EFI/UniXNU/unixnu.toml').write_text(text)
    runner=Path('/root/unixnu-build/pdx234-unixnu-package/Scripts/qemu-run.py')
    command=['python3','-B',str(runner),str(esp),'--log',str(menu/'serial.log'),
        '--screenshot',str(menu/'menu.png'),'--expect',"default 0 'xnu'",'--reject',
        'UNIXNU: config: default entry needs confirmation','--timeout','60','--finish-on-expect']
    with (menu/'runner.log').open('x') as log:subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,timeout=90,check=True)
    menu_record=dict(passed=True,application_sha256=sha(app),config_sha256=helpers.sha(text.encode()),command=command,
        scope='Actual UniXNU menu configuration only',hardware_verified=False,desktop_verified=False)
    save(menu/'result.json',menu_record)
    release.run([sys.executable,'-B',ROOT/'scripts/ci/verify-d27-sdt.py','--strict',a.strict,
        '--out',work/'sdt-verified.json'],work/'sdt.log')
    kernel=work/'kernel.macho';kernel.write_bytes((a.strict/'kernel.macho').read_bytes())
    release.run([sys.executable,'-B',ROOT/'scripts/patch-panic-screen.py','--kernel',kernel,
        '--mainline',BASE/'sources/UniXNU','--uefi',ROOT.parent/'uefi-pdx234','--preserve-auth'],work/'panic-patch.log')
    panic=json.loads((work/'kernel.panic-screen.json').read_text())
    if not panic['auth_instructions_preserved'] or panic['source_kernel_sha256']!=s['candidate_sha256']:raise ValueError('Panic diagnostic auth checks failed')
    before_seal=kernel.read_bytes()
    release.run([sys.executable,'-B',BASE/'sources/UniXNU/scripts/seal-source-crypto-kernel.py',kernel,
        '--kernel-args',arguments],work/'seal.log',dict(os.environ,UNIXNU_XNU_ARCH='arm64e',UNIXNU_IOS_VERSION='27.0'))
    seal=json.loads((work/'kernel.macho.crypto-hmac.json').read_text());sealed=kernel.read_bytes()
    if seal['kernel_sha256']!=sha(kernel):raise ValueError('Final kernel seal identity differs')
    sys.path.insert(0,str(a.strict/'XnuPrelink'));from kc_image import Image
    initial=Image(before_seal)
    for _,offset in initial.entries.values():
        member=Image(before_seal,offset)
        for segment in member.segments:
            if segment['name'] in ('__TEXT_EXEC','__KLD') and segment['filesize']:
                at,size=segment['fileoff'],segment['filesize']
                if before_seal[at:at+size]!=sealed[at:at+size]:raise ValueError('Seal changed executable bytes')
    release.run([sys.executable,'-B',ROOT/'scripts/ci/audit-darwinboot-parser.py','--darwinboot',ROOT/'.cache/firmware-components/DarwinBoot',
        '--kernel',kernel,'--report',work/'darwinboot-parser.json'],work/'parser.log')
    if not json.loads((work/'darwinboot-parser.json').read_text())['accepted']:raise ValueError('DarwinBoot rejected final kernel')
    config=work/'unixnu.toml';config.write_text(text)
    fat=work/'payload.fat';fat.write_bytes(baseline['fat']);old_files=helpers.fat_inventory(fat)
    for local,remote in ((kernel,'Payloads/kernel.macho'),(config,'unixnu.toml')):
        os.utime(local,(315532800,315532800))
        subprocess.run(['mcopy','-o','-m','-i',str(fat),str(local),'::/EFI/UniXNU/'+remote],check=True)
    new_files=helpers.fat_inventory(fat);changed={name for name in old_files if old_files[name]!=new_files.get(name)}
    if old_files.keys()!=new_files.keys() or changed!={'EFI/UniXNU/unixnu.toml','EFI/UniXNU/Payloads/kernel.macho'}:
        raise ValueError('Unexpected058 payload changes')
    image,blob,commands=transport.pack_transport(baseline,fat.read_bytes(),work,helpers)
    if len(image)>96*1024**2:raise ValueError('Sony boot partition capacity exceeded')
    a.out.mkdir(parents=True);target=a.out.resolve()/'boot-pdx234-pac-abi-060.img';target.write_bytes(image)
    record=copy.deepcopy(prior)
    record.update(image=str(target),bytes=len(image),sha256=helpers.sha(image),label='PAC-ABI-060',
        source_image_sha256=BASELINE_SHA,source_release=str(a.release.resolve()),
        native_sha256=n['native_sha256'],strict_kernel_sha256=s['candidate_sha256'],payload_kernel_sha256=sha(kernel),
        payload_sha256=sha(fat),bundle_sha256=helpers.sha(blob),kernel_args=arguments,screen_build_tag='PDX060',
        menu_title=title,arguments_removed=['build-tag=PDX058'],arguments_added=['build-tag=PDX060'],
        panic_screen=panic,crypto_seal=seal,expanded_native_data=s['expanded_native_data'],
        native_review_receipt=str((a.strict/'result.json').resolve()),strict_result_sha256=sha(a.strict/'result.json'),
        physical_058_derived=True,physical_storage_display_retained=True,virtual_backends_selected=False,
        official_upstream_parity=n['official_upstream_parity'],pm_classification_repair=True,
        handset_instruction_verification=v,handset_instruction_verification_receipt=str(a.verification.resolve()),
        handset_instruction_verification_sha256=sha(a.verification),
        menu_qemu_receipt=str(menu/'result.json'),menu_qemu_receipt_sha256=sha(menu/'result.json'),
        minimal_driver_control=False,minimal_drivers=False,strict_missing={},strict_stubbed={},allow_missing=False,
        correction='Physical058 plus authenticated PM event classification, official arm64 user PAC transition, PAR sync and root-union FSID',
        functional_first_frame_fix_claimed=False,handset_test_authorized=True,hardware_boot_verified=False,
        desktop_verified=False,device_writes=False,staging_only=False)
    save(a.out/'release.json',record);(a.out/'SHA256SUMS').write_text(record['sha256']+'  '+target.name+'\n')
    final=helpers.readback(a.out,work/'final-readback.log')
    if final['fd']!=baseline['fd'] or final['android']!=baseline['android'] or final['get']('EFI/UniXNU/Payloads/kernel.macho')!=sealed:
        raise ValueError('Final independent readback differs')
    save(work/'report.json',dict(passed=True,image=str(target),sha256=record['sha256'],changed_files=sorted(changed),
        all_other_payload_files_identical=True,android_identical=True,firmware_identical=True,
        menu_check=menu_record,commands=commands,packager_sha256=sha(__file__),hardware_verified=False,desktop_verified=False))
    print(json.dumps(dict(image=str(target),bytes=len(image),sha256=record['sha256'],
        strict_kernel_sha256=s['candidate_sha256'],payload_kernel_sha256=sha(kernel),
        cdc_disabled=True,gpu_enabled=True,desktop_verified=False),indent=2),flush=True)


if __name__=='__main__':main()
