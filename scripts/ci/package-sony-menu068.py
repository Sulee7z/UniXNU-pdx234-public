#!/usr/bin/env python3
"""Correct067's overlong request, preserving every payload byte except TOML."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
sys.path.insert(0,str(ROOT/'ci'))
from platform067.integration import sha
from darwin_boot_args import validate
from pdx_boot_transport import BootTransport
from sony_menu068 import PRIOR_IMAGE_SHA,KERNEL_SHA,FIRMWARE_SHA,REMOVED_DEFAULTS,shorten,loader_guard


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('release','work','out','request-tests'):parser.add_argument('--'+key,type=Path,required=True)
    args=parser.parse_args()
    if args.work.exists() or args.out.exists():raise ValueError('Preserve all previous images and evidence')
    before=json.loads((args.release/'release.json').read_text())
    if before['sha256']!=PRIOR_IMAGE_SHA or before['label']!='PAC-ABI-067':raise ValueError('Exact failed067 image required')
    tests=json.loads(args.request_tests.read_text())
    if not tests['passed'] or not tests['actual067_rejection_reproduced']:
        raise ValueError('Production request rejection regression required')
    helpers=load('menu068_helpers',ROOT/'scripts/ci/package-d27-reviewed-native.py')
    release=load('menu068_release',ROOT/'scripts/ci/release-d27-pac-abi.py')
    transport=load('menu068_transport',ROOT/'scripts/ci/package-d27-metal-refresh.py')
    fw=load('menu068_firmware',ROOT/'scripts/check-firmware-services.py')
    helpers.require_space();args.work.mkdir(parents=True);work=args.work.resolve()
    original=BootTransport(args.release/Path(before['image']).name,PRIOR_IMAGE_SHA)
    if (helpers.sha(original.fd)!=FIRMWARE_SHA or helpers.sha(original.android)!=before['original_android_sha256'] or
            helpers.sha(original.get('EFI/UniXNU/Payloads/kernel.macho'))!=KERNEL_SHA):
        raise ValueError('Failed067 retained payload identity differs')
    pe=next(data for kind,data in fw.volume_files(original.fd)['1b64af87-8415-4b57-9b16-680d70913b9f'] if kind==0x10)
    actual_loader=loader_guard(pe)
    fixed=shorten(before['kernel_args']);valid=validate(fixed)
    # Prove both removed values are the actual selected objects' defaults.
    native=Path('/mnt/f/UniXNU-Port-artifacts/platform067-20261118/native-platform067-full-002')
    native_record=json.loads((native/'result.json').read_text())
    if native_record['native_sha256']!=before['native_sha256'] or sha(native/'native.macho')!=before['native_sha256']:
        raise ValueError('Require exact linked067 input provenance')
    from compile_dependencies import valid as dependencies_valid
    publication=BASE/'gpu-source-006/build/adreno740/NativeAdrenoPublish.o.dependencies.json'
    pub=json.loads(publication.read_text());power=native_record['platform067_performance']['compiled']['GpuPowerProbe']
    power_dep=json.loads(Path(power['dependency_receipt']).read_text())
    if not dependencies_valid(pub) or not dependencies_valid(power_dep):raise ValueError('Selected defaults dependencies changed')
    if sha(pub['object'])!=pub['object_sha256'] or sha(power['object'])!=power['object_sha256']:
        raise ValueError('Selected default object bytes changed')
    pub_text=Path(pub['source']).read_text();power_text=Path(power['source']).read_text()
    if ('bool wake_by_interrupt=true;' not in pub_text or 'unsigned by_interrupt=1;' not in pub_text or
            'PE_parse_boot_argn("gpu-fence-wake",&by_interrupt,sizeof by_interrupt)' not in pub_text or
            'unsigned gPauseUs = 1000;' not in power_text or
            'PE_parse_boot_argn("gpu-pause-us", &us, sizeof us)' not in power_text):
        raise ValueError('Cannot prove removed arguments equal the linked defaults')
    import hashlib
    for key,obj in (('publication',Path(pub['object'])),('power',Path(power['object']))):
        member=subprocess.check_output(['llvm-ar','p',native_record['gpu_source']['archive'],obj.name])
        if hashlib.sha256(member).hexdigest()!=sha(obj):raise ValueError('Default object not actually selected: '+key)
    default_proof=dict(passed=True,values={'gpu-fence-wake':1,'gpu-pause-us':1000},
        sources={str(Path(pub['source'])):sha(pub['source']),power['source']:sha(power['source'])},
        selected_objects={pub['object']:sha(pub['object']),power['object']:sha(power['object'])},
        archive=native_record['gpu_source']['archive'],archive_sha256=sha(native_record['gpu_source']['archive']))
    old_config=original.get('EFI/UniXNU/unixnu.toml').decode();old=tomllib.loads(old_config)
    xnu=next(entry for entry in old['entry'] if entry['id']=='xnu')
    if xnu['args']!=before['kernel_args']:raise ValueError('Actual067 config arguments differ')
    text=release.replace_config_arguments(old_config,before['kernel_args'],fixed)
    title=before['menu_title'].replace('PAC-ABI-067','PAC-ABI-068')
    if text.count(json.dumps(before['menu_title']))!=1:raise ValueError('Unique067 title required')
    text=text.replace(json.dumps(before['menu_title']),json.dumps(title))
    expected=copy.deepcopy(old);expected['ui']['title']=title
    next(entry for entry in expected['entry'] if entry['id']=='xnu')['args']=fixed
    if tomllib.loads(text)!=expected:raise ValueError('Unexpected menu policy change')
    config=work/'unixnu.toml';config.write_text(text)
    # Run the exact request guards on corrected args plus the actual2GiB seed.
    mock_release=work/'request-release';mock_release.mkdir();save(mock_release/'release.json',dict(kernel_args=fixed))
    seed=work/'scratch-data.request-check.img';seed.write_bytes(original.get('EFI/UniXNU/Payloads/scratch-data.img'))
    command=[sys.executable,'-B',ROOT/'scripts/ci/check-darwinboot-request.py','--out',work/'request-validation',
             '--release',mock_release,'--expect-rejected',args.release,'--ramdisk',seed]
    release.run(command,work/'request-validation.log')
    menu=work/'menu';esp=menu/'esp';(esp/'EFI/BOOT').mkdir(parents=True);(esp/'EFI/UniXNU').mkdir(parents=True)
    app=BASE/'tmp/first-frame-menu058/esp/EFI/BOOT/BOOTAA64.EFI'
    if sha(app)!='3327e1b7a84fc0e6cd796c54acf63620d9d2add99e78b6a4032d99c9dd9d25c3':
        raise ValueError('Qualified menu executable differs')
    (esp/'EFI/BOOT/BOOTAA64.EFI').write_bytes(app.read_bytes());(esp/'EFI/UniXNU/unixnu.toml').write_text(text)
    menu_command=['python3','-B','/root/unixnu-build/pdx234-unixnu-package/Scripts/qemu-run.py',str(esp),
        '--log',str(menu/'serial.log'),'--screenshot',str(menu/'menu.png'),'--expect',"default 0 'xnu'",
        '--reject','UNIXNU: config: default entry needs confirmation','--timeout','30','--finish-on-expect']
    with (menu/'runner.log').open('x') as log:subprocess.run(menu_command,stdout=log,stderr=subprocess.STDOUT,timeout=45,check=True)
    save(menu/'result.json',dict(passed=True,command=menu_command,scope='Menu only; actual request guard tested separately'))
    fat=work/'payload.fat';fat.write_bytes(original.fat);old_files=helpers.fat_inventory(fat)
    os.utime(config,(315532800,315532800));subprocess.run(['mcopy','-o','-m','-i',str(fat),str(config),'::/EFI/UniXNU/unixnu.toml'],check=True)
    new_files=helpers.fat_inventory(fat);changed={name for name in old_files if old_files[name]!=new_files.get(name)}
    if old_files.keys()!=new_files.keys() or changed!={'EFI/UniXNU/unixnu.toml'}:
        raise ValueError('A nonconfiguration payload file changed')
    # Re-running the existing seal contract on a copy must change no byte.
    kernel=work/'kernel.seal-check.macho';kernel.write_bytes(original.get('EFI/UniXNU/Payloads/kernel.macho'))
    release.run([sys.executable,'-B',BASE/'sources/UniXNU/scripts/seal-source-crypto-kernel.py',kernel,
        '--kernel-args',fixed],work/'seal-check.log',dict(os.environ,UNIXNU_XNU_ARCH='arm64e',UNIXNU_IOS_VERSION='27.0'))
    if sha(kernel)!=KERNEL_SHA:raise ValueError('Shorter request unexpectedly changes the existing sealed kernel')
    image,blob,commands=transport.pack_transport(original.baseline_dict(),fat.read_bytes(),work,helpers)
    if len(image)>96*1024**2:raise ValueError('Sony boot partition capacity exceeded')
    helpers.require_space();args.out.mkdir(parents=True);target=args.out.resolve()/'boot-pdx234-pac-abi-068.img';target.write_bytes(image)
    correction=dict(prior_argument_bytes=1041,argument_bytes=valid['ascii_bytes'],capacity_bytes=1024,
        removed_explicit_defaults=REMOVED_DEFAULTS,defaults_proof=default_proof,actual_loader=actual_loader,
        only_config_changed=True,kernel_byte_identical_to067=True,no_auth_or_abi_changes=True,
        request_validation_receipt=str(work/'request-validation/result.json'),
        request_validation_receipt_sha256=sha(work/'request-validation/result.json'))
    record=copy.deepcopy(before);record.update(image=str(target),bytes=len(image),sha256=helpers.sha(image),label='PAC-ABI-068',
        source_image_sha256=PRIOR_IMAGE_SHA,source_release=str(args.release.resolve()),kernel_args=fixed,screen_build_tag='PDX068',menu_title=title,
        arguments_removed=['build-tag=PDX067',*REMOVED_DEFAULTS],arguments_added=['build-tag=PDX068'],
        payload_sha256=sha(fat),bundle_sha256=helpers.sha(blob),correction='Fix067 pre-kernel DarwinBoot argument overflow; no kernel/firmware/driver changes',
        darwinboot_args_fix=correction,darwinboot_command_line=valid,prior067_withdrawn_for_boot=True,
        baseline_kernel_byte_identity=True,baseline_firmware_byte_identity=True,image_delivered=False,
        ready_for_manual_test=True,hardware_boot_verified=False,device_writes=False,
        menu_qemu_receipt=str(menu/'result.json'),menu_qemu_receipt_sha256=sha(menu/'result.json'))
    record['historical067_platform_policy']=record.pop('platform067_policy')
    record['metadata_normalization_history067']=record.pop('metadata_normalization',None)
    record['platform068_effective_default_arguments']={'gpu-fence-wake':1,'gpu-pause-us':1000}
    save(args.out/'release.json',record);(args.out/'SHA256SUMS').write_text(record['sha256']+'  '+target.name+'\n')
    final=helpers.readback(args.out,work/'final-readback.log')
    if final['android']!=original.android or final['fd']!=original.fd:raise ValueError('Retained boot firmware/Android changed')
    for path,digest in old_files.items():
        if path=='EFI/UniXNU/unixnu.toml':continue
        if helpers.sha(final['get'](path))!=digest:raise ValueError('Final nonconfig payload changed: '+path)
    save(work/'report.json',dict(passed=True,image=str(target),sha256=record['sha256'],changed_files=sorted(changed),
        all_other_payload_files_identical=True,android_identical=True,firmware_identical=True,
        old_files=old_files,new_files=new_files,argument_validation=valid,request_tests=correction['request_validation_receipt'],
        packager_sha256=sha(__file__),commands=commands,device_operations=False,hardware_verified=False))
    print(json.dumps(dict(image=str(target),bytes=len(image),sha256=record['sha256'],argument_bytes=valid['ascii_bytes'],
        all_payload_except_config_identical=True,hardware_verified=False),indent=2))


if __name__=='__main__':main()
