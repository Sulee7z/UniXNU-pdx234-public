#!/usr/bin/env python3
"""Package the qualified Sony touch kernel over the lockscreen-tested physical060 image."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
BASELINE_SHA='618d2c3bf69e9aacb1d962c5e4f6fc00afb61fbf7c3ce52903501fa00515fb0c'


def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def load(name,file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('release','native','strict','touch','verification','work','out'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--label',choices=('061','062','063','064','065','066'),default='061')
    parser.add_argument('--ui-tests',type=Path)
    a=parser.parse_args()
    if a.work.exists() or a.out.exists():raise ValueError('Preserve existing package artifacts')
    helpers=load('sony_touch_pack_helpers','package-d27-reviewed-native.py')
    release=load('sony_touch_release_helpers','release-d27-pac-abi.py')
    transport=load('sony_touch_transport','package-d27-metal-refresh.py')
    helpers.require_space();a.work.mkdir(parents=True);work=a.work.resolve()
    baseline=helpers.readback(a.release,work/'baseline-readback.log');prior=baseline['j']
    if prior['sha256']!=BASELINE_SHA or not prior['gpu_enabled'] or not prior['cdc_disabled']:
        raise ValueError('Require exact physical060 GPU-on/CDC-off baseline')
    n=json.loads((a.native/'result.json').read_text());s=json.loads((a.strict/'result.json').read_text())
    k=json.loads((a.strict/'kernel.json').read_text());v=json.loads(a.verification.read_text())
    touch=json.loads((a.touch/'result.json').read_text())
    if (sha(a.native/'native.macho')!=n['native_sha256'] or n['native_sha256']!=s['native_sha256'] or
        sha(a.strict/'kernel.macho')!=s['candidate_sha256'] or s['candidate_sha256']!=k['candidate_sha256'] or
        k['missing'] or k['stubbed'] or k['allow_missing'] or not k['candidate_written'] or
        not s['pac_enabled'] or s['auth_instruction_patches'] or s['pac_metadata_adapters'] or
        not v['passed'] or v['native_sha256']!=n['native_sha256'] or v['strict_sha256']!=s['candidate_sha256']):
        raise ValueError('Require exact strict native/instruction verification')
    expected_init=touch.get('cold_boot_init_implemented') if a.label=='061' else (
        touch.get('inherited_engine_init_implemented') and touch.get('se_dma_implemented') and touch.get('protected_alias_access') is False)
    if n['sony_touch']!=touch or not expected_init or touch['virtual_backend_included']:
        raise ValueError('Require the qualified physical Sony touch build')
    if a.label in ('063','064','065','066') and (not n.get('block_descriptor_abi') or not v.get('block_descriptor_abi',{}).get('passed')):
        raise ValueError('Require the repaired and tested signed Blocks ABI')
    if a.label in ('064','065','066'):
        if not a.ui_tests or not json.loads(a.ui_tests.read_text())['passed']:
            raise ValueError('Require actual no-overlay/per-CPU observer regression')
        ui_tests=json.loads(a.ui_tests.read_text())
        if sha(ui_tests['cpu_source'])!=ui_tests['cpu_source_sha256'] or sha(ui_tests['ui_source'])!=ui_tests['ui_source_sha256']:
            raise ValueError('Tested UI policy or CPU recorder source changed')
        if not touch.get('engine_irq_registered_before_mask') or not touch.get('per_cpu_runtime_recorder'):
            raise ValueError('064 requires IRQ registration and per-core runtime recorder')
    if a.label in ('065','066'):
        if not touch.get('dma_done_is_completion') or not touch.get('late_hid_match_retried'):
            raise ValueError('065 requires reviewed DMA completion and HID late-match replay')
        for row in touch['chain_regressions'].values():
            test=Path(row['receipt'])
            if sha(test)!=row['sha256'] or not json.loads(test.read_text())['passed']:
                raise ValueError('Chain regression receipt changed')
    if a.label=='066' and not touch.get('sw82907_vendor_boot_policy'):
        raise ValueError('066 requires runtime-evidenced vendor boot-status policy')
    for key in ('sources','objects'):
        for path,digest in touch[key].items():
            if sha(path)!=digest:raise ValueError('Qualified touch artifact changed: '+path)
    if sha(touch['archive'])!=touch['sha256']:raise ValueError('Touch archive changed')
    if (v['full_profile_roots'],v['closure_entries'],v['matching_personalities'],v['original_kmod_pac_fields'])!=(19,38,32,36):
        raise ValueError('Full physical060 profile/PAC selection differs')
    sys.path.insert(0,str(ROOT/'ci'));from native_source_overlays import validate_overlays
    validate_overlays(n,sha)
    for key in ('gpu_source','framebuffer_call_trace','usb_sources'):
        if s[key]!=prior[key]:raise ValueError('Preserved060 implementation changed: '+key)
    if a.label=='066':
        profile=Path(s['selected_profile']['path']);parsed=tomllib.loads(profile.read_text())
        if (sha(profile)!=s['selected_profile']['sha256'] or
            s['selected_profile']['roots']!=prior['selected_profile']['roots'] or
            parsed['kernel']['prelink']['roots']!=prior['selected_profile']['roots'] or
            parsed['kernel']['prelink']['kernelcache_sha256']!='c28f4fc9b83cde00087e81f890c82d566b9e98b5ac228dfecd83afdf34070445'):
            raise ValueError('066 full original profile identities/roots changed')
    elif s['selected_profile']!=prior['selected_profile']:
        raise ValueError('Preserved060 implementation changed: selected_profile')
    if n['official_upstream_parity']!=prior['official_upstream_parity']:
        raise ValueError('Pinned upstream repair inputs differ from060')
    for key in ('gpu_source','display_source','boot_screen'):
        if sha(s[key]['archive'])!=s[key]['sha256']:raise ValueError('Linked module changed: '+key)
    if not s['boot_screen'].get('sony_touch_rows_enabled') or not s['display_source'].get('sony_touch_start_connected'):
        raise ValueError('Input startup/diagnostic screen is disconnected')
    # Bind each existing-module change to the exact one-anchor source adaptation.
    display_original=BASE/'display-source-009/kits/sheng/LegacyDisplayProbe.cpp'
    display_source=Path(s['display_source']['archive']).parent/'LegacyDisplayProbe.cpp'
    anchor='    native_keystore_probe();\n' if a.label=='061' else '    sheng_gpu_power_probe();\n'
    expected=display_original.read_text().replace(anchor,
        anchor+'    extern void native_sony_touch_start(void);\n    native_sony_touch_start();\n')
    if sha(display_original)!=prior['display_source']['staged_probe_sha256'] or display_source.read_text()!=expected:
        raise ValueError('Physical display startup change is not the reviewed anchor')
    screen_original=BASE/'boot-screen-015/BootProgress.c';screen_source=Path(s['boot_screen']['archive']).parent/'BootProgress.c'
    if screen_source.read_text()!=screen_original.read_text().replace('  if(0 && &native_touch_rows) {',
        '  if(&native_touch_rows && native_touch_rows[0][0]) {'):
        raise ValueError('Unexpected display diagnostic change')
    original=baseline['get']('EFI/UniXNU/unixnu.toml').decode()
    tokens=prior['kernel_args'].split()
    if tokens.count('build-tag=PDX060')!=1:raise ValueError('060 build tag differs')
    for key in ('sony-touch','touch-hid'):
        if any(t.startswith(key+'=') for t in tokens):raise ValueError('Unexpected baseline touch argument')
    if a.label in ('064','065','066'):
        if tokens.count('boot-diag-resume=10')!=1 or any(t.startswith('banner=') for t in tokens):
            raise ValueError('Unexpected baseline overlay policy')
        tokens[tokens.index('boot-diag-resume=10')]='boot-diag-resume=0'
        tokens.append('banner=0')
    arguments=' '.join('build-tag=PDX'+a.label if t=='build-tag=PDX060' else t for t in tokens)+' sony-touch=1 touch-hid=1'
    title=prior['menu_title'].replace('PAC-ABI-060','PAC-ABI-'+a.label)
    text=release.replace_config_arguments(original,prior['kernel_args'],arguments)
    if text.count(json.dumps(prior['menu_title']))!=1:raise ValueError('Ambiguous menu title')
    text=text.replace(json.dumps(prior['menu_title']),json.dumps(title))
    expected=copy.deepcopy(tomllib.loads(original));expected['ui']['title']=title
    next(entry for entry in expected['entry'] if entry['id']=='xnu')['args']=arguments
    if tomllib.loads(text)!=expected:raise ValueError('Unexpected configuration change')
    menu=work/'menu';menu.mkdir();esp=menu/'esp';(esp/'EFI/BOOT').mkdir(parents=True);(esp/'EFI/UniXNU').mkdir()
    app=BASE/'tmp/first-frame-menu058/esp/EFI/BOOT/BOOTAA64.EFI'
    if sha(app)!='3327e1b7a84fc0e6cd796c54acf63620d9d2add99e78b6a4032d99c9dd9d25c3':
        raise ValueError('Qualified menu application changed')
    (esp/'EFI/BOOT/BOOTAA64.EFI').write_bytes(app.read_bytes());(esp/'EFI/UniXNU/unixnu.toml').write_text(text)
    menu_command=['python3','-B','/root/unixnu-build/pdx234-unixnu-package/Scripts/qemu-run.py',str(esp),
        '--log',str(menu/'serial.log'),'--screenshot',str(menu/'menu.png'),'--expect',"default 0 'xnu'",'--reject',
        'UNIXNU: config: default entry needs confirmation','--timeout','60','--finish-on-expect']
    with (menu/'runner.log').open('x') as log:subprocess.run(menu_command,stdout=log,stderr=subprocess.STDOUT,timeout=90,check=True)
    save(menu/'result.json',dict(passed=True,command=menu_command,application_sha256=sha(app),
        config_sha256=hashlib.sha256(text.encode()).hexdigest(),scope='Menu parsing only; no guest XNU boot'))
    release.run([sys.executable,'-B',ROOT/'scripts/ci/verify-d27-sdt.py','--strict',a.strict,
        '--out',work/'sdt-verified.json'],work/'sdt.log')
    kernel=work/'kernel.macho';kernel.write_bytes((a.strict/'kernel.macho').read_bytes())
    release.run([sys.executable,'-B',ROOT/'scripts/patch-panic-screen.py','--kernel',kernel,
        '--mainline',BASE/'sources/UniXNU','--uefi',ROOT.parent/'uefi-pdx234','--preserve-auth'],work/'panic-patch.log')
    panic=json.loads((work/'kernel.panic-screen.json').read_text())
    if not panic['auth_instructions_preserved'] or panic['source_kernel_sha256']!=s['candidate_sha256']:
        raise ValueError('Panic renderer authentication changed')
    before=kernel.read_bytes()
    release.run([sys.executable,'-B',BASE/'sources/UniXNU/scripts/seal-source-crypto-kernel.py',kernel,
        '--kernel-args',arguments],work/'seal.log',dict(os.environ,UNIXNU_XNU_ARCH='arm64e',UNIXNU_IOS_VERSION='27.0'))
    seal=json.loads((work/'kernel.macho.crypto-hmac.json').read_text());sealed=kernel.read_bytes()
    if seal['kernel_sha256']!=sha(kernel):raise ValueError('Crypto seal kernel identity differs')
    sys.path.insert(0,str(a.strict/'XnuPrelink'));from kc_image import Image
    image=Image(before)
    for _,offset in image.entries.values():
        member=Image(before,offset)
        for segment in member.segments:
            if segment['name'] in ('__TEXT_EXEC','__KLD'):
                at,size=segment['fileoff'],segment['filesize']
                if before[at:at+size]!=sealed[at:at+size]:raise ValueError('Seal changed executable bytes')
    release.run([sys.executable,'-B',ROOT/'scripts/ci/audit-darwinboot-parser.py','--darwinboot',ROOT/'.cache/firmware-components/DarwinBoot',
        '--kernel',kernel,'--report',work/'darwinboot-parser.json'],work/'parser.log')
    if not json.loads((work/'darwinboot-parser.json').read_text())['accepted']:raise ValueError('DarwinBoot parser rejected final kernel')
    config=work/'unixnu.toml';config.write_text(text)
    fat=work/'payload.fat';fat.write_bytes(baseline['fat']);old=helpers.fat_inventory(fat)
    for local,remote in ((kernel,'Payloads/kernel.macho'),(config,'unixnu.toml')):
        os.utime(local,(315532800,315532800))
        subprocess.run(['mcopy','-o','-m','-i',str(fat),str(local),'::/EFI/UniXNU/'+remote],check=True)
    new=helpers.fat_inventory(fat);changed={name for name in old if old[name]!=new.get(name)}
    if old.keys()!=new.keys() or changed!={'EFI/UniXNU/Payloads/kernel.macho','EFI/UniXNU/unixnu.toml'}:
        raise ValueError('Unexpected060 payload change')
    packed,blob,commands=transport.pack_transport(baseline,fat.read_bytes(),work,helpers)
    if len(packed)>96*1024**2:raise ValueError('Image exceeds Sony boot partition')
    a.out.mkdir(parents=True);target=a.out.resolve()/('boot-pdx234-pac-abi-'+a.label+'.img');target.write_bytes(packed)
    record=copy.deepcopy(prior)
    record.update(image=str(target),bytes=len(packed),sha256=helpers.sha(packed),label='PAC-ABI-'+a.label,
        source_image_sha256=BASELINE_SHA,source_release=str(a.release.resolve()),
        native_sha256=n['native_sha256'],strict_kernel_sha256=s['candidate_sha256'],payload_kernel_sha256=sha(kernel),
        payload_sha256=sha(fat),bundle_sha256=helpers.sha(blob),kernel_args=arguments,screen_build_tag='PDX'+a.label,
        menu_title=title,arguments_removed=['build-tag=PDX060'],arguments_added=['build-tag=PDX'+a.label,'sony-touch=1','touch-hid=1'],
        panic_screen=panic,crypto_seal=seal,expanded_native_data=s['expanded_native_data'],
        display_source=s['display_source'],boot_screen=s['boot_screen'],selected_profile=s['selected_profile'],
        native_review_receipt=str(a.strict/'result.json'),strict_result_sha256=sha(a.strict/'result.json'),
        handset_instruction_verification=v,handset_instruction_verification_receipt=str(a.verification.resolve()),
        handset_instruction_verification_sha256=sha(a.verification),
        sony_touch=touch,sony_touch_verification=v['sony_touch'],sony_touch_hid_abi=json.loads((a.touch/'hid-abi.json').read_text()),
        touch_runtime_verified=False,home_screen_verified=False,hardware_boot_verified=False,desktop_verified=False,
        baseline_lockscreen_user_reported=True,device_writes=False,staging_only=False,
        menu_qemu_receipt=str(menu/'result.json'),menu_qemu_receipt_sha256=sha(menu/'result.json'),
        correction=('Honor Sony SW82907 boot-status SKIP semantics after measured065 boot=0/error-33; validate firmware version and post-start CRC/running state' if a.label=='066' else
                    'Use vendor/official SE DMA completion, restore GENI idle outputs, retry late HID matching and record the full touch chain; preserve064 UI policy and063 Block ABI' if a.label=='065' else
                    'Register the Sony GENI IRQ route before masking, preserve063 Block ABI, disable live UI overlay/timed takeover and record all eight core states' if a.label=='064' else
                    'D27 signed Blocks descriptor ABI across all local producers/runtime, retaining062 Sony touch transport and diagnostics' if a.label=='063' else
                    'Physical060 plus Sony LXS SW82907/GENI I2C, checked OEM engine firmware, D27 HID and diagnostics' if a.label=='061' else
                    'Physical060 plus retained OEM I2C firmware, GPIO/SMMU-qualified FIFO or SE DMA, GIC-masked visible status and detailed touch/HID diagnostics'),
        gpu_rendering_verified=False,source_only_touch_claim=False)
    if a.label in ('063','064','065','066'):record['block_descriptor_abi']=v['block_descriptor_abi']
    if a.label in ('064','065','066'):
        record.update(ui_overlay_disabled=True,ui_timed_takeover_disabled=True,
            cpu_runtime_recording_enabled=True,cpu_all_online_runtime_verified=False,
            ui_tests_receipt=str(a.ui_tests),ui_tests_sha256=sha(a.ui_tests))
        record['arguments_removed']+=['boot-diag-resume=10']
        record['arguments_added']+=['boot-diag-resume=0','banner=0']
    save(a.out/'release.json',record);(a.out/'SHA256SUMS').write_text(record['sha256']+'  '+target.name+'\n')
    final=helpers.readback(a.out,work/'final-readback.log')
    if final['fd']!=baseline['fd'] or final['android']!=baseline['android'] or final['get']('EFI/UniXNU/Payloads/kernel.macho')!=sealed:
        raise ValueError('Final independent readback differs')
    save(work/'report.json',dict(passed=True,image=str(target),sha256=record['sha256'],changed_files=sorted(changed),
        all_other_payload_files_identical=True,android_identical=True,firmware_identical=True,commands=commands,
        packager_sha256=sha(__file__),touch_runtime_verified=False,device_operations=False))
    print(json.dumps(dict(image=str(target),bytes=len(packed),sha256=record['sha256'],
        strict_kernel_sha256=s['candidate_sha256'],payload_kernel_sha256=sha(kernel),
        cdc_disabled=True,gpu_enabled=True,touch_runtime_verified=False),indent=2),flush=True)


if __name__=='__main__':main()
