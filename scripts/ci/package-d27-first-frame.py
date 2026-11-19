#!/usr/bin/env python3
"""Package the tested first-frame recorder over the immutable 057 payload."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tomllib

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
BASELINE_SHA='573eb4e96a1e1730c9e8b510bb094afa89c62067d459020e6b554c313dc1eaaf'
DIAGNOSTIC_ARGUMENTS=('first-frame-diag=1','gpu-trace=1','sheng-gpu-trace=1')


def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(filename))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('release','strict','screen','tests','work','out'):p.add_argument('--'+key,type=Path,required=True)
    a=p.parse_args();helper=load('first_frame_helpers','package-d27-reviewed-native.py')
    release=load('first_frame_release','release-d27-pac-abi.py')
    transport=load('first_frame_transport','package-d27-metal-refresh.py')
    helper.require_space()
    if a.work.exists() or a.out.exists():p.error('Require new output directories')
    a.work.mkdir(parents=True)
    baseline=helper.readback(a.release,a.work/'baseline-readback.log');record=baseline['j']
    if record['sha256']!=BASELINE_SHA or not record['cdc_disabled'] or not record['gpu_enabled']:
        raise ValueError('Require exact057 CDC-off/GPU-on release')
    provenance=json.loads((a.strict/'result.json').read_text())
    strict=json.loads((a.strict/'kernel.json').read_text())
    raw_kernel=a.strict/'kernel.macho'
    if (digest(raw_kernel)!=provenance['candidate_sha256'] or digest(raw_kernel)!=strict['candidate_sha256'] or
        strict['missing'] or strict['stubbed'] or strict['allow_missing'] or not strict['candidate_written'] or
        not provenance['pac_enabled'] or provenance['pac_metadata_adapters'] or provenance['auth_instruction_patches']):
        raise ValueError('Require strict PAC collection without missing/stubbed identities')
    if not provenance.get('framebuffer_call_trace',{}).get('verified'):
        raise ValueError('Require the qualified source-level framebuffer call trace')
    for key in ('gpu_source','display_source','selected_profile','usb_sources'):
        if provenance[key]!=record[key]:raise ValueError('057 integration input changed: '+key)
    for key in ('gpu_source','display_source'):
        if digest(provenance[key]['archive'])!=provenance[key]['sha256']:raise ValueError('Driver archive changed: '+key)
    screen=json.loads((a.screen/'result.json').read_text())
    if (screen!=provenance['boot_screen'] or digest(screen['archive'])!=screen['sha256'] or
        not screen.get('first_frame_diagnostics') or screen.get('pac_flag')!='-fptrauth-function-pointer-type-discrimination'):
        raise ValueError('First-frame screen is not the linked qualified archive')
    if not screen.get('swift_trap_diagnostic',{}).get('verified'):
        raise ValueError('Require the qualified Swift message capture in the same candidate')
    for source in screen['sources']:
        if digest(source['source'])!=source['sha256']:raise ValueError('Screen source changed')
    for key in ('diagnostic_headers','first_frame_headers'):
        for name,expected in screen[key].items():
            if digest(a.screen/name)!=expected or (ROOT/'ci'/name).exists() and digest(ROOT/'ci'/name)!=expected:
                raise ValueError('Screen header changed: '+name)
    swift=screen['swift_trap_diagnostic']
    if (digest(ROOT/'ci/PdxSwiftTrapDiagnostic.h')!=swift['header_sha256'] or
        digest(a.screen/'PdxSwiftTrapDiagnostic.h')!=swift['header_sha256'] or
        digest(ROOT/'ci/swift_trap_diagnostic.py')!=swift['overlay_sha256'] or
        digest(swift['tests_receipt'])!=swift['tests_sha256']):
        raise ValueError('Swift diagnostic qualification inputs changed')
    swift_tests=json.loads(Path(swift['tests_receipt']).read_text())
    if not swift_tests.get('passed'):raise ValueError('Swift bounded-copy verification failed')
    tests=json.loads(a.tests.read_text())
    if (not tests.get('passed') or tests.get('hardware_verified') is not False or
        not tests.get('native_compile_provenance_verified') or tests.get('native_build',{}).get('sha256')!=screen['sha256']):
        raise ValueError('Require successful bounded host diagnostics with explicit hardware limit')
    for name,expected in tests['headers'].items():
        if digest(ROOT/'ci'/name)!=expected:raise ValueError('Diagnostic test source differs: '+name)
    if not screen['first_frame_headers'].keys()<=tests['headers'].keys():raise ValueError('Diagnostic tests omit a production header')
    before_args=record['kernel_args'];tokens=before_args.split()
    if tokens.count('build-tag=PDX057')!=1:raise ValueError('Unexpected baseline tag')
    for argument in DIAGNOSTIC_ARGUMENTS:
        if any(t.split('=')[0]==argument.split('=')[0] for t in tokens):raise ValueError('Diagnostic switch already present')
    arguments=' '.join('build-tag=PDX058' if t=='build-tag=PDX057' else t for t in tokens)+' '+' '.join(DIAGNOSTIC_ARGUMENTS)
    original=baseline['get']('EFI/UniXNU/unixnu.toml').decode()
    text=release.replace_config_arguments(original,before_args,arguments).replace('PAC-ABI-057','PAC-ABI-058')
    before,after=tomllib.loads(original),tomllib.loads(text);expected=copy.deepcopy(before)
    expected['ui']['title']=expected['ui']['title'].replace('057','058')
    next(e for e in expected['entry'] if e['id']=='xnu')['args']=arguments
    if after!=expected or after['boot']['timeout']!=-1 or after['boot']['default']!='xnu':raise ValueError('Unexpected menu delta')
    if 'confirm' in next(e for e in after['entry'] if e['id']=='xnu'):raise ValueError('Confirmation conflict reintroduced')
    menu_test=BASE/'tmp/first-frame-menu058'
    menu_receipt=json.loads((menu_test/'result.json').read_text())
    if (not menu_receipt.get('passed') or (menu_test/'unixnu.toml').read_bytes()!=text.encode() or
        menu_receipt['config_sha256']!=hashlib.sha256(text.encode()).hexdigest()):
        raise ValueError('Final configuration differs from the actual QEMU-tested menu')
    release.run([sys.executable,'-B',ROOT/'scripts/ci/verify-d27-sdt.py','--strict',a.strict,'--out',a.work/'sdt-verified.json'],a.work/'sdt.log')
    kernel=a.work/'kernel.macho';kernel.write_bytes(raw_kernel.read_bytes())
    release.run([sys.executable,'-B',ROOT/'scripts/patch-panic-screen.py','--kernel',kernel,
                 '--mainline',BASE/'sources/UniXNU','--uefi',ROOT.parent/'uefi-pdx234','--preserve-auth'],a.work/'panic-patch.log')
    panic=json.loads((a.work/'kernel.panic-screen.json').read_text())
    if not panic['auth_instructions_preserved'] or panic['source_kernel_sha256']!=digest(raw_kernel):raise ValueError('Panic renderer auth check failed')
    before_seal=kernel.read_bytes()
    release.run([sys.executable,'-B',BASE/'sources/UniXNU/scripts/seal-source-crypto-kernel.py',kernel,'--kernel-args',arguments],
                a.work/'seal.log',dict(os.environ,UNIXNU_XNU_ARCH='arm64e',UNIXNU_IOS_VERSION='27.0'))
    seal=json.loads((a.work/'kernel.macho.crypto-hmac.json').read_text())
    if seal['kernel_sha256']!=digest(kernel):raise ValueError('Seal identity mismatch')
    sys.path.insert(0,str(a.strict/'XnuPrelink'));from kc_image import Image
    initial=Image(before_seal);sealed=kernel.read_bytes()
    for _,offset in initial.entries.values():
        member=Image(before_seal,offset)
        for segment in member.segments:
            if segment['name'] in ('__TEXT_EXEC','__KLD') and segment['filesize']:
                start,size=segment['fileoff'],segment['filesize']
                if before_seal[start:start+size]!=sealed[start:start+size]:raise ValueError('Seal changed instructions')
    release.run([sys.executable,'-B',ROOT/'scripts/ci/audit-darwinboot-parser.py','--darwinboot',ROOT/'.cache/firmware-components/DarwinBoot',
                 '--kernel',kernel,'--report',a.work/'darwinboot-parser.json'],a.work/'parser.log')
    if not json.loads((a.work/'darwinboot-parser.json').read_text())['accepted']:raise ValueError('DarwinBoot rejected collection')
    config=a.work/'unixnu.toml';config.write_text(text)
    fat=a.work/'payload.fat';fat.write_bytes(baseline['fat']);old_files=helper.fat_inventory(fat)
    import subprocess
    for local,remote in ((kernel,'Payloads/kernel.macho'),(config,'unixnu.toml')):
        os.utime(local,(315532800,315532800))
        subprocess.run(['mcopy','-o','-m','-i',str(fat),str(local),'::/EFI/UniXNU/'+remote],check=True)
    new_files=helper.fat_inventory(fat)
    changed={name for name in old_files if old_files[name]!=new_files.get(name)}
    if old_files.keys()!=new_files.keys() or changed!={'EFI/UniXNU/unixnu.toml','EFI/UniXNU/Payloads/kernel.macho'}:
        raise ValueError('Unexpected FAT changes')
    image,bundle,commands=transport.pack_transport(baseline,fat.read_bytes(),a.work,helper)
    a.out.mkdir(parents=True);target=a.out.resolve()/'boot-pdx234-pac-abi-058.img';target.write_bytes(image)
    result=copy.deepcopy(record)
    result.update(image=str(target),bytes=len(image),sha256=helper.sha(image),label='PAC-ABI-058',
        source_image_sha256=BASELINE_SHA,source_release=str(a.release.resolve()),native_sha256=provenance['native_sha256'],
        strict_kernel_sha256=digest(raw_kernel),payload_kernel_sha256=digest(kernel),payload_sha256=digest(fat),bundle_sha256=helper.sha(bundle),
        kernel_args=arguments,screen_build_tag='PDX058',menu_title=after['ui']['title'],boot_screen=screen,
        expanded_native_data=provenance['expanded_native_data'],panic_screen=panic,crypto_seal=seal,
        framebuffer_call_trace=provenance['framebuffer_call_trace'],
        native_review_receipt=str((a.strict/'result.json').resolve()),strict_result_sha256=digest(a.strict/'result.json'),
        boot_screen_receipt=str((a.screen/'result.json').resolve()),boot_screen_receipt_sha256=digest(a.screen/'result.json'),
        boot_screen_verification_receipt=str(a.tests.resolve()),boot_screen_verification_sha256=digest(a.tests),
        arguments_removed=['build-tag=PDX057'],arguments_added=['build-tag=PDX058',*DIAGNOSTIC_ARGUMENTS],
        first_frame_diagnostics=True,first_frame_diagnostic_arguments=list(DIAGNOSTIC_ARGUMENTS),
        swift_trap_diagnostic=swift,
        menu_qemu_receipt=str(menu_test/'result.json'),menu_qemu_receipt_sha256=digest(menu_test/'result.json'),
        baseline_arguments_unchanged=False,comparison_release=None,comparison_image_sha256=None,comparison_kernel_byte_identity=False,
        staging_only=False,correction='Expose first-frame client failures, render roles, fence progress, display state and per-name process exits together',
        functional_first_frame_fix_claimed=False,hardware_boot_verified=False,desktop_verified=False,device_writes=False)
    helper.write_json(a.out/'release.json',result)
    (a.out/'SHA256SUMS').write_text(result['sha256']+'  '+target.name+'\n')
    final=helper.readback(a.out,a.work/'final-readback.log')
    if final['fat']!=fat.read_bytes() or final['fd']!=baseline['fd'] or final['android']!=baseline['android']:raise ValueError('Final readback differs')
    helper.write_json(a.work/'report.json',dict(passed=True,image=str(target),sha256=result['sha256'],changed=sorted(changed),commands=commands,
        packager_sha256=digest(__file__),hardware_verified=False,desktop_verified=False))
    print(json.dumps(dict(image=str(target),sha256=result['sha256'],desktop_verified=False),indent=2))


if __name__=='__main__':main()
