#!/usr/bin/env python3
"""Package059's GPU-on minimal matching selection over the exact058 payload."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import struct
import subprocess
import sys
import tomllib

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
BASELINE_SHA='45baa2f1799bc1ddda81dd3236b7d20ea78aeb8c0aec635697e29a5096b36331'
STRICT_SHA='a57854987d193a6f647dd41065f808879728e7c2ba381f362e8f208be4ce951f'
REMOVED={
    'com.apple.driver.AppleM2ScalerCSCDriver':['s5l8720x'],
    'com.apple.driver.IODARTFamily':['IODARTMapper'],
    'com.apple.iokit.IOAVFamily':['AppleARMIISAudioLinkDelegate','IOAVAudioDriver',
        'IOAVCECService','IOAVService','IOAVSplitDisplay'],
}


def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(filename))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def info(data):
    if struct.unpack_from('<I',data)[0]!=0xfeedfacf:raise ValueError('Require64bit Mach-O')
    at=32
    for _ in range(struct.unpack_from('<I',data,16)[0]):
        cmd,size=struct.unpack_from('<II',data,at)
        if size<8 or at+size>len(data):raise ValueError('Invalid Mach-O command')
        if cmd==0x19 and data[at+8:at+24].rstrip(b'\0')==b'__PRELINK_INFO':
            offset,length=struct.unpack_from('<QQ',data,at+40)
            if offset+length>len(data):raise ValueError('Prelink info outside image')
            return plistlib.loads(data[offset:offset+length].split(b'\0',1)[0])
        at+=size
    raise ValueError('Prelink info absent')


def matching_delta(before,after):
    old={row['CFBundleIdentifier']:row for row in info(before)['_PrelinkInfoDictionary']}
    new={row['CFBundleIdentifier']:row for row in info(after)['_PrelinkInfoDictionary']}
    if old.keys()!=new.keys():raise ValueError('Retained original member metadata changed')
    old_count=new_count=0
    for name,row in old.items():
        previous=row.get('IOKitPersonalities') or {};current=new[name].get('IOKitPersonalities') or {}
        old_count+=len(previous);new_count+=len(current)
        if name in REMOVED:
            if sorted(previous)!=REMOVED[name] or current:raise ValueError('Optional matching delta differs: '+name)
        elif previous!=current:raise ValueError('Required matching changed: '+name)
        if {k:v for k,v in row.items() if k!='IOKitPersonalities'}!={k:v for k,v in new[name].items() if k!='IOKitPersonalities'}:
            raise ValueError('Non-personality member metadata changed: '+name)
    if (old_count,new_count)!=(32,25):raise ValueError('Unexpected matching counts')
    return dict(before=old_count,after=new_count,removed=REMOVED,
        metadata_sha256=hashlib.sha256(plistlib.dumps({k:v.get('IOKitPersonalities') or {} for k,v in new.items()},sort_keys=True)).hexdigest())


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('release','audit','strict','work','out'):parser.add_argument('--'+key,type=Path,required=True)
    args=parser.parse_args()
    helpers=load('minimal_helpers','package-d27-reviewed-native.py')
    release=load('minimal_release','release-d27-pac-abi.py')
    transport=load('minimal_transport','package-d27-metal-refresh.py')
    helpers.require_space()
    if args.work.exists() or args.out.exists():parser.error('Require fresh output directories')
    audit=json.loads(args.audit.read_text())
    profile_path=ROOT/'profiles/ios-27.0.1-24A446-iphone14/minimal-graphics-prelink.toml'
    profile=tomllib.loads(profile_path.read_text())
    if (not audit.get('passed') or audit['release_sha256']!=BASELINE_SHA or
        audit['minimal_profile_roots']!=profile['kernel']['prelink']['roots'] or len(audit['minimal_profile_roots'])!=10):
        raise ValueError('Require the reviewed ten-root058 baseline audit')
    for path,expected in audit['source_identities'].items():
        if digest(path)!=expected:raise ValueError('Audited input changed: '+path)
    args.work.mkdir(parents=True)
    baseline=helpers.readback(args.release,args.work/'baseline-readback.log');prior=baseline['j']
    if prior['sha256']!=BASELINE_SHA or not prior['gpu_enabled'] or not prior['cdc_disabled']:
        raise ValueError('Require exact058 GPU-on/CDC-off release')
    provenance=json.loads((args.strict/'result.json').read_text())
    strict=json.loads((args.strict/'kernel.json').read_text())
    raw_path=args.strict/'kernel.macho';raw_kernel=raw_path.read_bytes()
    if (helpers.sha(raw_kernel)!=STRICT_SHA or provenance['candidate_sha256']!=STRICT_SHA or
        strict['candidate_sha256']!=STRICT_SHA or strict['missing'] or strict['stubbed'] or strict['allow_missing'] or
        not strict['candidate_written'] or not provenance['pac_enabled'] or provenance['pac_metadata_adapters'] or
        provenance['auth_instruction_patches'] or not provenance.get('minimal_drivers')):
        raise ValueError('Require complete strict minimal collection preserving PAC')
    selected=provenance['selected_profile']
    if (selected['sha256']!=digest(profile_path) or selected['path']!=str(profile_path.resolve()) or
        selected['roots']!=audit['minimal_profile_roots'] or provenance['native_sha256']!=prior['native_sha256']):
        raise ValueError('Minimal profile/native identity differs from audit')
    for key in ('gpu_source','display_source','boot_screen','framebuffer_call_trace','usb_sources'):
        if provenance[key]!=prior[key]:raise ValueError('058 implementation changed: '+key)
    old_strict_path=Path(prior['native_review_receipt'])
    if digest(old_strict_path)!=prior['strict_result_sha256']:raise ValueError('058 strict receipt changed')
    original_strict=json.loads(old_strict_path.with_name('kernel.json').read_text())
    if (strict['closure']!=original_strict['closure'] or
        set(strict['personalities_dropped'])-set(original_strict['personalities_dropped'])!=set(REMOVED) or
        not set(original_strict['personalities_dropped'])<=set(strict['personalities_dropped'])):
        raise ValueError('Minimal original dependency closure differs')
    baseline_kernel=baseline['get']('EFI/UniXNU/Payloads/kernel.macho')
    delta=matching_delta(baseline_kernel,raw_kernel)
    if sorted(sum(REMOVED.values(),[]))!=sorted(audit['matching_personalities_removed']):
        raise ValueError('Audited personality names differ')
    before_text=baseline['get']('EFI/UniXNU/unixnu.toml').decode();before=tomllib.loads(before_text)
    entry=next(row for row in before['entry'] if row['id']=='xnu');tokens=entry['args'].split()
    if tokens.count('cpufreq=1')!=1 or tokens.count('build-tag=PDX058')!=1:raise ValueError('Unexpected058 command line')
    arguments=' '.join('cpufreq=0' if t=='cpufreq=1' else 'build-tag=PDX059' if t=='build-tag=PDX058' else t for t in tokens)
    text=release.replace_config_arguments(before_text,entry['args'],arguments).replace('PAC-ABI-058','PAC-ABI-059')
    expected=copy.deepcopy(before);expected['ui']['title']=expected['ui']['title'].replace('058','059')
    next(row for row in expected['entry'] if row['id']=='xnu')['args']=arguments
    after=tomllib.loads(text)
    if after!=expected or after['boot']['timeout']!=-1 or after['boot']['default']!='xnu':raise ValueError('Unexpected menu delta')
    if 'confirm' in next(row for row in after['entry'] if row['id']=='xnu'):raise ValueError('Default confirmation conflict')
    menu=BASE/'tmp/minimal-driver-menu059-v2';menu_receipt=json.loads((menu/'result.json').read_text())
    if not menu_receipt['passed'] or (menu/'unixnu.toml').read_bytes()!=text.encode() or menu_receipt['config_sha256']!=helpers.sha(text.encode()):
        raise ValueError('Final configuration differs from QEMU-tested menu bytes')
    release.run([sys.executable,'-B',ROOT/'scripts/ci/verify-d27-sdt.py','--strict',args.strict,'--out',args.work/'sdt-verified.json'],args.work/'sdt.log')
    kernel=args.work/'kernel.macho';kernel.write_bytes(raw_kernel)
    release.run([sys.executable,'-B',ROOT/'scripts/patch-panic-screen.py','--kernel',kernel,'--mainline',BASE/'sources/UniXNU',
                 '--uefi',ROOT.parent/'uefi-pdx234','--preserve-auth'],args.work/'panic-patch.log')
    panic=json.loads((args.work/'kernel.panic-screen.json').read_text())
    if not panic['auth_instructions_preserved'] or panic['source_kernel_sha256']!=STRICT_SHA:raise ValueError('Panic auth check failed')
    before_seal=kernel.read_bytes()
    release.run([sys.executable,'-B',BASE/'sources/UniXNU/scripts/seal-source-crypto-kernel.py',kernel,'--kernel-args',arguments],
                args.work/'seal.log',dict(os.environ,UNIXNU_XNU_ARCH='arm64e',UNIXNU_IOS_VERSION='27.0'))
    seal=json.loads((args.work/'kernel.macho.crypto-hmac.json').read_text());sealed=kernel.read_bytes()
    if seal['kernel_sha256']!=helpers.sha(sealed):raise ValueError('Seal identity mismatch')
    sys.path.insert(0,str(args.strict/'XnuPrelink'));from kc_image import Image
    initial=Image(before_seal);old_image=Image(baseline_kernel);final_image=Image(sealed)
    checked=0
    if initial.entries.keys()!=old_image.entries.keys():raise ValueError('Binary member selection changed')
    for name,(_,offset) in initial.entries.items():
        member=Image(before_seal,offset);old_member=Image(baseline_kernel,old_image.entries[name][1]);final_member=Image(sealed,final_image.entries[name][1])
        for segment in member.segments:
            prot=struct.unpack_from('<II',before_seal,segment['command_offset']+56)[1]
            if prot&4 and segment['filesize']:
                old_segment=next(s for s in old_member.segments if s['name']==segment['name'])
                current=next(s for s in final_member.segments if s['name']==segment['name'])
                start,size=segment['fileoff'],segment['filesize']
                if before_seal[start:start+size]!=sealed[start:start+size]:raise ValueError('Seal changed executable bytes')
                if (segment['va'],size)!=(old_segment['va'],old_segment['filesize']) or current['va']!=segment['va']:
                    raise ValueError('Executable layout changed')
                if sealed[current['fileoff']:current['fileoff']+size]!=baseline_kernel[old_segment['fileoff']:old_segment['fileoff']+size]:
                    raise ValueError('058 executable implementation changed: '+name)
                checked+=1
    if matching_delta(baseline_kernel,sealed)!=delta:raise ValueError('Packaged matching differs from strict candidate')
    release.run([sys.executable,'-B',ROOT/'scripts/ci/audit-darwinboot-parser.py','--darwinboot',ROOT/'.cache/firmware-components/DarwinBoot',
                 '--kernel',kernel,'--report',args.work/'darwinboot-parser.json'],args.work/'parser.log')
    if not json.loads((args.work/'darwinboot-parser.json').read_text())['accepted']:raise ValueError('Loader rejected collection')
    config=args.work/'unixnu.toml';config.write_text(text)
    fat=args.work/'payload.fat';fat.write_bytes(baseline['fat']);old_files=helpers.fat_inventory(fat)
    for local,remote in ((kernel,'Payloads/kernel.macho'),(config,'unixnu.toml')):
        os.utime(local,(315532800,315532800))
        subprocess.run(['mcopy','-o','-m','-i',str(fat),str(local),'::/EFI/UniXNU/'+remote],check=True)
    new_files=helpers.fat_inventory(fat);changed={name for name in old_files if old_files[name]!=new_files.get(name)}
    if old_files.keys()!=new_files.keys() or changed!={'EFI/UniXNU/unixnu.toml','EFI/UniXNU/Payloads/kernel.macho'}:raise ValueError('Unexpected FAT delta')
    image,blob,commands=transport.pack_transport(baseline,fat.read_bytes(),args.work,helpers)
    args.out.mkdir(parents=True);target=args.out.resolve()/'boot-pdx234-pac-abi-059.img';target.write_bytes(image)
    record=copy.deepcopy(prior)
    record.update(image=str(target),bytes=len(image),sha256=helpers.sha(image),label='PAC-ABI-059',
        source_image_sha256=BASELINE_SHA,source_release=str(args.release.resolve()),kernel_args=arguments,
        screen_build_tag='PDX059',menu_title=after['ui']['title'],
        arguments_removed=['cpufreq=1','build-tag=PDX058'],arguments_added=['cpufreq=0','build-tag=PDX059'],
        payload_kernel_sha256=helpers.sha(sealed),strict_kernel_sha256=STRICT_SHA,payload_sha256=digest(fat),bundle_sha256=helpers.sha(blob),
        minimal_driver_control=True,minimal_driver_audit=str(args.audit.resolve()),minimal_driver_audit_sha256=digest(args.audit),
        minimal_prelink_profile=str(profile_path.resolve()),minimal_prelink_profile_sha256=digest(profile_path),
        minimal_prelink_roots=selected['roots'],suppressed_matching_personalities=audit['matching_personalities_removed'],
        matching_selection=delta,prelink_personalities_dropped=strict['personalities_dropped'],original_binary_closure=len(strict['closure']),
        prelink_missing={},prelink_stubbed={},disabled_active_optional_driver='CpuFreqProbe (read-only EPSS observer)',
        baseline_kernel_byte_identity=False,native_kernel_byte_identity=True,retained_executable_bytes_unchanged=True,
        baseline_arguments_unchanged=False,selected_profile=selected,expanded_native_data=provenance['expanded_native_data'],
        native_review_receipt=str((args.strict/'result.json').resolve()),strict_result_sha256=digest(args.strict/'result.json'),
        panic_screen=panic,crypto_seal=seal,comparison_release=None,comparison_image_sha256=None,comparison_kernel_byte_identity=False,
        correction='GPU-on minimal-driver control: suppress seven optional scaler/DART/IOAV matching personalities and disable CPU-frequency observer',
        menu_qemu_receipt=str(menu/'result.json'),menu_qemu_receipt_sha256=digest(menu/'result.json'),
        functional_first_frame_fix_claimed=False,hardware_boot_verified=False,desktop_verified=False,device_writes=False)
    helpers.write_json(args.out/'release.json',record);(args.out/'SHA256SUMS').write_text(record['sha256']+'  '+target.name+'\n')
    final=helpers.readback(args.out,args.work/'final-readback.log')
    if final['fd']!=baseline['fd'] or final['android']!=baseline['android'] or final['get']('EFI/UniXNU/Payloads/kernel.macho')!=sealed:
        raise ValueError('Final readback differs')
    helpers.write_json(args.work/'report.json',dict(passed=True,image=str(target),sha256=record['sha256'],changed_files=sorted(changed),
        matching_selection=delta,executable_segments_unchanged=checked,commands=commands,packager_sha256=digest(__file__),hardware_verified=False,desktop_verified=False))
    print(json.dumps(dict(image=str(target),sha256=record['sha256'],kernel_sha256=record['payload_kernel_sha256'],matching=delta,desktop_verified=False),indent=2))


if __name__=='__main__':main()
