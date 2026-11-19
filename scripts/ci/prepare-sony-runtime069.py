#!/usr/bin/env python3
"""Merge reviewed069 runtime files into actual068 addon; retain all prior trust."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'ci'))
from pdx_boot_transport import BootTransport
from platform069.addon import append_trust,decode,encode,trust_modules
from platform069.integration import sha
from platform069.menu import BASELINE_IMAGE_SHA
from platform069.codesign import inspect
from platform069.launchd_cache import inspect_detached_signature,transform_cache_bytes


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('release','plan','out'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    prior=json.loads((args.release/'release.json').read_text());plan=json.loads(args.plan.read_text())
    if prior['sha256']!=BASELINE_IMAGE_SHA or plan.get('baseline_image_sha256')!=BASELINE_IMAGE_SHA:
        raise ValueError('Exact actually booted068 baseline required')
    if args.out.exists():raise ValueError('Preserve prior runtime outputs')
    for path,digest in plan['inputs'].items():
        if sha(path)!=digest:raise ValueError('Reviewed runtime input differs: '+path)
    before=BootTransport(args.release/Path(prior['image']).name,BASELINE_IMAGE_SHA)
    old_addon=before.get('EFI/UniXNU/Payloads/kernel.macho.gpuaddon')
    old_trust=before.get('EFI/UniXNU/Payloads/kernel.macho.trustcache')
    original=decode(old_addon);files=copy.deepcopy(original);changed=[];names=set()
    for row in plan['files']:
        name=row['path'];source=Path(row['source']);data=source.read_bytes()
        if name in names or plan['inputs'].get(str(source))!=row['sha256'] or sha(source)!=row['sha256']:
            raise ValueError('Duplicate or unreviewed runtime file: '+name)
        names.add(name)
        if name in original:
            if hashlib.sha256(original[name]['data']).hexdigest()!=row.get('previous_sha256'):
                raise ValueError('Replacement lacks exact existing068 identity: '+name)
        elif row.get('previous_sha256') is not None:raise ValueError('Expected replacement is not in068 addon')
        files[name]=dict(data=data,mode=row['mode']);changed.append(name)
    addon_bytes=encode(files)
    if decode(addon_bytes)!=files:raise ValueError('Runtime addon readback differs')
    for name,row in original.items():
        if name not in names and files[name]!=row:raise ValueError('Unrelated068 runtime member changed')
    args.out.mkdir(parents=True,exist_ok=False);out=args.out.resolve();stage=out/'stage'
    for name,row in files.items():
        target=stage/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(row['data']);target.chmod(row['mode'])
    signatures={};cdhashes=[]
    for key,path in (('plugin',stage/'addons/NativeAdrenoMetal.bundle'),
                     ('turnip',stage/'addons/NativeAdrenoMetal.bundle/libvulkan_freedreno.dylib')):
        value=inspect(path);value.pop('entitlements')
        if value!=prior['metal_runtime']['signature_checks'][key]:raise ValueError('Qualified Metal signature changed')
        signatures[key]=value;cdhashes.append(value['cdhash'])
    signed_plan={row['path']:row for row in plan.get('signed_files',[])}
    if len(signed_plan)!=len(plan.get('signed_files',[])):raise ValueError('Duplicate signed runtime entry')
    extra_checks={}
    for name in changed:
        data=files[name]['data']
        if data[:4] not in (b'\xcf\xfa\xed\xfe',b'\xca\xfe\xba\xbe',b'\xbe\xba\xfe\xca'):
            if name in signed_plan:raise ValueError('Signature plan refers to a non Mach-O entry')
            continue
        if name not in signed_plan:raise ValueError('Unsigned/unreviewed new Mach-O addon: '+name)
        value=inspect(stage/name);entitlements=value.pop('entitlements')
        entitlement_hash=hashlib.sha256(entitlements).hexdigest()
        if entitlement_hash!=signed_plan[name]['entitlements_sha256']:
            raise ValueError('Runtime entitlements differ from reviewed signed build: '+name)
        extra_checks[name]=dict(value,entitlements_sha256=entitlement_hash);cdhashes.append(value['cdhash'])
    if set(extra_checks)!=set(signed_plan):raise ValueError('Unselected signed runtime file')
    detached_checks={}
    for row in plan.get('detached_signed_files',[]):
        name=row['path'];signature=row['signature']
        if (name in detached_checks or name not in changed or signature not in changed or
            name in signed_plan or signature in signed_plan):
            raise ValueError('Missing, duplicate or unselected detached runtime signature')
        data=files[name]['data'];sig=files[signature]['data']
        identifier='launchd-'+hashlib.sha1(data).hexdigest()
        value=inspect_detached_signature(data,sig,identifier)
        if value['cdhash']!=row['cdhash'] or files[name]['mode']!=0o644 or files[signature]['mode']!=0o644:
            raise ValueError('Detached signature identity/mode differs')
        detached_checks[name]=dict(value,signature_path=signature,
            data_sha256=hashlib.sha256(data).hexdigest(),signature_sha256=hashlib.sha256(sig).hexdigest(),
            signature_pages_verified=True,target_runtime_acceptance_verified=False)
        cdhashes.append(value['cdhash'])
    cache_record=None
    if detached_checks:
        if set(detached_checks)!={'xpc/launchd.plist'} or detached_checks['xpc/launchd.plist']['signature_path']!='xpc/launchd.plist.sig':
            raise ValueError('Only the source-qualified launchd cache has detached signatures')
        original_path=Path(plan['launchd_cache_original'])
        if plan['inputs'].get(str(original_path))!=sha(original_path):raise ValueError('Original launchd cache identity missing')
        original_bytes=original_path.read_bytes();expected,transform=transform_cache_bytes(original_bytes)
        import plistlib
        if plistlib.loads(files['xpc/launchd.plist']['data'])!=expected:
            raise ValueError('Final launchd cache differs from the exact qualified transform')
        cache_record=dict(source_sha256=hashlib.sha256(original_bytes).hexdigest(),
            transform=transform,original=str(original_path),original_jobs=transform['source_jobs'],
            runtime_jobs=transform['staged_jobs'],source_jobs_and_limits_preserved=True,
            apple_loader_runtime_acceptance_verified=False)
    firmware_record=None
    if plan.get('firmware_manifest'):
        manifest_path=Path(plan['firmware_manifest'])
        if plan['inputs'].get(str(manifest_path))!=sha(manifest_path):raise ValueError('Firmware manifest is not hash-bound')
        manifest=json.loads(manifest_path.read_text());firmware_files={}
        if manifest['device']!='Sony XQ-DQ72' or len(manifest['files'])!=53:
            raise ValueError('Complete Sony radio firmware inputs required')
        for row in manifest['files']:
            staged=Path(row['staged']);parts=staged.parts
            if 'firmware' not in parts:raise ValueError('Firmware source has no exact addon-relative prefix')
            at=len(parts)-1-parts[::-1].index('firmware');relative='/'.join(parts[at:])
            if relative in firmware_files or relative not in changed or row['phone_hash_matches'] is not True:
                raise ValueError('Unselected, duplicate or unverified Sony firmware')
            actual=files[relative]
            if (len(actual['data'])!=row['bytes'] or hashlib.sha256(actual['data']).hexdigest()!=row['sha256'] or actual['mode']!=0o644):
                raise ValueError('Final runtime Sony firmware differs from capture: '+relative)
            firmware_files[relative]=dict(sha256=row['sha256'],bytes=row['bytes'],android_path=row['android_path'])
        firmware_record=dict(manifest_sha256=sha(manifest_path),files=firmware_files,
            dtb_sha256=manifest['dtb_sha256'],phone_hashes_matched=True,bluetooth_nvm_selection='runtime ROM/BID query',
            connection_or_pairing_verified=False)
    # Include the existing Metal identities in the new owner module for the
    # inherited reader contract. Every original module, even the068 owner
    # module, is retained byte-for-byte rather than replaced.
    trust_bytes=append_trust(old_trust,cdhashes) if extra_checks or detached_checks else old_trust
    before_modules=trust_modules(old_trust);after_modules=trust_modules(trust_bytes)
    if after_modules[:len(before_modules)]!=before_modules:raise ValueError('An existing trust module changed')
    addon=out/'kernel.macho.gpuaddon';addon.write_bytes(addon_bytes)
    trust=out/'kernel.macho.trustcache';trust.write_bytes(trust_bytes)
    record=copy.deepcopy(prior['metal_runtime'])
    record.update(addon=str(addon),addon_sha256=sha(addon),trust=str(trust),trust_sha256=sha(trust),
        files=[dict(path=name,mode=row['mode'],bytes=len(row['data']),sha256=hashlib.sha256(row['data']).hexdigest()) for name,row in files.items()],
        signature_checks=signatures,extra_signature_checks=extra_checks,detached_signature_checks=detached_checks,
        launchd_cache=cache_record,radio_firmware=firmware_record,signature_pages_verified=True,
        original_trust_modules_unchanged=True,all068_trust_modules_retained=True,
        original068_trust_module_count=len(before_modules),trust_module_count=len(after_modules),
        source_addon_sha256=hashlib.sha256(old_addon).hexdigest(),source_trust_sha256=hashlib.sha256(old_trust).hexdigest(),
        baseline_image_sha256=BASELINE_IMAGE_SHA,plan=str(args.plan),plan_sha256=sha(args.plan),
        changed_or_added_files=sorted(changed),unrelated068_runtime_members_preserved=True,
        target='arm64e-apple-ios27.0',device_operations=False,runtime_verified=False)
    (out/'result.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
