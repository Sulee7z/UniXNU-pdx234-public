#!/usr/bin/env python3
"""Select exact signed069 runtime inputs without changing any frozen package."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'ci'))
from platform069.codesign import inspect
from platform069.integration import sha
from platform069.launchd_cache import WIFI_JOB,inspect_detached_signature,transform_cache_bytes
from platform069.menu import BASELINE_IMAGE_SHA


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('bluetooth','wifi','firmware-manifest','cache','out'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--extra-receipt',type=Path,action='append',default=[],
        help='Additional signed runtime files/signed_files/inputs receipt, e.g. brightness')
    args=parser.parse_args()
    if args.out.exists():raise ValueError('Preserve existing runtime plans')
    bt=json.loads(args.bluetooth.read_text());wifi=json.loads(args.wifi.read_text())
    firmware=json.loads(args.firmware_manifest.read_text());cache=json.loads(args.cache.read_text())
    if (bt.get('passed') is not True or wifi.get('passed') is not True or
        bt['target']!='arm64e-apple-ios27.0' or wifi['target']!='arm64e-apple-ios27.0' or
        bt.get('hardware_verified') or wifi.get('hardware_verified') or
        bt.get('device_operations') or wifi.get('device_operations')):
        raise ValueError('Signed arm64e/iOS27 host-only radio inputs required')
    if (firmware['device']!='Sony XQ-DQ72' or len(firmware['files'])!=53 or
        firmware['dtb_sha256']!='6ab06c177a7131338cd8cc374b304838738497bf0d709a48ed50f0282c03bb8a'):
        raise ValueError('Exact captured Sony firmware inputs required')
    files=[];signed=[];inputs={};names=set()
    def pin(path):
        path=Path(path).resolve();value=sha(path)
        if str(path) in inputs and inputs[str(path)]!=value:raise ValueError('Input changed during planning')
        inputs[str(path)]=value;return path
    def add(name,source,mode,expected):
        if name in names:raise ValueError('Duplicate runtime selection: '+name)
        source=pin(source)
        if inputs[str(source)]!=expected:raise ValueError('Runtime source differs: '+str(source))
        names.add(name);files.append(dict(path=name,source=str(source),mode=mode,sha256=expected))
    def code(name,source,mode,expected,entitlement_hash,expected_cdhash):
        value=inspect(source)
        if (value['cdhash']!=expected_cdhash or
            hashlib.sha256(value['entitlements']).hexdigest()!=entitlement_hash):
            raise ValueError('Signed runtime identity/entitlements changed: '+name)
        add(name,source,mode,expected);signed.append(dict(path=name,entitlements_sha256=entitlement_hash))
    bt_signed={row['path']:row for row in bt['signed_files']}
    for row in bt['files']:
        if row['path'] in bt_signed:
            code(row['path'],row['source'],row['mode'],row['sha256'],
                bt_signed[row['path']]['entitlements_sha256'],bt['signature_checks'][row['path']]['cdhash'])
        else:add(row['path'],row['source'],row['mode'],row['sha256'])
    code('wifi-bin/unixnu-wpa_supplicant',wifi['binary'],0o755,wifi['sha256'],
        wifi['entitlements_sha256'],wifi['signature']['cdhash'])
    for row in firmware['files']:
        source=Path(row['staged']);parts=source.parts
        index=len(parts)-1-parts[::-1].index('firmware');relative='/'.join(parts[index:])
        if not row['phone_hash_matches'] or source.stat().st_size!=row['bytes']:
            raise ValueError('Sony firmware size/phone match failed')
        pin(row['path']);add(relative,source,0o644,row['sha256'])
    staged=cache['staged'];raw=Path(staged['cache_path']).read_bytes();signature=Path(staged['signature_path']).read_bytes()
    check=inspect_detached_signature(raw,signature,'launchd-'+hashlib.sha1(raw).hexdigest())
    if (check['cdhash']!=staged['signature']['cdhash'] or
        check['identification_wrapper']['matches_raw_plist_sha1'] is not True):
        raise ValueError('Detached launchd identity differs')
    original=pin(cache['original']['cache_path'])
    if inputs[str(original)]!=cache['original']['cache_sha256']:raise ValueError('Original launchd cache changed')
    expected,changes=transform_cache_bytes(original.read_bytes())
    if plistlib.loads(raw)!=expected or changes!=cache['transform']:
        raise ValueError('Cache transform differs from reviewed source')
    add('xpc/launchd.plist',staged['cache_path'],0o644,staged['cache_sha256'])
    add('xpc/launchd.plist.sig',staged['signature_path'],0o644,staged['signature']['detached_signature_sha256'])
    args.out.mkdir(parents=True,exist_ok=False);out=args.out.resolve()
    config=out/'wpa_supplicant.conf';config.write_text('# Networks arrive from the native Wi-Fi control channel.\nap_scan=1\n')
    add('etc/wifi/wpa_supplicant.conf',config,0o600,sha(config))
    job=out/'org.unixnu.wifi.supplicant.plist';job.write_bytes(plistlib.dumps(WIFI_JOB,sort_keys=False))
    add('daemons/'+job.name,job,0o644,sha(job))
    for receipt in args.extra_receipt:
        extra=json.loads(receipt.read_text());pin(receipt)
        if extra.get('passed') is not True or extra.get('device_operations') or extra.get('hardware_verified'):
            raise ValueError('Additional runtime receipt must be passing host-only qualification')
        wanted={row['path']:row for row in extra.get('signed_files',[])}
        for row in extra['files']:
            if row['path'] in wanted:
                value=inspect(row['source'])
                code(row['path'],row['source'],row['mode'],row['sha256'],
                    wanted[row['path']]['entitlements_sha256'],value['cdhash'])
            else:add(row['path'],row['source'],row['mode'],row['sha256'])
        for path,digest in extra.get('inputs',{}).items():
            if sha(pin(path))!=digest:raise ValueError('Additional runtime source input changed')
    for path in [args.bluetooth,args.wifi,args.firmware_manifest,args.cache,Path(__file__),
        ROOT/'ci/platform069/launchd_cache.py',ROOT/'ci/platform069/codesign.py']:
        pin(path)
    result=dict(baseline_image_sha256=BASELINE_IMAGE_SHA,inputs=inputs,files=files,signed_files=signed,
        detached_signed_files=[dict(path='xpc/launchd.plist',signature='xpc/launchd.plist.sig',cdhash=check['cdhash'])],
        launchd_cache_original=str(original),firmware_manifest=str(args.firmware_manifest.resolve()),
        hardware_verified=False,device_operations=False)
    (out/'plan.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(plan=str(out/'plan.json'),files=len(files),signed_executables=len(signed),
        detached_signatures=1,firmware_files=53,device_operations=False),indent=2))


if __name__=='__main__':main()
