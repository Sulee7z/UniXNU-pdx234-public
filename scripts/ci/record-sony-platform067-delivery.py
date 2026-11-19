#!/usr/bin/env python3
"""Record a candidate only after independent final transport readback and file hash."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'ci'))
from platform067.integration import sha
from darwin_boot_args import validate as validate_boot_arguments


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release',type=Path,required=True)
    parser.add_argument('--linux-readback',type=Path,required=True)
    parser.add_argument('--windows-readback',type=Path,required=True)
    parser.add_argument('--windows-filehash',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    if args.out.exists():raise ValueError('Preserve prior delivery evidence')
    j=json.loads((args.release/'release.json').read_text());image=args.release/Path(j['image']).name
    validate_boot_arguments(j['kernel_args'])
    if (j['label']!='PAC-ABI-067' or sha(image)!=j['sha256'] or image.stat().st_size!=j['bytes'] or
            j['staging_only'] or not j['ready_for_manual_test']):
        raise ValueError('Completed manual-test candidate required, not a staging fixture')
    readbacks=[]
    for path in (args.linux_readback,args.windows_readback):
        v=json.loads(path.read_text())
        for key in ('image_sha256','firmware_sha256'):
            if v[key]!=j['sha256' if key=='image_sha256' else key]:raise ValueError('Readback identity differs')
        for key in ('raw_lzma_crc_verified','windows_independent_fat_readback','physical066_and_blocks_inherited',
                    'persistence_disabled','temporary_touch_probes_and_painters_removed',
                    'sony_governors_enabled_and_software_vsync120_requested'):
            if v.get(key) is not True:raise ValueError('Required final readback check missing: '+key)
        if v['volatile_data_seed_mib']!=2048 or v['sony_buttons_final_pac_slots']!=207 or v['sony_oled_final_pac_slots']!=168:
            raise ValueError('Final Data or driver ABI extent differs')
        readbacks.append(dict(path=str(path),sha256=sha(path)))
    windows=json.loads(args.windows_filehash.read_text())
    if windows['sha256'].lower()!=j['sha256'] or windows['bytes']!=j['bytes'] or windows['platform']!='Windows':
        raise ValueError('Separate Windows file hash required')
    status=j['platform067_feature_status']
    if any(v['hardware_verified'] for v in status.values()):raise ValueError('Candidate not yet handset-tested')
    record=dict(date='2026-11-18',image=str(image),bytes=j['bytes'],sha256=j['sha256'],
        native_sha256=j['native_sha256'],strict_sha256=j['strict_kernel_sha256'],
        sealed_sha256=j['payload_kernel_sha256'],source_image_sha256=j['source_image_sha256'],
        release_receipt=str(args.release/'release.json'),release_receipt_sha256=sha(args.release/'release.json'),
        readbacks=readbacks,separate_windows_filehash=dict(path=str(args.windows_filehash),sha256=sha(args.windows_filehash)),
        full_profile_roots=19,closure_entries=38,matching_personalities=32,original_kmod_pac_fields=36,
        signed_blocks_inputs=66,touch_hid_pac_slots=207,buttons_hid_pac_slots=207,oled_service_pac_slots=168,
        cdc_disabled=True,gpu_enabled=True,pac_amfi_trust_verified_root_retained=True,
        volatile_data_seed_mib=2048,data_persist=0,feature_status=status,
        all_requested_features_complete=False,image_delivered=True,manual_test_candidate=True,
        hardware_verified=False,device_operations=False,commit_or_push=False,
        limits='Wi-Fi/Bluetooth/physical brightness/actual panel120 remain incomplete; '
               'Power/VolumeUp and governors are source-qualified experimental hardware paths, not validated repairs.')
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(dict(image=str(image),bytes=j['bytes'],sha256=j['sha256'],
        delivered_candidate=True,all_requested_features_complete=False,hardware_verified=False),indent=2))


if __name__=='__main__':main()
