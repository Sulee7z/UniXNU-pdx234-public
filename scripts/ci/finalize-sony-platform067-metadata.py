#!/usr/bin/env python3
"""Replace inherited historical release labels with exact067 delta metadata.

The IMG is never changed. The original generated receipt is preserved beside a
hash-bound normalization record, so historical evidence is not lost.
"""
import argparse
import copy
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'ci'))
from platform067.integration import sha


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release',type=Path,required=True)
    parser.add_argument('--baseline',type=Path,required=True)
    args=parser.parse_args()
    path=args.release/'release.json';j=json.loads(path.read_text())
    before=json.loads((args.baseline/'release.json').read_text())
    if j['label']!='PAC-ABI-067' or j['source_image_sha256']!=before['sha256'] or sha(args.release/Path(j['image']).name)!=j['sha256']:
        raise ValueError('Exact067/066 image provenance required')
    backup=args.release/'release.before-metadata-normalization.json'
    if backup.exists():raise ValueError('Preserve an existing metadata normalization')
    backup.write_bytes(path.read_bytes());original=copy.deepcopy(j)
    old_tokens=before['kernel_args'].split();new_tokens=j['kernel_args'].split()
    j.update(arguments_removed=[token for token in old_tokens if token not in new_tokens],
        arguments_added=[token for token in new_tokens if token not in old_tokens],
        correction='Physical066 plus completed touch-probe cleanup, official CPU/GPU governors with Sony OPP/real-contact boost, '
            '2GiB volatile Data seed, official addon length and exit/checkpoint logs, source-qualified experimental Power/VolumeUp. '
            'Radio and OLED drivers staged only; no actual panel120 mode backend.',
        first_frame_diagnostic_arguments=[],first_frame_diagnostic_arguments_disabled=['first-frame-diag=0','gpu-trace=0','sheng-gpu-trace=0'],
        cpu_runtime_recording_enabled=False,temporary_probe_cleanup=True,
        image_delivered=False,all_requested_features_complete=False)
    for key in ('ui_tests_receipt','ui_tests_sha256'):
        if key in j:j['historical066_'+key]=j.pop(key)
    j['metadata_normalization']=dict(original_receipt=str(backup),original_receipt_sha256=sha(backup),
        helper_sha256=sha(__file__),image_unchanged=True,scope='Historical release fields only; does not qualify new runtime behavior')
    path.write_text(json.dumps(j,indent=2)+'\n')
    changed={key:dict(before=original.get(key),after=j.get(key)) for key in set(original)|set(j) if original.get(key)!=j.get(key)}
    (args.release/'metadata-normalization.json').write_text(json.dumps(dict(passed=True,image_sha256=j['sha256'],
        original_receipt_sha256=sha(backup),normalized_receipt_sha256=sha(path),changed=changed),indent=2)+'\n')
    print(json.dumps(dict(passed=True,image_unchanged=True,sha256=j['sha256'],changed_fields=sorted(changed)),indent=2))


if __name__=='__main__':main()
