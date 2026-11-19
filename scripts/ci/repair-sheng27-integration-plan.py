#!/usr/bin/env python3
"""Record current repair evidence without treating inventory as semantic review."""
import argparse
import json
from pathlib import Path

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--audit',type=Path,required=True)
    args=parser.parse_args()
    audit=json.loads((args.audit/'summary.json').read_text())
    receipts=json.loads((args.audit/'component-receipts.json').read_text())
    strict=json.loads((Path(audit['strict'])/'result.json').read_text())
    removed=sorted(audit['removed_initializers'])
    plan=dict(
        status='initial inventory and patch replay complete; full semantic and hardware review ongoing',
        pinned_sheng_commit='1108068537d5396edb2c63b2f8c6f5b97b0a4bbc',
        pinned_core_commit='82b847c4ac3f68a57024b3082ffa3a03442defd9',
        source_replay=dict(patches=89,touched_files=125,differences=4,
            difference_descriptions=[
                'bsd/kern/kern_exec.c: D27 spawn-wire ABI and sanitizer entitlement source overlay',
                'config/Private.exports: D27 Image4 V2 no-monitor exports',
                'libkern/image4/image4_v2.c: D27 no-monitor compatibility exports',
                'security/mac_vfs.c: historical suppression restored by audit-source-repairs; readonly SDT consumer added'],
            action='retain only with per-file D27 receipt; no silent upstream overwrite'),
        compiled_source_identity=dict(native_jobs=audit['native_jobs'],
            failures=len(audit['native_source_identity_failures']),
            source_hashes_match=not audit['native_source_identity_failures']),
        candidate=dict(path=strict['candidate'],sha256=strict['candidate_sha256'],
            missing=strict['strict_missing'],stubbed=strict['strict_stubbed'],packaged=False),
        component_receipts=receipts,
        omitted_initializers=removed,
        repair_units=[
            dict(id='memory-vnodes',action='already-repaired-in029',evidence='resource_limits.py;029 ADT readback',remaining='hardware effect'),
            dict(id='apple-keystore-events',action='already-repaired-in027',evidence='offline-key-events=1; AKS opens/calls in027',remaining='hardware follow-up'),
            dict(id='darwinboot-headless-console',action='already-repaired-in031',evidence='darwinboot-dxe-log.patch; photo030 assertion',remaining='hardware follow-up'),
            dict(id='display-core',action='present-but-incomplete',reference_settings=['offline-legacy-register','offline-legacy-gop','offline-legacy-cpu-present','offline-legacy-phase','vsync=120','vsync-fixed=1','backlight properties'],
                 blocked_by='Sony panel/backlight ABI not yet matched'),
            dict(id='native-initializers',action='audit-each-removed-call',functions=removed,
                 rule='enable only where Sony hardware input and D27 ABI receipt exist; no sheng tablet resource copy'),
            dict(id='userspace-metal',action='qualified-build-exists-but-D27-runtime-unverified',
                 evidence='metal-d27-qualified-001 removes J820 absolute accesses; metal-package-002 addon/trust signed and verified',
                 next='integrate package into release and verify readback; GPU runtime unverified'),
            dict(id='header-cache',action='implemented-and-native-freshly-rebuilt',
                 evidence='compile_dependencies.py; native-audit-004 zero reuse, 5028 dependencies',
                 remaining='external archive dependency receipts'),
            dict(id='prelink-closure',action='profile-root-closure-present',
                 roots='full-sheng iPadOS27 root set requires D27 identity derivation',
                 next='compare every iPad root against D27 original and archive receipt'),
            dict(id='outside-memory',action='not-yet-applied',
                 rule='macOS outside-memory patches excluded; first qualify sheng iPad contiguous window with031 console fix'),
        ],
        argument_differences=audit['argument_differences'],
        hardware_verified=False,
        device_operations=False)
    (args.audit/'repair-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    print(json.dumps(dict(removed_initializers=len(removed),argument_differences=len(audit['argument_differences']),repair_units=len(plan['repair_units'])),indent=2))

if __name__=='__main__':main()
