#!/usr/bin/env python3
"""Bind exact candidate feature boundaries and manually tested input prerequisites."""
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'ci'))
from platform067.integration import sha
from native_source_overlays import validate_overlays


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('native','platform-verification','seed-tests','out'):parser.add_argument('--'+key,type=Path,required=True)
    args=parser.parse_args()
    if args.out.exists():raise ValueError('Preserve existing candidate policies')
    n=json.loads((args.native/'result.json').read_text());v=json.loads(args.platform_verification.read_text())
    if sha(args.native/'native.macho')!=n['native_sha256'] or not v['passed'] or v['native_sha256']!=n['native_sha256']:
        raise ValueError('Actual selected candidate verification required')
    validate_overlays(n,sha)
    buttons=n['platform067_buttons'];radio=n['platform067_radio'];oled=n['platform067_oled']
    if (not buttons['source_qualified_experimental_power_volume_up'] or
            not buttons['tested_and_target_compiled_same_snapshot'] or buttons['pmic_register_writes'] or
            not buttons['linux_read_offsets_opcode_status_match']):
        raise ValueError('Source-qualified named PON observer route required')
    if radio['firmware']['wifi_ready'] or radio['firmware']['bluetooth_ready'] or oled['hardware_enabled']:
        raise ValueError('Policy does not cover newly qualified radio/brightness hardware')
    sparse=json.loads(args.seed_tests.read_text())
    if not sparse['passed'] or sparse['persistence_required'] or sparse['logical_bytes']!=2147483648:
        raise ValueError('Actually linked2GiB volatile boundary tests required')
    changes=dict(n['platform067_performance']['integration']['required_bootargs'])
    changes.update({'vsync':120,'first-frame-diag':0,'gpu-trace':0,'sheng-gpu-trace':0,
                    'sony-buttons':1,'sony-buttons-read-qualified':1,'sony-buttons-pon-apid':560,
                    'wifi':0,'bluetooth':0,'backlight':1,'storage-probe':1})
    features={
        'heat':dict(implemented=True,hardware_verified=False,
            limits='Official CPU mode4/GPU DCVS with Sony OPP/real-contact boost. No thermal governor or power-collapse; temperature effect unmeasured.'),
        'refresh':dict(implemented=False,hardware_verified=False,software_request_hz=120,
            limits='vsync120 is software request only. Sony panel120 HS/MDP/TE owner/commit and inherited-mode snapshot are not implemented.'),
        'app_exits':dict(implemented=True,hardware_verified=False,
            limits='Audited official addon-length hunk,2GiB RAM Data and official exit/checkpoint logging. Not a claim all app exits or Mach-port guards fixed.'),
        'wifi':dict(implemented=False,hardware_verified=False,core_linked=True,
            limits='Official125-object Ath12k plus Sony board glue linked; shared resource/ITS/DMA providers, firmware and signed supplicant missing. wifi0.'),
        'bluetooth':dict(implemented=False,hardware_verified=False,core_linked=True,
            limits='Official QcaBluetooth plus Sony UART14 adapter linked; resource/DMA/firmware/D27 daemon/runtime inputs missing. bluetooth0.'),
        'brightness':dict(implemented=False,hardware_verified=False,staged_driver_linked=True,
            limits='Sony dualDSI/OLED service compiled; no qualified command owner/clock/ULPS/panel readback. backlight1 refuses before MMIO/control publication.'),
        'power_key':dict(implemented=True,hardware_verified=False,experimental=True,
            limits='Power/VolumeUp source-qualified APID560 observer with sameboot map/owner checks. First real read, release and OS consumption untested; no VolumeDown/suspend/wake.'),
        'touch':dict(implemented=True,hardware_verified=False,
            limits='066 sensor-to-HID reports observed.067 removes temporary worker/painters while retaining production guards; new hardware regression not yet run.'),
    }
    paths=[args.native/'result.json',args.platform_verification,args.seed_tests,
           ROOT/'scripts/ci/package-sony-platform067.py',ROOT/'scripts/ci/verify-delivered-high-memory.py',
           ROOT/'scripts/ci/prepare-sony-platform067-policy.py']
    for name in ('platform067_performance','platform067_buttons','platform067_oled','platform067_radio'):
        if 'tests' in n[name] and Path(n[name]['tests']).is_file():paths.append(Path(n[name]['tests']))
    policy=dict(argument_changes=changes,feature_status=features,inputs={str(p):sha(p) for p in paths},
        volatile_seed_test=str(args.seed_tests),image_for_user_delivery=True,
        scope='Manual handset test candidate. Does not certify heat/FPS/radio/brightness/power-key hardware success.',
        all_requested_features_complete=False,hardware_features_verified=False,device_operations=False)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(policy,indent=2)+'\n')
    print(json.dumps(dict(policy=str(args.out),argument_changes=changes,feature_status=features),indent=2))


if __name__=='__main__':main()
