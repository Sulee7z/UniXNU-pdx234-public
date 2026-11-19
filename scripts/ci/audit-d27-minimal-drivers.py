#!/usr/bin/env python3
"""Trace058's actual driver inputs before making a GPU-on minimal control."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tomllib

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
RELEASE_SHA='45baa2f1799bc1ddda81dd3236b7d20ea78aeb8c0aec635697e29a5096b36331'
ABSENT_STARTERS=('sheng_wifi_probe','sheng_bluetooth_probe','sheng_adsp_probe','sheng_audio_probe',
                 'sheng_battery_probe','native_touch_probe','sheng_keyboard_probe','sheng_video_probe',
                 'sheng_backlight_probe','sheng_buttons_probe')


def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    if a.out.exists():p.error('Use a fresh output file')
    release_path=ROOT/'out/d27-pac-abi-release-20261117-058/release.json'
    release=json.loads(release_path.read_text())
    if release['sha256']!=RELEASE_SHA:raise ValueError('Require exact058 release')
    native_path=BASE/'native-first-frame-058-001/native.macho'
    strict_path=BASE/'strict-first-frame-058-001/kernel.macho'
    if sha(native_path)!=release['native_sha256'] or sha(strict_path)!=release['strict_kernel_sha256']:
        raise ValueError('058 native or strict input changed')
    plan_path=BASE/'native-screen007-055-001/plan.json';plan=json.loads(plan_path.read_text())
    bsd=next(job for job in plan['jobs'] if Path(job['source']).name=='bsd_init.c')
    if sha(bsd['source'])!=bsd['source_sha256']:raise ValueError('Compiled native initializer changed')
    flags={value.split('=')[0]:value.split('=',1)[1] for value in bsd['command'] if value.startswith(('XNU_SHENG_','XNU_ADRENO_','XNU_SMMU4K_','XNU_CONSTANT_','XNU_NATIVE_')) and '=' in value}
    for flag in ('XNU_SHENG_PMGR','XNU_ADRENO_FIRMWARE_PROBE','XNU_ADRENO_PM4_PROBE','XNU_SMMU4K_PROBE','XNU_CONSTANT_UPLOADS_PROBE','XNU_NATIVE_OFFLINE_GPU'):
        if flags.get(flag)!='0':raise ValueError('Nonessential compiled probe selected: '+flag)
    display=BASE/'display-source-009/kits/sheng/LegacyDisplayProbe.cpp';text=display.read_text()
    if sha(display)!=release['display_source']['staged_probe_sha256']:raise ValueError('Compiled display initializer changed')
    start=text.index('void native_legacy_display_late_probe(void) {');end=text.index('    {\n        kern_return_t hid',start)
    calls=[line.strip() for line in text[start:end].splitlines() if line.strip() in ('native_keystore_probe();','sheng_cpufreq_probe();','sheng_gpu_power_probe();')]
    if calls!=['native_keystore_probe();','sheng_cpufreq_probe();','sheng_gpu_power_probe();']:raise ValueError('Unreviewed late driver sequence')
    symbols=subprocess.check_output(['llvm-nm','--defined-only',str(native_path)],text=True)
    absent={name:not any(line.split()[-1]=='_'+name for line in symbols.splitlines() if line.split()) for name in ABSENT_STARTERS}
    if not all(absent.values()):raise ValueError('Unexpected board peripheral startup definition')
    frequency=BASE/'display-source-009/kits/sheng/CpuFreqProbe.cpp';freq=frequency.read_text()
    if 'if (!mode || gLock) return;' not in freq or 'if (!gMode || !gLock) return;' not in freq:
        raise ValueError('CPU-frequency disable gates changed')
    probe_start=freq.index('extern "C" void sheng_cpufreq_probe(void)')
    probe=freq[probe_start:]
    if probe.index('if (!mode || gLock) return;')>probe.index('gLock = IOLockAlloc();') or probe.index('if (!mode || gLock) return;')>probe.index('mapWindow('):
        raise ValueError('CPU-frequency zero mode no longer avoids mapping')
    usb=ROOT/'ci/usb/PdxUsbWorker.c';usb_text=usb.read_text()
    gate='if (!PE_parse_boot_argn("qcom-usb-debug", &enabled, sizeof(enabled)) || enabled != 1) return;'
    if gate not in usb_text:raise ValueError('USB disable gate changed')
    args=release['kernel_args'].split()
    for expected in ('cpufreq=1','qcom-usb-debug=0','gpu-power=9','gpu-metal=1','sheng-gpu-addon=1','fb-gpu=1','dpu-scanout=0','offline-key-events=1'):
        if args.count(expected)!=1:raise ValueError('Unexpected effective058 argument: '+expected)
    closure=json.loads((BASE/'strict-first-frame-058-001/kernel.json').read_text())['closure']
    minimal_profile=tomllib.loads((ROOT/'profiles/ios-27.0.1-24A446-iphone14/minimal-graphics-prelink.toml').read_text())
    roots=minimal_profile['kernel']['prelink']['roots']
    required={'com.apple.filesystems.apfs','com.apple.driver.AppleMobileFileIntegrity','com.apple.iokit.IOStorageFamily',
              'com.apple.AppleFSCompression.AppleFSCompressionTypeZlib','com.apple.security.sandbox','com.apple.iokit.IOSurface',
              'com.apple.iokit.IOMobileGraphicsFamily','com.apple.iokit.IOGPUFamily','com.apple.iokit.IOHIDFamily'}
    if len(roots)!=10 or not required.issubset(roots) or 'com.apple.security.AppleImage4' not in roots or any(name in roots for name in (
        'com.apple.driver.AppleM2ScalerCSCDriver','com.apple.driver.IODARTFamily','com.apple.iokit.IOAVFamily')):
        raise ValueError('Minimal profile must contain the exact required nine-root subset')
    inputs=[release_path,native_path,strict_path,plan_path,Path(bsd['source']),display,frequency,usb,
            BASE/'native-first-frame-058-001/native-link.command.json',BASE/'strict-first-frame-058-001/kernel.json',
            ROOT/'profiles/ios-27.0.1-24A446-iphone14/minimal-graphics-prelink.toml']
    result=dict(passed=True,release_sha256=RELEASE_SHA,source_identities={str(path):sha(path) for path in inputs},
        official_references=['https://unixnu.com/zh/porting/drivers#_2-按硬件依赖顺序操作',
                             'https://unixnu.com/porting/platform#block-and-os-services',
                             'https://unixnu.com/reference/components','https://unixnu.com/xnu/boot-arguments'],
        late_driver_calls=calls,compiled_probe_flags=flags,absent_board_startup_symbols=absent,
        selected_optional_to_disable='cpufreq=1 -> cpufreq=0 (EPSS read-only probe)',
        minimal_profile_roots=roots,original_closure_entries=len(closure),
        binary_dependencies_preserved=['AppleM2ScalerCSCDriver','IODARTFamily','IOAVFamily','IOCECFamily','IOHDCPFamily','AppleAudioClockLibs','AppleIISController','IOAudio2Family','Libm','ApplePMGR','AppleARMWatchdogTimer'],
        security_identity_explicitly_retained='com.apple.security.AppleImage4',
        matching_personalities_removed=['s5l8720x','IODARTMapper','AppleARMIISAudioLinkDelegate','IOAVAudioDriver','IOAVCECService','IOAVService','IOAVSplitDisplay'],
        newly_suppressed_kext_bundles=['com.apple.driver.AppleM2ScalerCSCDriver','com.apple.driver.IODARTFamily','com.apple.iokit.IOAVFamily'],
        zero_mode_gate='Returns before lock allocation or mapping; subsequent polling returns before MMIO',
        essential_paths_retained=['CPU/GIC/timer/RAM','UFS/SMMU/verified root/Data','Crypto/AMFI/sandbox/KeyStore state and events',
                                  'GOP/IOMobileFramebuffer/IOSurface/IOHID logical families','Adreno740/Metal/Turnip and power/firmware/compiler dependencies'],
        prelinked_original_closure=closure,
        caution='Included original OS family does not imply its hardware driver started. Remove only dependency-qualified components; a userspace daemon name does not prove its hardware driver is enabled.',
        device_operations=False,hardware_verified=False)
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(passed=True,late_driver_calls=calls,absent_peripheral_starters=len(absent),optional_to_disable=result['selected_optional_to_disable']),indent=2))


if __name__=='__main__':main()
