#!/usr/bin/env python3
"""Record tested performance artifacts and immutable post066 evidence; no device I/O."""
from __future__ import annotations
import argparse
import difflib
import json
from pathlib import Path
import re
import subprocess
import sys

from source import sha

ROOT=Path(__file__).resolve().parents[3]
SNAP=Path('/mnt/f/UniXNU-Port-artifacts/platform067-20261118')
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
CAPTURE=Path('/mnt/g/UniXNU-Port/evidence/Xperia-XQ-DQ72/20261118-platform-post066-readonly-001')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build',type=Path,default=SNAP/'performance-006')
    p.add_argument('--tests',type=Path,default=SNAP/'performance-tests-007')
    a=p.parse_args()
    build=json.loads((a.build/'result.json').read_text())
    tests=json.loads((a.tests/'result.json').read_text())
    if not tests['passed'] or sha(a.build/'result.json')!=tests['build_receipt_sha256']:
        raise ValueError('Test receipt not bound to this build')
    unit=subprocess.run([sys.executable,'-B','-m','unittest','discover','-s',str(ROOT/'tests'),
                         '-p','sony_platform_performance_tests.py','-v'],capture_output=True,text=True,timeout=60)
    if unit.returncode:raise RuntimeError(unit.stdout+unit.stderr)
    (a.tests/'python-tests.log').write_text(unit.stdout+unit.stderr)
    api={}
    for name,row in build['gpu_api_audit'].items():
        old=BASE/'gpu-source-006/drivers/Adreno740'/name
        new=SNAP/'Adreno740'/name
        diff=''.join(difflib.unified_diff(old.read_text().splitlines(keepends=True),new.read_text().splitlines(keepends=True),
                                        fromfile='selected/'+name,tofile='latest/'+name))
        path=a.build/('api-diff-'+name+'.txt');path.write_text(diff)
        api[name]=dict(**row,identical=not diff,diff=str(path),diff_sha256=sha(path))
    release=ROOT/'out/d27-pac-abi-release-20261118-066/release.json'
    args=json.loads(release.read_text())['kernel_args'].split()
    knobs=dict(token.split('=',1) for token in args if '=' in token)
    msg=CAPTURE/'decoded/PDX066-3e181303/msgbuf.txt'
    slots=CAPTURE/'decoded/PDX066-3e181303/slots.txt'
    header=CAPTURE/'decoded/PDX066-3e181303/header.txt'
    text=msg.read_text(errors='replace')
    counts={name:len(re.findall(pattern,text)) for name,pattern in (
        ('explicit_ENOSPC',r'ENOSPC'),('no_space_text',r'No space left on device'),
        ('cannot_enter_shrink_transaction',r'cannot enter tx size'),
        ('metal_cache_write_denial',r'deny\(1\) file-write-create /private/var/mobile/Library/Caches/org\.unixnu\.metal/'))}
    disassembly=subprocess.check_output(['llvm-objdump','--disassemble-symbols=_sheng_cpu_idle_mach',
                                        build['baseline']+'/native.macho'],text=True)
    if '_recount_processor_usage' not in disassembly or 'pacibsp' not in disassembly or 'retab' not in disassembly:
        raise ValueError('Actual native idle helper body differs')
    (a.build/'native-idle-helper.txt').write_text(disassembly)
    evidence=dict(date='2026-11-18',scope='isolated platform067 CPU/GPU governor and read-only display cadence integration',
                  official_docs=['https://unixnu.com/zh/porting/power','https://unixnu.com/zh/porting/display','https://unixnu.com/zh/porting/gpu'],
                  official_sheng_pin=build['official_sheng_pin'],
                  baseline_native=build['baseline'],baseline_native_sha256=build['baseline_native_sha256'],
                  baseline_strict_sha256='0855e4bb87d6d22e974cd07f28cf3d62de14f07eb10d43f3a1de7458c5da7cf3',
                  build_receipt=str(a.build/'result.json'),build_receipt_sha256=sha(a.build/'result.json'),
                  tests_receipt=str(a.tests/'result.json'),tests_receipt_sha256=sha(a.tests/'result.json'),
                  host_result=tests['host_result'],python_tests=9,asan_ubsan=True,
                  python_test_log=str(a.tests/'python-tests.log'),python_test_log_sha256=sha(a.tests/'python-tests.log'),
                  official_sources=build['official_sources'],official_vs_baseline=build['official_vs_baseline'],
                  cpu_inputs=build['hardware'],sony_gpu_mhz=build['sony_gpu_mhz'],
                  gpu_votes_header_sha256=build['gpu_votes_header_sha256'],
                  archives=build['archives'],objects={n:{k:v for k,v in r.items() if k not in ('command',)} for n,r in build['compiled'].items()},
                  api_audit=api,gpu_core_pin_preserved=build['gpu_core_pin_preserved'],
                  latest_gpu_core_pin=build['latest_gpu_core_pin'],
                  newest_core_binary_layout_compatible=False,newest_core_rebuilt=False,
                  gpu_api_findings=['NativeAdrenoABI.h wire format unchanged',
                      'Ring adds bvProgressState; Submit adds fields in Recovery/Job and changes recover signature',
                      'Vm changes object layout and cache-maintenance methods; UserClient header differs',
                      'New/latest headers are not mixed with selected 653e11c compiled C++ objects',
                      'Power probe executable text matches latest sheng; its selected old-core interfaces compile and resolve'],
                  firmware_member_sha256=build['firmware_member_sha256'],firmware_unchanged=True,
                  shared_apps_smmu_changes=False,shared_apps_smmu_reason='CPU EPSS/L3 and GPU/GMU MMIO are disjoint; observer never maps/programs apps-SMMU and holds no touch/UFS config lock',
                  native_idle_helper=dict(path=str(a.build/'native-idle-helper.txt'),sha256=sha(a.build/'native-idle-helper.txt'),
                      actual_native_calls_recount=True,new_helper_required=False),
                  fence_path=dict(already_in_066=True,new_sleep_patch=False,
                      selected_source=tests['actual_selected_fence_source'],sha256=tests['actual_selected_fence_sha256'],
                      interrupt_wait='arms stack waiter before ring-fence observation; completion pass disarms under wake_lock; sleeps outside submission lock until completion or caller deadline',
                      fallback_pause='board ringIdle sleeps at most gpu-pause-us=1000 only when IRQ attached, interrupts enabled, not interrupt context, preemption level zero; otherwise bounded 20us delay'),
                  target_new_unresolved_apis=tests['target_new_unresolved_apis'],
                  blocks_abi_inherited_objects=66,blocks_compile_flags=build['blocks_flags'],
                  baseline066_config=dict(receipt=str(release),sha256=sha(release),
                      knobs={k:knobs.get(k) for k in ('cpufreq','vsync','gpu-power','gpu-metal','fb-gpu','gpu-dcvs','gpu-fence-wake','gpu-pause-us','dpu-scanout')},
                      cpufreq_read_only=True,dcvs_enabled=False,
                      gpu_boot_level='default index1 = 124800000Hz in selected Sony HFI table, absent gpu-perf override'),
                  post066_readonly_log=dict(msgbuf=str(msg),msgbuf_sha256=sha(msg),slots=str(slots),slots_sha256=sha(slots),
                      header=str(header),header_sha256=sha(header),capture_tag='PDX066',observed_errors=counts,
                      caveat='retained tail, not entire boot; process churn/ENOSPC can add load but this does not quantify CPU utilization or establish sole heat cause'),
                  observer=build['observer'],integration=build['integration'],
                  main_owned_inputs_not_changed=['SonyLxsTouch','BootProgress/touch-screen-067-002','global build/relink/package scripts','board/profiles/porting','Data seed','firmware'],
                  source_integration=True,target_compiled=True,host_tested=True,native_relinked=False,
                  strict_prelinked=False,image_delivered=False,device_tested=False,device_operations=False,
                  heat_reduction_proven=False,panel120_proven=False,fps_improvement_proven=False,
                  known_limits=build['known_limits'])
    dest=ROOT/'evidence/d27-platform067-performance.json'
    dest.write_text(json.dumps(evidence,indent=2)+'\n')
    print(json.dumps(dict(evidence=str(dest),sha256=sha(dest),archives={k:dict(path=r['archive'],sha256=r['sha256']) for k,r in build['archives'].items()},
                          host_result=tests['host_result'],python_tests=9,errors=counts),indent=2))


if __name__=='__main__':main()
