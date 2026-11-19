#!/usr/bin/env python3
"""Build isolated Sony CPU/DCVS replacements; never relink, package or touch a device."""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ci/platform067/performance'))
sys.path.insert(0, str(ROOT / 'ci'))
from compile_dependencies import run_recorded, valid
from inputs import qualify
from source import (BASE_NATIVE_SHA, BASE_GPU_SHA, BASE_DISPLAY_SHA, SHENG_REV,
                    CPU_SHA, GPU_SHA, cpu_source, gpu_source, parse_opps, replace_once, sha)

BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
SNAP = Path('/mnt/f/UniXNU-Port-artifacts/platform067-20261118')
DTB = Path('/mnt/g/UniXNU-Port/evidence/Xperia-XQ-DQ72/20261118-platform-post066-readonly-001/live.dtb')


def read_members(archive: Path) -> dict[str, str]:
    names = subprocess.check_output(['llvm-ar', 't', str(archive)], text=True).splitlines()
    if len(set(names)) != len(names):
        raise ValueError('Duplicate archive members: ' + str(archive))
    import hashlib
    return {n: hashlib.sha256(subprocess.check_output(['llvm-ar', 'p', str(archive), n])).hexdigest() for n in names}


def compile_command(dep: dict, source: Path, obj: Path) -> list[str]:
    old, result, i = dep['command'], [], 0
    while i < len(old):
        v = old[i]
        if v in ('-MF', '-MT', '-MQ', '-MJ'):
            i += 2
            continue
        if v not in ('-MD', '-MMD', '-MP'):
            result.append(v)
        i += 1
    result[result.index(dep['source'])] = str(source)
    result[result.index('-o') + 1] = str(obj)
    if '-fptrauth-function-pointer-type-discrimination' not in result:
        raise ValueError('Require selected PAC recipe')
    if '-fptrauth-block-descriptor-pointers' not in result:
        result += ['-Xclang', '-fptrauth-block-descriptor-pointers']
    result += ['-I', str(ROOT / 'ci/platform067/performance'), '-mgeneral-regs-only',
               '-Wno-unused-but-set-global', '-Wno-missing-designated-field-initializers']
    return result


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--baseline', type=Path, default=BASE / 'native-sony-touch-066-002')
    p.add_argument('--snapshot', type=Path, default=SNAP)
    p.add_argument('--live-dtb', type=Path, default=DTB)
    p.add_argument('--jobs', type=int, choices=range(1, 9), default=4)
    a = p.parse_args()
    before = a.baseline.resolve()
    receipt = json.loads((before / 'result.json').read_text())
    if sha(before / 'native.macho') != BASE_NATIVE_SHA or receipt['native_sha256'] != BASE_NATIVE_SHA:
        raise ValueError('Require exact physical066002, including all 66 corrected Blocks objects')
    if len(receipt['block_descriptor_abi']['replacements']) != 66 or not receipt['block_descriptor_abi']['passed']:
        raise ValueError('Missing inherited Blocks ABI qualification')
    for key, expected in (('display_source', BASE_DISPLAY_SHA), ('gpu_source', BASE_GPU_SHA)):
        if receipt[key]['sha256'] != expected or sha(receipt[key]['archive']) != expected:
            raise ValueError('Baseline archive changed: ' + key)
    snapshot = a.snapshot.resolve()
    pin = subprocess.check_output(['git', '-C', str(snapshot / 'sheng'), 'rev-parse', 'HEAD'], text=True).strip()
    if pin != SHENG_REV:
        raise ValueError('Official sheng snapshot pin changed')
    official_cpu = snapshot / 'sheng/package/CpuFreqProbe.cpp'
    official_gpu = snapshot / 'sheng/package/GpuPowerProbe.cpp'
    if sha(official_cpu) != CPU_SHA or sha(official_gpu) != GPU_SHA:
        raise ValueError('Official performance source changed')
    selected_gpu = BASE / 'gpu-source-006'
    old_gpu_text=(selected_gpu / 'kits/sheng/GpuPowerProbe.cpp').read_text()
    current_gpu_text=official_gpu.read_text()
    normalized_old=replace_once(old_gpu_text,
        '// Self-SGI probe (system registers only): row 2 ends with s<cores that ran a probe> p<INTIDs 0..15 that became pending as Group 1>/<as Group 0>,',
        '// Self-SGI probe: row 2 ends with s<cores that ran a probe> p<owned SGIs pending as Group 1>/<as Group 0>,')
    if normalized_old != current_gpu_text or sha(BASE / 'display-source-009/kits/sheng/CpuFreqProbe.cpp') != CPU_SHA:
        raise ValueError('Unreviewed official CPU/GPU delta')
    votes = selected_gpu / 'build/sheng-gmu/ShengGmuVotesSource.h'
    opps = parse_opps(votes.read_text())
    hardware = qualify(snapshot, a.live_dtb, opps)
    out = a.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    (out / 'objects').mkdir()
    (out / 'sources').mkdir()
    originals = {
        'CpuFreqProbe': BASE / 'display-source-009/build/native-legacy-display/CpuFreqProbe.o.dependencies.json',
        'GpuPowerProbe': selected_gpu / 'build/adreno740/GpuPowerProbe.o.dependencies.json',
        'LegacyDisplayProbe': before / 'LegacyDisplayProbe.o.dependencies.json',
    }
    deps = {name: json.loads(path.read_text()) for name, path in originals.items()}
    for name, dep in deps.items():
        if not valid(dep):
            raise ValueError('Selected compile dependencies changed: ' + name)
    texts = {'CpuFreqProbe': cpu_source(official_cpu.read_text()),
             'GpuPowerProbe': gpu_source(official_gpu.read_text(), opps)}
    late = Path(deps['LegacyDisplayProbe']['source']).read_text()
    texts['LegacyDisplayProbe'] = replace_once(late, '    sheng_cpufreq_probe();\n',
        '    sheng_cpufreq_probe();\n    extern void native_sony_performance_start(void);\n    native_sony_performance_start();\n')
    texts['SonyPerformanceProbe'] = (ROOT / 'ci/platform067/performance/SonyPerformanceProbe.cpp').read_text()
    deps['SonyPerformanceProbe'] = deps['CpuFreqProbe']
    def compile_one(name):
        dep = deps[name]
        source, obj = out / 'sources' / (name + '.cpp'), out / 'objects' / (name + '.o')
        source.write_text(texts[name])
        command = compile_command(dep, source, obj)
        # Recorded headers are absolute, but XNU's meta_features/iokitcpp headers
        # also require the original compilation directory's relative includes.
        directory = Path(next(s for s in dep['dependencies'] if Path(s).name == 'meta_features.h')).parent
        env = dict(os.environ, CCC_OVERRIDE_OPTIONS='# +-Wno-missing-designated-field-initializers +-Wno-unused-but-set-global')
        with (out / (name + '.compile.log')).open('x') as stream:
            r = run_recorded(command, cwd=directory, env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=180)
        if r.returncode:
            raise RuntimeError((out / (name + '.compile.log')).read_text()[-7000:])
        return name, dict(source=str(source), source_sha256=sha(source), object=str(obj), object_sha256=sha(obj),
                          original_receipt=str(originals.get(name, originals['CpuFreqProbe'])),
                          dependency_receipt=str(obj) + '.dependencies.json', command=command, directory=str(directory))
    with ThreadPoolExecutor(max_workers=a.jobs) as pool:
        compiled = dict(pool.map(compile_one, texts))
    archives = {}
    for key, objects, filename in (
            ('display_source', ['CpuFreqProbe', 'LegacyDisplayProbe', 'SonyPerformanceProbe'], 'libPhysicalDisplaySonyPerformance.a'),
            ('gpu_source', ['GpuPowerProbe'], 'libAdreno740SonyPerformance.a')):
        old = Path(receipt[key]['archive'])
        dest = out / filename
        old_members = read_members(old)
        shutil.copyfile(old, dest)
        subprocess.run(['llvm-ar', 'r', str(dest), *[compiled[n]['object'] for n in objects]], check=True)
        new_members = read_members(dest)
        changed = [n for n in old_members if new_members.get(n) != old_members[n]]
        added = sorted(set(new_members) - set(old_members))
        expected_changed = [n + '.o' for n in objects if n != 'SonyPerformanceProbe']
        if set(changed) != set(expected_changed) or added != (['SonyPerformanceProbe.o'] if key == 'display_source' else []):
            raise ValueError('Unexpected archive delta: ' + key)
        archives[key] = dict(archive=str(dest), sha256=sha(dest), baseline_archive=str(old), baseline_sha256=sha(old),
                             changed_members=changed, added_members=added,
                             unchanged_members={n: digest for n, digest in old_members.items() if n not in changed})
    # Audit rather than upgrade the GPU core: no firmware or driver API is
    # replaced to get a frequency governor that is already source-identical.
    api_names = ['NativeAdrenoABI.h', 'NativeAdrenoRing.h', 'NativeAdrenoSubmit.h', 'NativeAdrenoVm.h',
                 'NativeAdrenoUserClient.h', 'NativeAdrenoGmuContext.h', 'NativeAdrenoGpuContext.h']
    api = {name: dict(selected_sha256=sha(selected_gpu / 'drivers/Adreno740' / name),
                      latest_sha256=sha(snapshot / 'Adreno740' / name)) for name in api_names}
    firmware_member = read_members(Path(receipt['gpu_source']['archive']))['firmware.o']
    result = dict(schema=1, baseline=str(before), baseline_native_sha256=BASE_NATIVE_SHA,
                  baseline_result_sha256=sha(before / 'result.json'), official_sheng_pin=SHENG_REV,
                  official_sources={str(official_cpu): CPU_SHA, str(official_gpu): GPU_SHA}, hardware=hardware,
                  sony_gpu_mhz=[row[0] / 1000000 for row in opps], gpu_votes_header_sha256=sha(votes),
                  compiled=compiled, archives=archives, gpu_api_audit=api,
                  gpu_core_pin_preserved=receipt['gpu_source']['pins']['drivers/Adreno740'],
                  latest_gpu_core_pin=subprocess.check_output(['git', '-C', str(snapshot / 'Adreno740'), 'rev-parse', 'HEAD'], text=True).strip(),
                  firmware_member_sha256=firmware_member, firmware_unchanged=True,
                  official_vs_baseline=dict(cpu_identical=True, gpu_executable_text_identical=True,
                      gpu_only_delta='Self-SGI comment', governor_policy_rewritten=False),
                  shared_apps_smmu_changes=False, blocks_abi_inherited_objects=66,
                  blocks_flags=['-Xclang', '-fptrauth-block-descriptor-pointers'],
                  integration=dict(replace_force_load_archives=True, native_relinked=False,
                                   preserve_all_other_link_inputs=True, preserve_dpu_scanout=0,
                                   required_bootargs={'cpufreq': 4, 'gpu-dcvs': 1, 'gpu-dcvs-min': 4,
                                                      'gpu-fence-wake': 1, 'gpu-pause-us': 1000,
                                                      'sony-display-timing': 1, 'sony-perf-samples': 60},
                                   vsync_request_hz=120, panel_refresh_verified=False),
                  observer=dict(independent_entry='native_sony_performance_start', initial_delay_ms=150000,
                                sample_interval_ms=10000, max_samples=60, mmio_writes=False,
                                touch_monitor_dependency=False, cpufreq_poll_dependency=False),
                  source_only=False, target_compiled=True, host_tested=False, device_tested=False,
                  packaged=False, device_operations=False,
                  known_limits=['CPU/GPU governor effect, heat, frame latency and hardware rate require device evidence',
                                'Sony DT 120 Hz support is not inherited GOP 120 Hz; no panel mode switch',
                                'Official CPU governor votes maximum allowed L3, not thermal control',
                                'GPU DCVS is frequency/bandwidth voting, not GMU/GX power-collapse or thermal policy',
                                'Working 653e11c core and firmware retained; newest core not transplanted',
                                '066 Data ENOSPC and process churn are independent observed load sources'])
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(target_compiled=True, result=str(out / 'result.json'), archives=archives), indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
