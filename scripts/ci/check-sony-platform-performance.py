#!/usr/bin/env python3
"""Run ASan/UBSan on actual selected governor/fence bodies and check archive boundaries."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ci/platform067/performance'))
sys.path.insert(0, str(ROOT / 'ci'))
from compile_dependencies import valid
from rates import interface_rate, present_rate
from source import BASE_NATIVE_SHA, sha


def region(text: str, start: str, end: str) -> str:
    if text.count(start) != 1 or text.count(end) != 1:
        raise ValueError('Unique actual-source test region required')
    first = text.index(start)
    return text[first:text.index(end, first)]


def members(path: Path) -> dict[str, str]:
    names = subprocess.check_output(['llvm-ar', 't', str(path)], text=True).splitlines()
    if len(names) != len(set(names)):
        raise ValueError('Duplicate archive members')
    return {n: hashlib.sha256(subprocess.check_output(['llvm-ar', 'p', str(path), n])).hexdigest() for n in names}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--cxx', default='/usr/bin/clang++-18')
    a = p.parse_args()
    build = json.loads((a.build / 'result.json').read_text())
    if build['baseline_native_sha256'] != BASE_NATIVE_SHA or build['blocks_abi_inherited_objects'] != 66:
        raise ValueError('Wrong source integration baseline')
    out = a.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    for row in build['compiled'].values():
        if sha(row['source']) != row['source_sha256'] or sha(row['object']) != row['object_sha256']:
            raise ValueError('Compiled source/object changed')
        if not valid(json.loads(Path(row['dependency_receipt']).read_text())):
            raise ValueError('Compiled object dependency changed')
        if '-fptrauth-block-descriptor-pointers' not in row['command']:
            raise ValueError('Blocks ABI flag missing')
    boundaries = {}
    for key, row in build['archives'].items():
        if sha(row['archive']) != row['sha256'] or sha(row['baseline_archive']) != row['baseline_sha256']:
            raise ValueError('Archive identity changed')
        old, new = members(Path(row['baseline_archive'])), members(Path(row['archive']))
        changed = [n for n in old if old[n] != new.get(n)]
        if changed != row['changed_members'] or sorted(set(new) - set(old)) != row['added_members']:
            raise ValueError('Unrecorded link member delta')
        for n, expected in row['unchanged_members'].items():
            if new[n] != expected:
                raise ValueError('Unchanged member differs: ' + n)
        boundaries[key] = dict(changed=changed, added=row['added_members'], preserved=len(row['unchanged_members']))
    gpu = Path(build['compiled']['GpuPowerProbe']['source']).read_text()
    cpu = Path(build['compiled']['CpuFreqProbe']['source']).read_text()
    # A host compiles the same governor code and LUT selection. The only CPU
    # instruction replaced is its target-only dsb; fake MMIO/sleep live in the
    # test harness. No reference model substitutes for the policy under test.
    cpu = re.sub(r'^#include <[^\n]+>\n', '', cpu, flags=re.M)
    cpu = cpu.replace('__asm__ volatile("dsb sy" ::: "memory");', '/* host MMIO ordering */')
    (out / 'cpu.inc').write_text(cpu)
    constants = region(gpu, 'constexpr uint32_t kGpuMHz[9]', 'uint64_t gpuBusyTicks()')
    vote = region(gpu, 'bool gpuVote(', 'unsigned gpuLevelFor(')
    level = region(gpu, 'unsigned gpuLevelFor(', 'void gpuPerfTick(')
    governor = region(gpu, 'void gpuDcvsThread(', 'void heartbeat();')
    (out / 'gpu.inc').write_text(constants + vote + level + governor)
    vote_index=Path('/mnt/e/UniXNU-sheng27-sony-20261113/gpu-source-006/kits/sheng/ShengGmuVotes.c')
    (out/'vote-index.inc').write_text('unsigned ShengGmuPerfVote('+
                                    vote_index.read_text().split('unsigned ShengGmuPerfVote(',1)[1])
    vote_table=Path('/mnt/e/UniXNU-sheng27-sony-20261113/gpu-source-006/build/sheng-gmu/ShengGmuVotesSource.h')
    (out/'ShengGmuVotesSource.h').write_text(vote_table.read_text())
    idle = region(gpu, 'volatile bool gIrqAttached;', 'OSSharedPtr<IOMemoryMap> gGpuMaps')
    (out / 'idle.inc').write_text(idle)
    selected = Path('/mnt/e/UniXNU-sheng27-sony-20261113/gpu-source-006/drivers/Adreno740/NativeAdrenoPublish.cpp')
    text = selected.read_text()
    fence = region(text, '        NativeAdrenoAbiWaitFence poll{};', '    } else {\n        /* A BoAlloc')
    (out / 'fence.inc').write_text(fence)
    command = [a.cxx, '-std=c++20', '-g', '-O1', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
               '-Wall', '-Wextra', '-Werror', '-Wno-unknown-attributes', '-Wno-ignored-attributes',
               '-Wno-pointer-bool-conversion', '-Wno-deprecated-volatile',
               '-I', str(out), '-I', str(ROOT / 'ci/platform067/performance'),
               str(ROOT / 'tests/sony_platform_performance_host.cpp'), '-o', str(out / 'host')]
    with (out / 'host-build.log').open('x') as stream:
        result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=120)
    if result.returncode:
        raise RuntimeError((out / 'host-build.log').read_text()[-7000:])
    result = subprocess.run([str(out / 'host')], capture_output=True, text=True, timeout=30)
    (out / 'host-run.log').write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError((out / 'host-run.log').read_text()[-7000:])
    # The governor's table must agree exactly in order with HFI, including the
    # 124.8 MHz low point. The arithmetic rounds MHz only; votes remain exact.
    assert build['sony_gpu_mhz'] == [0, 124.8, 220, 295, 348, 401, 475, 550, 615]
    assert '0, 124, 220, 295, 348, 401, 475, 550, 615' in gpu
    assert 'bootArg("gpu-dcvs-min", 4)' in gpu
    assert build['shared_apps_smmu_changes'] is False and build['firmware_unchanged']
    # Requesting 120 Hz cannot make a 60 Hz sample pass. No data is silently
    # interpreted as 120, and command-mode DPU cadence is not panel self-refresh.
    rate_cases = []
    for delta, enabled, expected in ((600, True, 60), (1200, True, 120), (0, True, None),
                                      (1200, False, None), (0xffffffff, True, None)):
        line = f'[sony-dpu-rate] interface=1 delta={delta} elapsed-us=10000000 timing={int(enabled):x} counter-enable=1'
        row = interface_rate(line)
        assert row['observed_interface_hz'] == expected and not row['panel_refresh_verified']
        rate_cases.append(row)
    row = present_rate('[sony-present-rate] elapsed-us=10000000 copy-delta=720 retire-delta=710 requested-vsync=120')
    assert row['copies_per_second'] == 72 and row['retirements_per_second'] == 71
    assert row['actual_panel_hz'] is None and row['compositor_fps'] is None
    baseline = Path(build['baseline'])
    symbols = subprocess.check_output(['llvm-nm', '--defined-only', str(baseline / 'native.macho')], text=True)
    for symbol in ('_sheng_cpu_idle_mach', '_native_gpu_idle_sleeps', '_native_adreno_fence_wake', '_native_gpu_dcvs'):
        assert any(line.endswith(' ' + symbol) for line in symbols.splitlines())
    defined={line.split()[-1] for line in symbols.splitlines() if line.split()}
    for path in [r['object'] for r in build['compiled'].values()]:
        defined.update(line.split()[-1] for line in subprocess.check_output(['llvm-nm','--defined-only',path],text=True).splitlines() if line.split())
    unresolved={}
    for name, obj in build['compiled'].items():
        imports={line.split()[-1] for line in subprocess.check_output(['llvm-nm','--undefined-only',obj['object']],text=True).splitlines() if line.split()}
        new=imports-defined
        if new:unresolved[name]=sorted(new)
    if unresolved:
        raise ValueError('Replacement requires unavailable native API: '+json.dumps(unresolved))
    manifest = dict(passed=True, target_objects_checked=len(build['compiled']),
                    host_command=command, host_result=result.stdout.strip(),
                    actual_selected_fence_source=str(selected), actual_selected_fence_sha256=sha(selected),
                     extracted_regions={str(out / name): sha(out / name) for name in (
                         'cpu.inc', 'gpu.inc', 'idle.inc', 'fence.inc', 'vote-index.inc','ShengGmuVotesSource.h')},
                    archive_boundaries=boundaries, rate_cases=rate_cases, present_case=row,
                    checks=['official CPU readonly/LUT/cap/governor/down-hysteresis/frame/touch cases',
                            'official GPU idle/busy/wake/touch/floor/span/vote-failure cases',
                            'selected fence completion-before-sleep/IRQ/timeout/zero deadline/close/fallback',
                            'selected board ringIdle sleepability guards and 1ms timeout',
                            'Sony HFI frequency order, exact vote helper, bandwidth coupling and 348MHz floor index',
                            'no 120Hz panel claim from vsync or DPU disabled/reset sample',
                            'all unchanged archive members including firmware and SMMU byte-identical'],
                    build_receipt=str(a.build / 'result.json'), build_receipt_sha256=sha(a.build / 'result.json'),
                    runtime_qualified=False, device_operations=False, asan_ubsan=True)
    manifest['target_new_unresolved_apis']=unresolved
    manifest['observer_limits_checked']=build['observer']
    manifest['tool_sources']={str(path):sha(path) for path in (
        ROOT/'scripts/ci/build-sony-platform-performance.py',ROOT/'scripts/ci/check-sony-platform-performance.py',
        ROOT/'ci/platform067/performance/source.py',ROOT/'ci/platform067/performance/inputs.py',
        ROOT/'ci/platform067/performance/rates.py',ROOT/'tests/sony_platform_performance_host.cpp')}
    (out / 'result.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
