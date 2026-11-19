#!/usr/bin/env python3
"""Compile upstream sheng screen and fault recorder with the actual D27 PAC ABI."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
DEVICE=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(DEVICE/'ci'))
from compile_dependencies import run_recorded
from boot_screen_cached_overlay import apply_progress, apply_usb, stage_headers, qualify, DISPLAY_PROBE_SHA256
from boot_screen_cached_overlay import apply_first_frame_progress, apply_first_frame_trace


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--cpufreq',action='store_true',help='Retain upstream governor polling and measured frequency rows')
    parser.add_argument('--usb-status',action='store_true',help='Show cached USB worker/failure state without MMIO on the screen thread')
    parser.add_argument('--first-frame',action='store_true',help='Expose cached client problems, fence counters and render-role samples together')
    parser.add_argument('--swift-tests',type=Path,help='Passing exact D27 Swift-message bounded-copy test receipt')
    args=parser.parse_args();out=args.out.resolve()
    if args.first_frame and not args.swift_tests:parser.error('--first-frame requires --swift-tests for the complete diagnostic candidate')
    if args.swift_tests and not args.first_frame:parser.error('--swift-tests requires --first-frame')
    if shutil.disk_usage('/mnt/g').free<8*1024**3:raise RuntimeError('G: free space below 8 GiB')
    probe=BASE/'display-source-009/kits/sheng/LegacyDisplayProbe.cpp'
    qualify(probe.read_text(),DISPLAY_PROBE_SHA256)
    out.mkdir(parents=True,exist_ok=False)
    upstream=BASE/'sources/sheng/package'
    for path in upstream.glob('Boot*.h'):shutil.copyfile(path,out/path.name)
    stage_headers(out)
    if args.first_frame:
        for name in ('PdxFirstFrameDiagnostics.h','PdxRenderThreadDiagnostics.h','PdxGpuProgressCache.h','PdxProcessChurnDiagnostics.h','PdxFramebufferCallDiagnostics.h'):
            shutil.copyfile(DEVICE/'ci'/name,out/name)
        from swift_trap_diagnostic import adapt_fault
        swift_tests=json.loads(args.swift_tests.read_text())
        if (not swift_tests.get('passed') or swift_tests.get('hardware_verified') is not False or
            swift_tests.get('header_sha256')!=hashlib.sha256((DEVICE/'ci/PdxSwiftTrapDiagnostic.h').read_bytes()).hexdigest() or
            swift_tests.get('overlay_sha256')!=hashlib.sha256((DEVICE/'ci/swift_trap_diagnostic.py').read_bytes()).hexdigest() or
            swift_tests.get('tests_sha256')!=hashlib.sha256((DEVICE/'ci/swift_trap_diagnostic_tests.py').read_bytes()).hexdigest()):
            raise ValueError('Swift bounded-copy test source identity differs')
        shutil.copyfile(DEVICE/'ci/PdxSwiftTrapDiagnostic.h',out/'PdxSwiftTrapDiagnostic.h')
    plan=json.loads((BASE/'native-graphics-005/plan.json').read_text())
    recipe=next(j for j in plan['jobs'] if Path(j['source']).name=='startup.c')
    env=dict(os.environ,CCC_OVERRIDE_OPTIONS='# +-Wno-missing-designated-field-initializers +-Wno-unused-but-set-global')
    font=DEVICE.parent/'uefi-pdx234/Silicon/Silicium/SiliciumPkg/Library/FrameBufferSerialPortLib'
    assert (font/'Font.h').is_file()
    objects=[];sources=[]
    for name in ('BootProgress','BootFaultProbe','BootProcessProbe','BootUiTraceProbe'):
        original=upstream/(name+'.c');source=out/original.name;text=original.read_text()
        if name=='BootProgress':
            text=apply_progress(text)
            if args.first_frame:text=apply_first_frame_progress(text)
            if args.usb_status:
                text=apply_usb(text)
            # File export is an independent optional module. Existing BootLog
            # handles the Sony log region; this archive supplies screen/faults.
            marker='// BootLog.c reaches the diagnostic file export (BootDiagExport.c) only through weak references'
            if text.count(marker)!=1:raise ValueError('Unexpected export anchor')
            text=text[:text.index(marker)]
            # Full upstream sampling capacities fit the expanded native DATA
            # mapping selected by finish-d27-pac-abi --expanded-native-data.
            # Sony uses UFS and has no tablet touch/cpufreq provider. Exclude
            # their optional presentation paths rather than supply fake metrics.
            text=text.replace('extern volatile uint32_t native_virtio_ready, native_virtio_read_requests, native_virtio_read_failures;', '')
            text=text.replace('extern volatile uint64_t native_virtio_verified_blocks;', '')
            for symbol in ('native_virtio_ready','native_virtio_read_requests','native_virtio_read_failures','native_virtio_verified_blocks'):
                text=text.replace(symbol,'0ULL')
            text=text.replace('&native_touch_stage_req && native_touch_stage_req','0')
            if not args.cpufreq:
                text=text.replace('&native_cpufreq_stage && native_cpufreq_stage>=2','0')
                text=text.replace('if(sheng_cpufreq_poll)sheng_cpufreq_poll();','/* No Sony cpufreq provider selected. */')
            start=text.index('  uint32_t seq=__atomic_load_n(&native_touch_seq,')
            end=text.index('\n}\n',start)
            text=text[:start]+'  /* Sony touch transport is not integrated. */'+text[end:]
        elif name=='BootUiTraceProbe' and args.first_frame:
            text=apply_first_frame_trace(text)
        elif name=='BootFaultProbe' and args.first_frame:
            text=adapt_fault(text)
        source.write_text(text);obj=out/(name+'.o');old=recipe['command'];cmd=[];i=0
        while i<len(old):
            value=old[i]
            if value==recipe['source']:cmd.append(str(source))
            elif value=='-o':cmd+=['-o',str(obj)];i+=1
            elif value in ('-MF','-MT','-MJ'):i+=1
            elif value in ('-MD','-MP'):pass
            elif value=='-Xclang' and old[i+1].startswith('-W'):i+=1
            elif not value.startswith('-W'):cmd.append(value.replace('XNU_BOOT_PROGRESS=0','XNU_BOOT_PROGRESS=1'))
            i+=1
        cmd+=['-mgeneral-regs-only','-I'+str(font),'-I'+str(original.parent),'-Wall','-Wextra','-Werror','-Wno-unused-parameter']
        if '-fptrauth-function-pointer-type-discrimination' not in cmd or '--target=arm64e-apple-ios27.0.0' not in cmd:
            raise RuntimeError('Missing required arm64e/PAC recipe')
        if shutil.disk_usage('/mnt/g').free<8*1024**3:raise RuntimeError('G: free space below 8 GiB')
        r=run_recorded(cmd,cwd=recipe['directory'],env=env,capture_output=True,text=True)
        (out/(name+'.log')).write_text(r.stdout+r.stderr)
        (out/(name+'.command.json')).write_text(json.dumps(cmd,indent=2)+'\n')
        if r.returncode:raise RuntimeError(r.stderr[-6500:])
        objects.append(obj);sources.append(dict(original=str(original),original_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),source=str(source),sha256=hashlib.sha256(source.read_bytes()).hexdigest()))
    archive=out/'libPdxBootScreen.a';subprocess.run(['llvm-ar','rcs',str(archive),*map(str,objects)],check=True)
    result=dict(archive=str(archive),sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),sources=sources,
                cached_boot_diagnostics=True,
                display_probe_sha256=DISPLAY_PROBE_SHA256,
                diagnostic_headers={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in
                    (out/'PdxBootCachedDiagnostics.h',out/'BootUiTraceDetails.h')},
                 cpufreq=args.cpufreq,
                 usb_status=args.usb_status,
                 first_frame_diagnostics=args.first_frame,
                 first_frame_headers={name:hashlib.sha256((out/name).read_bytes()).hexdigest() for name in
                     ('PdxFirstFrameDiagnostics.h','PdxRenderThreadDiagnostics.h','PdxGpuProgressCache.h','PdxProcessChurnDiagnostics.h','PdxFramebufferCallDiagnostics.h')} if args.first_frame else {},
                 swift_trap_diagnostic=dict(verified=True,
                     header_sha256=hashlib.sha256((out/'PdxSwiftTrapDiagnostic.h').read_bytes()).hexdigest(),
                     overlay_sha256=hashlib.sha256((DEVICE/'ci/swift_trap_diagnostic.py').read_bytes()).hexdigest(),
                     tests_receipt=str(args.swift_tests.resolve()),
                     tests_sha256=hashlib.sha256(args.swift_tests.read_bytes()).hexdigest()) if args.first_frame else None,
                pac_flag='-fptrauth-function-pointer-type-discrimination',runtime_verified=False,device_operations=False)
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
