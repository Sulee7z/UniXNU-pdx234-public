#!/usr/bin/env python3
"""Execute actual HID publication/callback/report methods with modeled IOKit services."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--old064',action='store_true');a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    spec=importlib.util.spec_from_file_location('sony_builder',ROOT/'scripts/ci/build-sony-touch.py')
    builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
    source=BASE/('sony-touch-driver-012' if a.old064 else 'qemu-input-002')/'source/NativeHidInput.cpp'
    text=source.read_text() if a.old064 else builder.adapt_hid(source.read_text())
    # Edge's original PAC/table implementation is checked separately on target
    # machine code. This host harness records install attempts only.
    text=text[text.index('static const unsigned char descriptor[]'):]
    start=text.index('namespace edge {');stop=text.index('class NativeHidInput',start)
    text=text[:start]+'namespace edge {static unsigned installs;static void install(IORegistryEntry *){++installs;}}\n'+text[stop:]
    text=text.replace('__asm__ volatile("dmb ish":::"memory");','__atomic_thread_fence(__ATOMIC_SEQ_CST);')
    (a.out/'actual-hid.inc').write_text(text)
    flags=['-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-fsanitize=address,undefined',
        '-I',str(ROOT/'drivers/SonyLxsTouch'),'-I',str(a.out)]
    obj=a.out/'HidTouchReport.o'
    subprocess.run(['clang','-std=c11','-fsanitize=address,undefined','-c',str(ROOT/'drivers/SonyLxsTouch/HidTouchReport.c'),'-o',str(obj)],check=True)
    exe=a.out/'hid-delivery';fixture=ROOT/'tests/sony_hid_delivery.cpp'
    subprocess.run(['clang++',*flags,str(fixture),str(obj),'-o',str(exe)],check=True,timeout=60)
    done=subprocess.run([str(exe),*(['old'] if a.old064 else [])],text=True,capture_output=True,timeout=15)
    (a.out/'run.log').write_text(done.stdout+done.stderr)
    if done.returncode:raise RuntimeError(done.stdout+done.stderr)
    files=[source,fixture,ROOT/'scripts/ci/build-sony-touch.py',ROOT/'drivers/SonyLxsTouch/HidTouchReport.c',ROOT/'drivers/SonyLxsTouch/HidTouchReport.h']
    result=dict(passed=True,old_late_matching_report_loss_reproduced=a.old064,
        actual_class_start_sink_workloop_report_methods_executed=True,platform_services_modeled=True,
        pac_edge_runtime_emulated=False,backboardd_or_handset_runtime_verified=False,
        sources={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
        adapted_hid_source_sha256=hashlib.sha256((source.read_text() if a.old064 else builder.adapt_hid(source.read_text())).encode()).hexdigest(),
        output=done.stdout)
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(done.stdout,end='')


if __name__=='__main__':main()
