#!/usr/bin/env python3
"""Check real Sony HID descriptor/reports with the selected Apple HID parser."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
HID=Path('/root/unixnu-build/pdx234-local-github-a6d2286-001/out/feeds/IOHIDFamily-f53ac321')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True)
    a=parser.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    spec=importlib.util.spec_from_file_location('sony_builder',ROOT/'scripts/ci/build-sony-touch.py')
    builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
    original=BASE/'qemu-input-002/source/NativeHidInput.cpp';text=builder.adapt_hid(original.read_text())
    descriptors=text[text.index('static const unsigned char descriptor[]'):text.index('#define TOUCH_FINGERS')]
    (a.out/'descriptors.h').write_text(descriptors)
    source=HID/'IOHIDSystem/IOHIDDescriptorParser'
    fixture=ROOT/'tests/sony_hid_parser.c';driver=ROOT/'drivers/SonyLxsTouch'
    sources=[*source.glob('*.c'),fixture,driver/'HidTouchReport.c']
    command=['clang','-std=c11','-O1','-g','-DRTKIT=1','-D__unused=__attribute__((unused))',
        '-Wno-multichar','-include','string.h','-fsanitize=address,undefined','-fno-omit-frame-pointer',
        '-I',str(HID/'IOHIDFamily'),'-I',str(HID/'IOHIDSystem/IOKit/hidsystem'),'-I',str(source),
        '-I',str(driver),'-I',str(a.out),*map(str,sources),'-o',str(a.out/'hid-parser')]
    compiled=subprocess.run(command,text=True,capture_output=True,timeout=60)
    (a.out/'compile.log').write_text(compiled.stdout+compiled.stderr)
    if compiled.returncode:raise RuntimeError(compiled.stderr[-9000:])
    done=subprocess.run([str(a.out/'hid-parser')],text=True,capture_output=True,timeout=15)
    (a.out/'run.log').write_text(done.stdout+done.stderr)
    if done.returncode:raise RuntimeError(done.stdout+done.stderr)
    hashes={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [*sources,original,ROOT/'scripts/ci/build-sony-touch.py']}
    result=dict(passed=True,apple_parser_revision='e31e90a24c27ad6cbe981650d12a1a4124065b03',
        descriptor_sha256=hashlib.sha256(descriptors.encode()).hexdigest(),sources=hashes,
        actual_descriptor_parsed=True,actual_generated_reports_decoded=True,sanitizers=['address','undefined'],
        kernel_matching_or_backboardd_runtime_verified=False,output=done.stdout)
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(done.stdout,end='')


if __name__=='__main__':main()
