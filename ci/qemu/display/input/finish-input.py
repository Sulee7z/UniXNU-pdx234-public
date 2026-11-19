#!/usr/bin/env python3
"""Finish the qualified current D27 HID archive and real VirtIO input transport."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
QEMU = Path('/mnt/g/UniXNU-Port/sources/UniXNU-qemu-20261110')


def sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Input source anchor differs: ' + old[:60])
    return text.replace(old, new)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build', type=Path, required=True)
    a = p.parse_args()
    out = a.build.resolve()
    if shutil.disk_usage('/mnt/g').free < 8 * 1024**3:
        raise ValueError('G reserve below8GiB')
    if (out / 'result.json').exists():
        raise ValueError('Preserve the existing input archive')
    spec = importlib.util.spec_from_file_location('input_compile', HERE / 'build-input.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    text = (QEMU / 'package/VirtioInput.cpp').read_text()
    text = once(text, '''        for (unsigned i = 0; read32(0x70) && i < 1000; i++) IODelay(10);
        write32(0x70, 1);''', '''        for (unsigned i = 0; read32(0x70) && i < 1000; i++) IODelay(10);
        if(read32(0x70))return false;
        write32(0x70, 1);''')
    text = once(text, '        while (usedHeader()[1] != used) {', '''        unsigned budget=kQueueSize;
        while (usedHeader()[1] != used && budget--) {''')
    text = once(text, '''            if (index >= kQueueSize) { native_virtio_input_failures = native_virtio_input_failures + 1; continue; }
            Event event;''', '''            const uint32_t length=usedRing()[(used-1)%kQueueSize].length;
            if (index >= kQueueSize || length!=sizeof(Event)) {
                native_virtio_input_failures=native_virtio_input_failures+1;
                write32(0x70,read32(0x70)|128);return;
            }
            Event event;''')
    text = once(text, '''        device.write32(0x70, 0);
        OSSafeReleaseNULL(device.ring);''', '''        device.write32(0x70, 0);
        for(unsigned attempt=0;device.read32(0x70) && attempt<1000;++attempt)IODelay(10);
        if(device.read32(0x70))panic("QEMU input: reset did not stop DMA");
        OSSafeReleaseNULL(device.ring);''')
    text = once(text, '''    if (timer && loop->addEventSource(timer) == kIOReturnSuccess) timer->setTimeoutMS(8);''', '''    if(!timer || loop->addEventSource(timer)!=kIOReturnSuccess)
        panic("QEMU input: event polling unavailable after device registration");
    timer->setTimeoutMS(8);''')
    (out / 'source/VirtioInput.cpp').write_text(text)
    shutil.copyfile(QEMU / 'package/TouchState.cpp', out / 'source/TouchState.cpp')
    shutil.copyfile(HERE / 'QemuInputStartup.cpp', out / 'source/QemuInputStartup.cpp')
    includes = ['-I', str(out / 'include'), '-idirafter',
                str(builder.SDK / 'System/Library/Frameworks/Kernel.framework/Versions/A/Headers')]
    commands = json.loads((out / 'compile.json').read_text())
    for name in ('VirtioInput', 'TouchState', 'QemuInputStartup'):
        commands[name] = builder.compile_cpp(out / 'source' / (name + '.cpp'),
                                             out / 'objects' / (name + '.o'), includes)
    (out / 'compile.json').write_text(json.dumps(commands, indent=2) + '\n')
    late = out / 'objects/NativeHidInput.late.o'
    subprocess.run(['/usr/lib/llvm-23/bin/llvm-objcopy', '--remove-section=__DATA,__mod_init_func',
                    '--globalize-symbol=__GLOBAL__sub_I_NativeHidInput.cpp',
                    str(out / 'objects/NativeHidInput.o'), str(late)], check=True)
    objects = [late, *(out / 'objects' / (v + '.o') for v in
               ('hid-bindings', 'hid-addresses', 'VirtioInput', 'TouchState', 'QemuInputStartup'))]
    archive = out / 'libQemuD27Input.a'
    subprocess.run(['llvm-ar', 'rcs', str(archive), *map(str, objects)], check=True)
    result = dict(archive=str(archive), sha256=sha(archive),
                  hid_abi_sha256=sha(out / 'hid-abi.json'), edge_abi_sha256=sha(out / 'edge-abi.json'),
                  hid_slots=207, hid_base_bytes=208, event_service_slots=220,
                  sources={str(v): sha(v) for v in (out / 'source').glob('*')},
                  objects={str(v): sha(v) for v in objects}, commands=commands,
                  startup='native_qemu_input_start', required_args=['qemu-input=1', 'touch-hid=1'],
                  transport='Actual QEMU modern VirtIO input MMIO devices from generated FDT',
                  qemu_devices=['virtio-tablet-device', 'virtio-keyboard-device'],
                  physical_device_access=False, runtime_verified=False, desktop_verified=False)
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k not in ('commands', 'sources', 'objects')}, indent=2))


if __name__ == '__main__':
    main()
