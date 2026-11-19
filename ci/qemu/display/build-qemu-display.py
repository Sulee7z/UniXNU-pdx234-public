#!/usr/bin/env python3
"""Build a QEMU-only D27 display archive from the retained qualified sources.

Preserves the D27 Legacy, IOSurface and KeyStore ABI. The owned probe omits
physical CPU/GPU initialization. The DPU setup is absent from the emitted
variant and a nonzero direct-display request is rejected before publication.
No physical source, native link inputs, prelink profile or OS image is changed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
CI = HERE.parents[1]
sys.path.insert(0, str(CI))
from compile_dependencies import run_recorded, valid

BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
DISPLAY = BASE / 'display-source-009'
SOURCE_HASHES = {
    'kits/sheng/LegacyDisplayProbe.cpp': 'd5f9692a8f2d6cc154239f5129fe9c14c4a999d0db3ff15f2578dd908c0ed855',
    'drivers/GopFramebuffer/NativeLegacyDisplay.cpp': '08f3339ff43702eb417f29bef7410a6bcb01a20bc9afde6867ba5c355cf96d8f',
}
MEMBERS = (
    'NativeLegacyDisplay.late.o', 'original-bindings.o', 'original-addresses.o',
    'LegacyDisplayProbe.o', 'LegacyDisplaySupport27.o', 'NativeGOPPresenter.late.o',
    'KeyStoreProbe.o', 'NativeKeyStoreEvents.late.o', 'PdxLegacyRequestLayout.o',
)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('QEMU overlay anchor changed: ' + old[:100])
    return text.replace(old, new, 1)


def function_body(text, signature, replacement):
    """Replace a uniquely named owned C++ method, keeping all other source."""
    if text.count(signature) != 1:
        raise ValueError('Non-unique function: ' + signature)
    start = text.index(signature)
    brace = text.index('{', start)
    level = 1
    end = brace + 1
    while level:
        level += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[:brace + 1] + replacement + text[end - 1:]


def overlay_probe(text):
    text = replace_once(text, '    sheng_cpufreq_probe();\n', '')
    text = replace_once(text, '    sheng_gpu_power_probe();\n', '')
    # Reject hardware-only modes rather than silently treating them as a GOP
    # success. Keystore, HID and the real display families remain unchanged.
    anchor = 'void native_legacy_display_late_probe(void) {\n'
    text = replace_once(text, anchor, anchor + '''    unsigned qemuDirect=0,qemuGpu=0;
    PE_parse_boot_argn("dpu-scanout",&qemuDirect,sizeof(qemuDirect));
    PE_parse_boot_argn("fb-gpu",&qemuGpu,sizeof(qemuGpu));
    if(qemuDirect || qemuGpu)panic("QEMU GOP: hardware DPU/GPU handoff requested");
''')
    text = replace_once(text, '#include <IOKit/IOUserClient.h>', '''#include <IOKit/IOUserClient.h>
extern "C" void native_qemu_display_observe(unsigned,IOService *);''')
    text = replace_once(text, '    if(stage==3)native_legacy_pm_callbacks=native_legacy_pm_callbacks+1;',
                        '''    if(stage==3)native_legacy_pm_callbacks=native_legacy_pm_callbacks+1;
    native_qemu_display_observe(0x10+stage,reinterpret_cast<IOService *>(native_legacy_object));''')
    text = replace_once(text, 'void native_legacy_registration_observed(IOService *display) {',
                        '''void native_legacy_registration_observed(IOService *display) {
    native_qemu_display_observe(1,display);''')
    text = replace_once(text, 'void native_legacy_client_observed(IOReturn status,IOUserClient *client) {',
                        '''void native_legacy_client_observed(IOReturn status,IOUserClient *client) {
    native_qemu_display_observe(2,reinterpret_cast<IOService *>(native_legacy_object));''')
    text = replace_once(text, '    native_legacy_swap_validation_checkpoint(accepted,reason,request,surface);',
                        '''    native_qemu_display_observe(accepted?3:4,reinterpret_cast<IOService *>(native_legacy_object));
    native_legacy_swap_validation_checkpoint(accepted,reason,request,surface);''')
    return text


def overlay_display(text):
    # The physical backend's startDirect() contains Qualcomm MMIO resources.
    # Do not compile that setup body into the QEMU variant. All calls into
    # direct methods are gated by directOn, whose sole true assignment is in
    # this removed body. Keep original method/vtable names and diversities.
    text = function_body(text, '    void startDirect()', '''
        // QEMU RAMFB is firmware-owned memory scanout, without a DPU.
        // A nonzero dpu-scanout is rejected by the QEMU late probe.
        return;
    ''')
    text = replace_once(text, '''        if(&native_adreno_fences && native_adreno_fences(&submitted,&retired)){const int32_t d=int32_t(submitted-retired);outstanding=d>0?(d>255?255:uint32_t(d)):0;}''',
                        '''        // QEMU has no hardware GPU fence provider. This diagnostic
        // records zero outstanding GPU work without querying Adreno.
        (void)submitted;(void)retired;''')
    text = function_body(text, '    void snapshot()', '''
        // The actual QEMU scanout remains the GOP memory, already visible to QMP.
        return;
    ''')
    for signature in ('    void flip(uint32_t iova,uint32_t stride)',
                      '    int directSlot(OSObject *surface,IOMemoryDescriptor *memory)',
                      '    bool gpuWrote(const OriginalLegacySwapRequest *request)',
                      '    void fenceTick()', '    void latchTick()'):
        text = function_body(text, signature, '\n        panic("QEMU GOP: unsupported hardware display path");\n    ')
    text = function_body(text, '    void directToBoot()', '''
        if(directOn)panic("QEMU GOP: unexpected DPU state");
    ''')
    text = replace_once(text,
                        '    static constexpr uint32_t kVig[2]={0x4000,0x6000},kCtlFlush=0x15018,kBootIova=0xb8000000U,kBootStride=0x2fa0;\n', '')
    text = replace_once(text, 'extern "C" void native_legacy_pm_observed(unsigned,IOReturn,unsigned long);',
                        '''extern "C" void native_legacy_pm_observed(unsigned,IOReturn,unsigned long);
extern "C" void native_qemu_display_observe(unsigned,IOService *);''')
    text = replace_once(text, '''        if(!logicalPM)return IOMobileFramebufferLegacy::setPowerState(ordinal,device);''',
                        '''        // Observe the original-family branch too: its callback can
        // precede logicalPM. Forward the actual ordinal/device/result unchanged.
        native_qemu_display_observe(5,this);
        if(!logicalPM) {
            IOReturn status=IOMobileFramebufferLegacy::setPowerState(ordinal,device);
            native_qemu_display_observe(6,this);
            return status;
        }''')
    return text


def object_symbols(path):
    data = Path(path).read_bytes()
    if struct.unpack_from('<I', data)[0] != 0xfeedfacf:
        raise ValueError('Expected Mach-O: ' + str(path))
    at = 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        cmd, size = struct.unpack_from('<II', data, at)
        if cmd == 2:
            syms, count, strings, _ = struct.unpack_from('<4I', data, at + 8)
            result = []
            for i in range(count):
                ix, kind, section, desc, va = struct.unpack_from('<IBBHQ', data, syms + i * 16)
                name = data[strings + ix:data.index(b'\0', strings + ix)].decode()
                result.append((name, kind, section, desc, va))
            return result
        at += size
    raise ValueError('No symbol table: ' + str(path))


def qualified_vtable(path, abi):
    data = Path(path).read_bytes()
    symbols = object_symbols(path)
    vtable = next(va for name, kind, section, desc, va in symbols if name == '__ZTV19NativeLegacyDisplay')
    at = 32
    entries = {}
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        cmd, size = struct.unpack_from('<II', data, at)
        if cmd == 0x19:
            for index in range(struct.unpack_from('<I', data, at + 64)[0]):
                sec = at + 72 + index * 80
                address, length, offset = struct.unpack_from('<QQI', data, sec + 32)
                if address <= vtable < address + length:
                    reloc, count = struct.unpack_from('<II', data, sec + 56)
                    for i in range(count):
                        delta, bits = struct.unpack_from('<II', data, reloc + i * 8)
                        if bits >> 27 & 1 and bits >> 25 & 3 == 3 and bits >> 28 == 11:
                            word = struct.unpack_from('<Q', data, offset + delta)[0]
                            entries[address + delta] = (symbols[bits & 0xffffff][0], word)
        at += size
    found = [entries.get(vtable + 16 + i * 8) for i in range(len(abi['slots']))]
    if not all(found) or vtable + 16 + len(found)*8 in entries:
        raise ValueError('Owned Legacy vtable extent changed')
    for i, (name, word) in enumerate(found):
        diversity = int(abi['slots'][i][1], 16)
        if not (word >> 63 and word >> 48 & 1 and word >> 49 & 3 == 0 and (word >> 32) & 0xffff == diversity):
            raise ValueError(f'Slot {i} ({name}) does not use the original IA/address diversity')
    return [name for name, word in found]


def compile_cpp(source, output, command, directory, log):
    args, skip = [], False
    for i, value in enumerate(command):
        if skip:
            skip = False
            continue
        if value in ('-MF', '-MT', '-MJ'):
            skip = True
        elif value == '-o':
            args += ['-o', str(output)]
            skip = True
        elif value.endswith('.cpp'):
            args.append(str(source))
        else:
            args.append(value)
    args += ['-Wno-missing-designated-field-initializers', '-Wno-unused-but-set-global']
    with log.open('w') as stream:
        result = run_recorded(args, cwd=directory, stdout=stream, stderr=subprocess.STDOUT, timeout=300)
    if result.returncode:
        raise RuntimeError(log.read_text())
    return args


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if shutil.disk_usage('/mnt/g').free < 8 * 1024**3:
        raise SystemExit('G: is below 8 GiB; no build started')
    out = args.out.resolve()
    if not str(out).startswith(str(BASE) + '/'):
        raise SystemExit('Output must be a new isolated EXT4 directory under BASE')
    out.mkdir(parents=True, exist_ok=False)
    for rel, expected in SOURCE_HASHES.items():
        if sha(DISPLAY / rel) != expected:
            raise ValueError('Qualified source changed: ' + rel)
    receipt = json.loads((DISPLAY / 'result.json').read_text())
    if sha(receipt['archive']) != receipt['sha256']:
        raise ValueError('Physical archive identity changed')
    abi = json.loads((DISPLAY / 'scripts/legacy-display-24A446.json').read_text())
    if (sha(DISPLAY / 'scripts/legacy-display-24A446.json') !=
            '25cf83fc9d21bac4b1e9cf5e9eccb27ae4aac746be582c0b2781653fe82cf3d1' or
            len(abi['slots']) != 379 or abi['instance_size'] != '0x1dd8'):
        raise ValueError('Require actual D27 Legacy ABI, 379 slots / 0x1dd8 bytes')
    original = DISPLAY / 'build/native-legacy-display'
    for name in ('LegacyDisplayProbe', 'NativeLegacyDisplay', 'LegacyDisplaySupport27', 'KeyStoreProbe'):
        dep = json.loads((original / (name + '.o.dependencies.json')).read_text())
        if not valid(dep):
            raise ValueError('Dependency changed: ' + name)
    source_dir = out / 'source'
    objects = out / 'objects'
    source_dir.mkdir()
    objects.mkdir()
    probe = source_dir / 'LegacyDisplayProbe.cpp'
    probe.write_text(overlay_probe((DISPLAY / 'kits/sheng/LegacyDisplayProbe.cpp').read_text()))
    display = source_dir / 'NativeLegacyDisplay.cpp'
    display.write_text(overlay_display((DISPLAY / 'drivers/GopFramebuffer/NativeLegacyDisplay.cpp').read_text()))
    command = json.loads((original / 'compile-command.json').read_text())
    # Quoted includes must still resolve to the immutable source headers and
    # generated exact D27 ABI, not some other build's headers.
    command += ['-I', str(DISPLAY / 'drivers/GopFramebuffer')]
    command += ['-I', str(source_dir)]
    fields = receipt['source_overlay']['diagnostic_fields']
    (source_dir / 'QemuDisplayOffsets.h').write_text(''.join(
        f'static constexpr unsigned {name}={value};\n' for name, value in (
            ('kQemuRequested',fields['requested']), ('kQemuPowered',fields['powered']),
            ('kQemuCurrent',abi['display']['current']), ('kQemuPending',abi['display']['head']),
            ('kQemuDefaultSurface',abi['display']['default_surface']))))
    observation = source_dir / 'QemuDisplayObservation.cpp'
    shutil.copyfile(HERE / 'QemuDisplayObservation.cpp', observation)
    plan = json.loads((BASE / 'pac-abi-native-019/plan.json').read_text())
    job = next(job for job in plan['jobs'] if Path(job['source']).name == 'IOPlatformExpert.cpp')
    commands = {}
    for source, stem in ((probe, 'LegacyDisplayProbe'), (display, 'NativeLegacyDisplay'), (observation, 'QemuDisplayObservation')):
        commands[stem] = compile_cpp(source, objects / (stem + '.o'), command, job['directory'], out / (stem + '.log'))
    vtable = qualified_vtable(objects / 'NativeLegacyDisplay.o', abi)
    if vtable != qualified_vtable(original / 'NativeLegacyDisplay.o', abi):
        raise ValueError('QEMU Legacy override/binding set differs from qualified D27')
    subprocess.run(['/usr/lib/llvm-23/bin/llvm-objcopy', '--remove-section=__DATA,__mod_init_func',
                    '--globalize-symbol=__GLOBAL__sub_I_NativeLegacyDisplay.cpp',
                    str(objects / 'NativeLegacyDisplay.o'), str(objects / 'NativeLegacyDisplay.late.o')], check=True)
    paths = [objects / 'NativeLegacyDisplay.late.o', original / 'original-bindings.o', original / 'original-addresses.o',
             objects / 'LegacyDisplayProbe.o', original / 'LegacyDisplaySupport27.o',
             DISPLAY / 'build/native-gop-presenter/NativeGOPPresenter.late.o', original / 'KeyStoreProbe.o',
             DISPLAY / 'build/apple-key-store-state/NativeKeyStoreEvents.late.o', original / 'PdxLegacyRequestLayout.o']
    if tuple(path.name for path in paths) != MEMBERS:
        raise ValueError('Unexpected archive membership')
    paths.append(objects / 'QemuDisplayObservation.o')
    for path in paths:
        if not path.is_file():
            raise ValueError('Missing member: ' + str(path))
        if path.parent != objects:
            archived = subprocess.check_output(['/usr/bin/llvm-ar', 'p', receipt['archive'], path.name])
            if hashlib.sha256(archived).hexdigest() != sha(path):
                raise ValueError('Retained member differs from qualified source archive: ' + path.name)
    imported = {name for path in paths for name, kind, *_ in object_symbols(path) if kind == 1}
    forbidden = [name for name in imported if any(value in name for value in ('sheng_cpufreq_probe', 'sheng_gpu_power_probe',
                  'sheng_touch_probe', 'sheng_dpu_probe', 'sheng_wifi_probe', 'sheng_adsp_probe',
                  'native_adreno_fences', 'native_ufs_dpu_map'))]
    if forbidden:
        raise ValueError('Hardware initializer still referenced: ' + ', '.join(forbidden))
    archive = out / 'libQemuD27Display.a'
    subprocess.run(['/usr/bin/llvm-ar', 'rcs', str(archive), *map(str, paths)], check=True)
    kept = {str(path): sha(path) for path in paths}
    result = dict(archive=str(archive), sha256=sha(archive), profile='iPhone14,7 D27AP 24A446 arm64e',
                  source_archive=receipt['archive'], source_archive_sha256=receipt['sha256'],
                  original_kernelcache_sha256=abi['kernelcache_sha256'], slots=len(abi['slots']),
                  authenticated_vtable_slots_verified=len(vtable), original_vtable_bindings_unchanged=True,
                  reused_members_match_qualified_archive=True,
                  members=kept, commands=commands, source_sha256={str(p):sha(p) for p in (probe, display, observation)},
                  patch='QEMU probe omits cpufreq/GPU init; display omits DPU MMIO setup',
                  omitted_members=['CpuFreqProbe.o'], forbidden_hardware_initializers=forbidden,
                  startup_api=['native_legacy_display_probe', 'native_legacy_display_late_probe'],
                  keystore_preserved=True, hid_family_preserved=True, virtual_hid_transport=False,
                  dpu_mmio_setup_compiled=False, native_linked=False, runtime_verified=False,
                  compositor_software_renderer_verified=False, springboard_desktop=False,
                  physical_source_changed=False, device_operations=False)
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k:result[k] for k in ('archive','sha256','slots','keystore_preserved','hid_family_preserved',
                                        'dpu_mmio_setup_compiled','runtime_verified','springboard_desktop')}, indent=2))


if __name__ == '__main__':
    main()
