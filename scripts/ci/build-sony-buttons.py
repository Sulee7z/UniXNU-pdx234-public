#!/usr/bin/env python3
"""Build a separate D27 IOHIDDevice consumer, reusing the qualified HID bindings."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
SHENG = Path('/mnt/f/UniXNU-Port-artifacts/platform067-20261118/sheng')
SHENG_REVISION = '6c42e1055ffb3b335fda991190ad221edaa7af3c'


def sha(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def qualify_buttons(out: Path, builder, touch: Path) -> dict:
    """Use actual D27 fixups, not a renamed/second NativeHidInput definition."""
    fixture = BASE / 'graphics-bindings-002/hid-device-24A446.json'
    if sha(fixture) != 'af3ff79be54e7836c21256984dccb1d8ce14966d6a664c1c11293a0a61439385':
        raise ValueError('Original D27 fixture differs')
    abi = json.loads(fixture.read_text())
    if sha(builder.CACHE) != abi['kernelcache_sha256']:
        raise ValueError('Original D27 kernelcache differs')
    sys.path.insert(0, str(ROOT / 'ci/XnuPrelink'))
    from kc_image import Image
    fixups = Image(builder.CACHE.read_bytes()).fixups()
    original = [fixups[int(abi['vtable'], 16) + 8*i] for i in range(len(abi['slots']))]
    for actual, expected in zip(original, abi['slots']):
        if actual != (int(expected[0], 16), 1, 0, int(expected[1], 16), 1):
            raise ValueError('Original D27 IOHIDDevice fixup differs')
    info = builder.object_info(out / 'objects/SonyButtonsHid.o')
    table = info['tables']['__ZTV14SonyButtonsHid']
    if len(table) != len(original) or len(table) != 207:
        raise ValueError('Consumer subclass vtable extent differs')
    shared = json.loads((touch / 'hid-abi.json').read_text())
    bindings = shared['bindings']
    rows = []
    for i, ((symbol, word), (target, auth, key, div, addr)) in enumerate(zip(table, original)):
        if (word >> 63, word >> 49 & 3, word >> 32 & 0xffff, word >> 48 & 1) != (auth, key, div, addr):
            raise ValueError(f'SonyButtonsHid PAC slot {i}: {symbol}')
        if '11IOHIDDevice' in symbol and int(bindings[symbol], 16) != target:
            raise ValueError(f'Shared HID binding target differs: {symbol}')
        rows.append(dict(slot=i, symbol=symbol, diversity=hex(div)))
    imports = {s['name'] for s in info['symbols'] if s['type'] == 1 and '11IOHIDDevice' in s['name']}
    missing = imports - bindings.keys()
    if missing:
        raise ValueError('Consumer imports need reviewed shared bindings: ' + repr(sorted(missing)))
    for name, target in abi['bindings'].items():
        if name in imports and int(bindings[name], 16) != int(target, 16):
            raise ValueError('Shared HID base constructor/meta target differs: ' + name)
    dwarf = subprocess.check_output([str(builder.LLVM / 'llvm-dwarfdump'), '--debug-info', '--name=IOHIDDevice',
                                    '--show-children', str(out / 'objects/SonyButtonsHid.o')], text=True)
    (out / 'IOHIDDevice.dwarf.txt').write_text(dwarf)
    if 'DW_AT_byte_size\t(0xd0)' not in dwarf and 'DW_AT_byte_size\t(0x00d0)' not in dwarf:
        raise ValueError('Real IOHIDDevice header is not208 bytes')
    result = dict(slots=207, base_bytes=208, all_authenticated_slots_match=True,
                  original_kernelcache_sha256=abi['kernelcache_sha256'], fixture_sha256=sha(fixture),
                  shared_bindings=str(touch / 'hid-abi.json'), shared_bindings_sha256=sha(touch / 'hid-abi.json'),
                  bindings={name: bindings[name] for name in sorted(imports)}, compiled_vtable=rows,
                  duplicate_native_hid_class=False, duplicate_base_binding_objects=False,
                  runtime_qualified=False)
    (out / 'buttons-hid-abi.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--tests', type=Path, help='Optional current-source preflight receipt; final tests always execute frozen snapshots')
    parser.add_argument('--touch-driver', type=Path, default=BASE / 'sony-touch-driver-015',
                        help='Provides the already linked original IOHIDDevice bindings, not touch source')
    args = parser.parse_args()
    out = args.out.resolve()
    if out.parent != BASE or not out.name.startswith('sony-buttons-driver-'):
        raise ValueError('Use a new isolated BASE/sony-buttons-driver-* folder')
    if out.exists():
        raise ValueError('Preserve the existing buttons build')
    # This builds four small objects (~3MiB total), not a native kernel or IMG.
    # Keep a1GiB backing-volume reserve plus32MiB inside the EXT4 output volume.
    if shutil.disk_usage('/mnt/g').free < 1024**3 or shutil.disk_usage(BASE).free < 32*1024**2:
        raise ValueError('Small archive reserve below1GiB host /32MiB output')
    if subprocess.check_output(['git', '-C', str(SHENG), 'rev-parse', 'HEAD'], text=True).strip() != SHENG_REVISION:
        raise ValueError('Official sheng snapshot differs')
    if args.tests:
        preflight = json.loads(args.tests.read_text())
        if not preflight['passed']:
            raise ValueError('Preflight tests failed')
        for path, digest in preflight['sources'].items():
            if sha(Path(path)) != digest:
                raise ValueError('Preflight source changed: ' + path)
    touch = args.touch_driver.resolve()
    receipt = json.loads((touch / 'result.json').read_text())
    for path, digest in receipt['objects'].items():
        if sha(Path(path)) != digest:
            raise ValueError('Shared HID binding provider object changed: ' + path)
    binding_identity = {}
    for name in ('hid-bindings.o', 'hid-addresses.o'):
        previous = BASE / 'sony-touch-driver-014/objects' / name
        current = touch / 'objects' / name
        if sha(previous) != sha(current):
            raise ValueError('Touch015/shared HID binding differs from audited014: ' + name)
        binding_identity[name] = sha(current)
    reference = BASE / 'qemu-input-002'
    out.mkdir(parents=True)
    for folder in ('source','objects','tests-source','test-reference','tools'):
        (out / folder).mkdir()
    shutil.copytree(reference / 'include', out / 'include')
    origin_records = {}
    def snapshot_file(original: Path, target: Path) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        digest = sha(original)
        shutil.copyfile(original, target)
        if sha(target) != digest or sha(original) != digest:
            raise ValueError('Source changed during snapshot copy: '+str(original))
        origin_records[str(target)] = dict(origin=str(original), sha256=digest)
    driver = ROOT / 'drivers/SonyButtons'
    for source in sorted(driver.iterdir()):
        if source.suffix in ('.c','.cpp','.h'):
            snapshot_file(source, out / ('include' if source.suffix=='.h' else 'source') / source.name)
    snapshot_file(SHENG / 'package/BootResetCore.h', out / 'include/BootResetCore.h')
    for fixture in sorted((ROOT / 'tests').glob('sony_buttons*')):
        snapshot_file(fixture, out / 'tests-source' / fixture.name)
    for original in [Path(__file__), ROOT / 'scripts/ci/check-sony-buttons.py',
                     ROOT / 'ci/qemu/display/input/build-input.py', ROOT / 'ci/compile_dependencies.py',
                     ROOT / 'ci/block_descriptor_abi.py']:
        snapshot_file(original, out / 'tools' / original.name)
    apple_hid = Path('/root/unixnu-build/pdx234-local-github-a6d2286-001/out/feeds/IOHIDFamily-f53ac321')
    for relative in ['IOHIDFamily','IOHIDSystem/IOKit/hidsystem','IOHIDSystem/IOHIDDescriptorParser']:
        for source in (apple_hid / relative).iterdir():
            if source.is_file() and source.suffix in ('.c','.h'):
                snapshot_file(source, out / 'test-reference/IOHIDFamily' / relative / source.name)
    snapshot_file(BASE / 'sony-spmi-fix-001/sony-yodo-1.2.0-rel__kernel_platform__msm-kernel__drivers__spmi__spmi-pmic-arb.c',
                  out / 'test-reference/sony-linux-spmi-pmic-arb.c')
    snapshot_manifest = out / 'snapshot-provenance.json'
    snapshot_manifest.write_text(json.dumps(dict(schema=1, files=origin_records,
        originals_are_provenance_not_runtime_build_dependencies=True),indent=2)+'\n')
    # Execute tests FROM the same frozen source/header paths the target compiler
    # will consume. Existing failed/stale004 receipts remain untouched.
    test_command = ['python3','-B',str(out / 'tools/check-sony-buttons.py'),
                    '--out',str(out / 'tests'),'--snapshot',str(out)]
    done = subprocess.run(test_command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
    (out / 'tests.log').write_text(done.stdout)
    if done.returncode:
        raise RuntimeError('Frozen snapshot tests failed:\n'+done.stdout[-12000:])
    final_tests = out / 'tests/result.json'
    tests = json.loads(final_tests.read_text())
    if (not tests['passed'] or tests.get('compiled_snapshot') != str(out) or
        not tests.get('verbatim_sony_linux_read_executed') or not tests.get('linux_read_offsets_opcode_and_status_match')):
        raise ValueError('Actual frozen-source sanitizer/parser/read comparison required')
    for path, digest in tests['tested_production_snapshot'].items():
        if sha(Path(path)) != digest or not Path(path).is_relative_to(out):
            raise ValueError('Tested production file is not the immutable compile snapshot: '+path)
    # Record every transitive real header copied into the build, including the
    # generated HIDDriverKit declarations. No private IOService stand-in.
    headers = {str(p): sha(p) for p in (out / 'include').rglob('*') if p.is_file()}
    sys.path.insert(0, str(out / 'tools'))
    spec = importlib.util.spec_from_file_location('sony_buttons_hid_builder', out / 'tools/build-input.py')
    builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)
    builder.CI = ROOT / 'ci' # Read-only original-kernel parsing, not compile source.
    from block_descriptor_abi import FLAGS as block_flags
    includes = ['-I', str(out / 'include'), '-I', str(out / 'source'),
                '-idirafter', str(builder.SDK / 'System/Library/Frameworks/Kernel.framework/Versions/A/Headers')]
    commands = {}
    for stem, suffix in [('SonyButtonsHid', '.cpp'), ('SonyButtons', '.cpp'), ('SonyButtonsSpmi', '.cpp'), ('SonyButtonsCore', '.c')]:
        source = out / 'source' / (stem + suffix)
        commands[stem] = builder.compile_cpp(source, out / 'objects' / (stem + '.o'), includes, block_flags)
        if '-fptrauth-function-pointer-type-discrimination' not in commands[stem]:
            raise ValueError('Function-pointer PAC type discrimination missing')
    dependencies = {}
    for stem in commands:
        receipt_path = out / 'objects' / (stem + '.o.dependencies.json')
        if not receipt_path.is_file():
            raise ValueError('Actual transitive-header compile receipt missing: ' + stem)
        dependencies[str(receipt_path)] = sha(receipt_path)
        for path in json.loads(receipt_path.read_text())['dependencies']:
            if Path(path).is_relative_to(driver) or Path(path) == SHENG / 'package/BootResetCore.h':
                raise ValueError('Target compile still consumed mutable owned source/header: '+path)
    qualify_buttons(out, builder, touch)
    # Run the official exact220event-schema/class-identity qualifier without
    # compiling or archiving its NativeHidInput. Buttons never replace a vtable.
    shutil.copyfile(reference / 'source/NativeHidInput.cpp', out / 'source/NativeHidInput.cpp')
    builder.qualify_edge(out)
    late = out / 'objects/SonyButtonsHid.late.o'
    subprocess.run(['llvm-objcopy-23', '--remove-section=__DATA,__mod_init_func',
                    '--globalize-symbol=__GLOBAL__sub_I_SonyButtonsHid.cpp',
                    str(out / 'objects/SonyButtonsHid.o'), str(late)], check=True)
    members = [late, *(out / 'objects' / (name + '.o') for name in ['SonyButtons', 'SonyButtonsSpmi', 'SonyButtonsCore'])]
    late_info = builder.object_info(late)
    if any(section['name'] == '__mod_init_func' for section in late_info['sections']):
        raise ValueError('Consumer metaclass still initializes before originalHID loads')
    archive = out / 'libSonyD27Buttons.a'
    subprocess.run(['llvm-ar', 'rcs', str(archive), *map(str, members)], check=True)
    symbols = subprocess.check_output(['llvm-nm-23', '--defined-only', str(archive)], text=True)
    (out / 'defined-symbols.txt').write_text(symbols)
    if any(token in symbols for token in ('NativeHidInput', 'native_touch_', 'native_hid_', 'native_buttons_set_sink',
                                          '__ZTV11IOHIDDevice', '__ZN11IOHIDDevice10gMetaClassE')):
        raise ValueError('Archive duplicates shared HID ABI or touch globals')
    disassembly = {}
    for stem in commands:
        text = subprocess.check_output([str(builder.LLVM / 'llvm-objdump'), '--macho', '--disassemble',
                                        str(out / 'objects' / (stem + '.o'))], text=True)
        path = out / (stem + '.disassembly.txt'); path.write_text(text)
        disassembly[str(path)] = sha(path)
        if stem in ('SonyButtons', 'SonyButtonsHid', 'SonyButtonsSpmi') and ('pacibsp' not in text or 'retab' not in text):
            raise ValueError('Native PAC prologue/return absent: ' + stem)
    # Exactly this observer read command, bounded official completion loop and
    # no PMIC write helper are present in the actual ARM64 source object.
    spmi = (out / 'SonyButtonsSpmi.disassembly.txt').read_text()
    if '_sony_buttons_qualify_apid' not in spmi or '#0x86a0' not in spmi or '#0x800, lsl #16' not in spmi:
        raise ValueError('Actual owned observer read/bounded wait instruction anchors differ')
    sources = [*out.glob('source/SonyButtons*'), *out.glob('include/SonyButtons*.h'),
               out / 'include/BootResetCore.h', *out.glob('tools/*.py')]
    for path,digest in tests['tested_production_snapshot'].items():
        if sha(Path(path)) != digest:
            raise ValueError('Production snapshot changed after tests/compile: '+path)
    result = dict(archive=str(archive), sha256=sha(archive), commands=commands,
                  objects={str(p): sha(p) for p in members}, sources={str(p): sha(p) for p in sources}, headers=headers,
                  compile_dependency_receipts=dependencies, native_disassembly=disassembly,
                  shared_binding_objects={str(touch / 'objects' / name): sha(touch / 'objects' / name)
                                          for name in ('hid-bindings.o', 'hid-addresses.o')},
                  tests=str(final_tests), tests_sha256=sha(final_tests), official_sheng=SHENG_REVISION,
                  immutable_snapshot=True, tested_and_target_compiled_same_snapshot=True,
                  snapshot_manifest=str(snapshot_manifest), snapshot_manifest_sha256=sha(snapshot_manifest),
                  mutable_owned_source_dependency=False,
                  hid_slots=207, hid_base_bytes=208, event_service_slots=220,
                  hid_abi_sha256=sha(out / 'buttons-hid-abi.json'), event_abi_sha256=sha(out / 'edge-abi.json'),
                  required_shared_binding_provider=str(touch / 'libSonyD27Touch.a'),
                  required_shared_binding_provider_sha256=sha(touch / 'libSonyD27Touch.a'),
                  touch015_bindings_identical_to014=binding_identity,
                  source_driver=str(out),
                  startup='native_sony_buttons_start', startup_must_be_called_by_native_integration=True,
                  required_args=['sony-buttons=1'],
                  qualified_read_args=['sony-buttons-read-qualified=1',
                                       'sony-buttons-pon-apid=560'],
                  optional_args=['sony-buttons-gpio-apid=<qualified owned APID for PPID18d>'],
                  descriptor='separate ConsumerControl report2: Power bit1 / VolumeUp bit2 / VolumeDown bit3',
                  synthetic_home=False, pmic_register_writes=False, pmic_or_apid_sweeps=False,
                  interrupt_or_power_ownership_changes=False, owned_observer_reads_only=True,
                  pmic_read_mapping_hardware_qualified=False, handset_runtime_verified=False,
                  neutral_hid_registration_without_mmio=True, missing_qualification_is_logged=True,
                  source_qualified_experimental_power_volume_up=True,
                  manual_test_args=['sony-buttons=1','sony-buttons-read-qualified=1','sony-buttons-pon-apid=560'],
                  previous_completed_xnu_read_required=False,
                  volume_down_enabled_for_manual_candidate=False,
                  linux_read_offsets_opcode_status_match=True,
                  linux_timeout_vs_native='Linux1000x1us; unchanged official br_wait100000polls, not equivalent calibrated elapsed time',
                  pon560_actual_access_set={
                      'reads':['0x0c400000','0x0c400004','0x0c4028c0','0x0c42d8c0','0x0c444608','0x0c444618'],
                      'writes':{'0x0c444600':'0x08000100 EXT_READL offset10 count1 only'}},
                  offline_evidence=tests['offline_evidence'], offline_evidence_sha256=tests['offline_evidence_sha256'],
                  limitations=['ManualPower/VolumeUp bringup is source-qualified using OEM/AndroidAPID560 plus sameboot prechecks; runtime acceptance remains false',
                               'sony-buttons=1 alone publishes only neutral HID; no PMIC MMIO or physical-key repair claim',
                               'Explicit experimental bootarg opt-in and exact prepare/per-read APID/owner validation required; no completed read certificate prerequisite',
                               'Idle20ms/active5ms IOTimer; one or two bounded observer reads per tick',
                               'Three read failures stop hardware access and queue explicitly marked neutral',
                               'External abort on metadata/CMD/STATUS/RDATA remains untested and cannot be converted into these return-code stops',
                               'No OS power policy, suspend/wake or backboardd acceptance claimed'])
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k not in ('commands', 'objects', 'sources', 'headers')}, indent=2))


if __name__ == '__main__':
    main()
