#!/usr/bin/env python3
"""Bounded host checks and arm64e compilation for independent Sony radio ADT/address inputs."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ci'))
from compile_dependencies import run_recorded, valid, digest
from block_descriptor_abi import enabled
from platform069 import radio_adt, radio_address

PRE_069_WIFI = Path('/mnt/e/UniXNU-sheng27-sony-20261113/sony-wcn-067-002/source/WifiProbe.cpp')
ADAPT_069 = ROOT / 'drivers/SonyWcn/platform069/adapt069.py'
START = 'extern "C" void native_sony_wifi_start(void)'
WORKER = 'void wifiThread(void *arg, wait_result_t)'


def run(command, out: Path, *, cwd=None):
    process = subprocess.run(list(map(str, command)), cwd=cwd, capture_output=True, text=True, timeout=120)
    out.write_text(process.stdout + process.stderr)
    if process.returncode:
        raise RuntimeError(f'{out}: exit {process.returncode}\n' + (process.stdout + process.stderr)[-4000:])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--provider', type=Path, default=radio_adt.ARTIFACTS / 'radio-provider069-007')
    args = parser.parse_args()
    provider = args.provider.resolve()
    source_inputs = radio_adt.verify_inputs()

    original_receipt = provider / 'objects/WifiProbe.o.dependencies.json'
    selected_source = provider / 'source/WifiProbe.cpp'
    original = json.loads(original_receipt.read_text())
    if (original['source'] != str(selected_source) or not valid(original) or
            digest(original['object']) != original['object_sha256'] or not enabled(original['command'])):
        raise ValueError('Selected immutable Sony Wi-Fi compiler/dependency identity differs')
    adapt069 = radio_adt.load_module('selected_sony069_adapt', ADAPT_069)
    baseline = PRE_069_WIFI.read_text()
    adapted = adapt069.wifi(baseline)
    if adapted.encode() != selected_source.read_bytes():
        raise ValueError('adapt069.wifi of the actual 067 Sony source differs from the frozen build007 source')
    official = (radio_adt.SHENG_REPO / 'package/WifiProbe.cpp').read_text()
    address_bodies = radio_address.validate_bodies(official)
    changed = radio_address.wifi(adapted)
    if radio_address.validate_bodies(changed) != address_bodies:
        raise ValueError('Pinned Wi-Fi address bodies changed')
    if radio_address.function(changed, WORKER) != radio_address.function(adapted, WORKER):
        raise ValueError('Address wrapper changed the build007 Wi-Fi worker')

    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    for child in ('source', 'objects', 'host', 'source-inputs', 'test-sources'):
        (out / child).mkdir()
    adt = radio_adt.build(out / 'adt')

    helper = ROOT / 'drivers/SonyWcn/platform069/SonyWifiAddress069.cpp'
    shutil.copyfile(helper, out / 'source/SonyWifiAddress069.cpp')
    (out / 'source/WifiProbe.cpp').write_text(changed)
    archived_sources = {}
    for src, name in ((PRE_069_WIFI, 'WifiProbe.067.cpp'), (selected_source, 'WifiProbe.007.cpp'),
                      (ADAPT_069, 'adapt069.py'), (ROOT / 'ci/platform069/radio_address.py', 'radio_address.py')):
        snapshot = out / 'source-inputs' / name
        shutil.copyfile(src, snapshot)
        archived_sources[name] = dict(path=str(snapshot), source=str(src), sha256=digest(snapshot))
    for name in ('sony_radio_address069.cpp', 'sony_radio_address_start069.cpp', 'test_sony_radio_adt069.py'):
        shutil.copyfile(ROOT / 'tests' / name, out / 'test-sources' / name)
    (out / 'host/SonyWifiAddressReference069.h').write_text(
        radio_address.function(official, 'bool boardMac(').replace('bool boardMac(', 'bool officialBoardMac(', 1) + '\n')
    (out / 'host/SonyWifiStart069.h').write_text(radio_address.function(changed, START) + '\n')
    host = []
    for name in ('sony_radio_address069', 'sony_radio_address_start069'):
        cmd = ['clang++', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
               '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-I' + str(out / 'host'),
               str(ROOT / 'tests' / (name + '.cpp')), '-o', str(out / 'host' / name)]
        run(cmd, out / (name + '.compile.log'))
        run([out / 'host' / name], out / (name + '.run.log'))
        host.append(dict(source=str(ROOT / 'tests' / (name + '.cpp')), command=cmd, passed=True))
    run([sys.executable, '-B', '-m', 'unittest', 'discover', '-s', ROOT / 'tests', '-p',
         'test_sony_radio_adt069.py', '-v'], out / 'adt-tests.log')

    objects = []
    for name in ('SonyWifiAddress069.cpp', 'WifiProbe.cpp'):
        source = out / 'source' / name
        obj = out / 'objects' / (source.stem + '.o')
        command = []
        index = 0
        while index < len(original['command']):
            value = original['command'][index]
            if value in ('-MF', '-MT', '-MQ'):
                index += 2
                continue
            if value not in ('-MD', '-MMD'):
                command.append(value)
            index += 1
        command[command.index(original['source'])] = str(source)
        command[command.index('-o') + 1] = str(obj)
        command += ['-iquote', str(provider / 'source')]
        with (out / (name + '.target.log')).open('x') as log:
            process = run_recorded(command, cwd=original['cwd'], stdout=log, stderr=subprocess.STDOUT, timeout=120)
        if process.returncode:
            raise RuntimeError((out / (name + '.target.log')).read_text()[-4000:])
        receipt = obj.with_name(obj.name + '.dependencies.json')
        compiled = json.loads(receipt.read_text())
        if (not valid(compiled) or not enabled(compiled['command']) or
                '-fptrauth-function-pointer-type-discrimination' not in compiled['command']):
            raise ValueError('New address object dependency/PAC validation failed')
        objects.append(dict(source=str(source), source_sha256=digest(source), object=str(obj),
                            object_sha256=digest(obj), dependency_receipt=str(receipt),
                            dependency_receipt_sha256=digest(receipt)))
    disassembly = subprocess.run(['llvm-objdump-23', '--macho', '--disassemble', '--reloc',
                                   str(out / 'objects/WifiProbe.o')], capture_output=True, text=True, check=True, timeout=30).stdout
    marker = '_native_sony_wifi_start:\n'
    if disassembly.count(marker) != 1:
        raise ValueError('Compiled Wi-Fi start symbol is missing or ambiguous')
    start_code = disassembly.split(marker, 1)[1].split('\n__ZN', 1)[0]
    required = ['_sony_wcn_platform_ready', '_sony_wcn_platform_wifi_ready',
                '_native_sony_wifi_publish', '_kernel_thread_start']
    if (any(token not in start_code for token in required) or
            [start_code.index(token) for token in required] != sorted(start_code.index(token) for token in required) or
            '_sony_wcn_wifi_inputs_ready' in start_code or
            'pacibsp' not in start_code or 'retab' not in start_code):
        raise ValueError('Compiled provider/ITS/publication/worker order or PAC return differs')
    (out / 'wifi-start.asm').write_text(marker + start_code)
    worker_marker = '__ZN12_GLOBAL__N_110wifiThreadEPvi:\n'
    if disassembly.count(worker_marker) != 1:
        raise ValueError('Compiled bounded Wi-Fi worker symbol is missing or ambiguous')
    worker_code = disassembly.split(worker_marker, 1)[1].split('\n__ZN', 1)[0]
    worker_order = ['_sony_wcn_wifi_inputs_ready', '__ZN12_GLOBAL__N_18boardMacEPh',
                    '__ZN12_GLOBAL__N_19mapWindowERNS_6WindowEyyj']
    if (any(token not in worker_code for token in worker_order) or
            [worker_code.index(token) for token in worker_order] != sorted(worker_code.index(token) for token in worker_order)):
        raise ValueError('Build007 firmware gate moved after address or MMIO mapping in the worker')
    (out / 'wifi-worker.asm').write_text(worker_marker + worker_code)

    record = dict(passed=True, host_only=True, device_operations=False, adt=adt,
                  input_verification=source_inputs, host_tests=host, target_objects=objects,
                  original_wifi_compile_receipt=str(original_receipt),
                  original_wifi_compile_receipt_sha256=digest(original_receipt),
                  source_inputs=archived_sources, address_body_sha256=address_bodies,
                  test_source_sha256={path.name: digest(path) for path in (out / 'test-sources').iterdir()},
                  source_sha256={str(path): digest(path) for path in [Path(__file__), helper,
                      ROOT / 'scripts/ci/compose-sony-wifi-address069.py',
                      ROOT / 'ci/platform069/radio_adt.py', ROOT / 'ci/platform069/radio_address.py', ADAPT_069,
                      ROOT / 'tests/sony_radio_address069.cpp', ROOT / 'tests/sony_radio_address_start069.cpp',
                      ROOT / 'tests/test_sony_radio_adt069.py']},
                  native_linked=False, strict_prelink_verified=False, startup_owner_modified=False,
                  compiled_publication_before_worker=True, compiled_pac_entry_return=True,
                  compiled_worker_firmware_gate_before_address_and_mapping=True,
                  selected_provider007_wifi_source_sha256=digest(selected_source),
                  selected_provider007_overlay_sha256=digest(out / 'source/WifiProbe.cpp'),
                  build007_source_reproduced_byte_for_byte=True, worker_source_unchanged=True,
                  integration_anchor='radio_address.wifi(adapt069.wifi(067 Sony WifiProbe source)) plus SonyWifiAddress069.cpp',
                  worker_contract='The build007 entry checks provider/ITS, publishes address properties, and queues the worker. The worker still validates firmware before publishMac and any MMIO.',
                  limitations=['Local software identity follows the pinned sheng boardMac/wlan_mac.bin policy.',
                               'Final native call order and handset execution are unverified.'])
    (out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({key: record[key] for key in ('passed', 'host_only', 'target_objects', 'integration_anchor', 'limitations')}, indent=2))


if __name__ == '__main__':
    main()
