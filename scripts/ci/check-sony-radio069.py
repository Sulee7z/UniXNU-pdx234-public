#!/usr/bin/env python3
"""ASan/UBSan Sony069 firmware, worker-gate and locked Ath12k API2 checks.

Run in UniXNU-Build. All generated files and command logs go to a NEW --out.
No driver edits, device operations, guests, native relinks or firmware writes.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

REPO = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/f/UniXNU-Port-artifacts/platform069-20261118')
OLD = Path('/mnt/e/UniXNU-sheng27-sony-20261113/sony-wcn-067-002')
OLD16_PROVIDER = BASE / 'radio-provider069-007'


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def function(text: str, name: str) -> str:
    """Extract one complete function verbatim, accepting nested C blocks."""
    pattern = re.compile(r'(?m)^[ \t]*(?:static\s+)?(?:inline\s+)?(?:int|void|bool|size_t|u8|u32|unsigned\s+int|long)\s+\b' + re.escape(name) + r'\s*\(')
    matches = list(pattern.finditer(text))
    require(len(matches) == 1, f'Expected one definition for {name}: {len(matches)}')
    start = matches[0].start()
    brace = text.index('{', matches[0].end())
    depth = 0
    # These selected functions have no brace characters inside string literals.
    for i in range(brace, len(text)):
        depth += (text[i] == '{') - (text[i] == '}')
        if depth == 0:
            return text[start:i + 1] + '\n'
    raise ValueError(f'Unclosed function {name}')


def load_adapter(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem + '_test_only', path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def api2_calls(text: str) -> list[tuple[str, str, str, str]]:
    return re.findall(r'\bath12k_core_fetch_board_data_api_n\(\s*ab,\s*bd,\s*(\w+),'
                      r'\s*(\w+),\s*(\w+),\s*(\w+)\s*\)', text)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--provider', type=Path, default=BASE / 'radio-provider069-008')
    parser.add_argument('--inputs', type=Path, default=BASE / 'radio-inputs069-003')
    parser.add_argument('--old', type=Path, default=OLD)
    parser.add_argument('--cc', default='/usr/bin/clang')
    parser.add_argument('--cxx', default='/usr/bin/clang++')
    args = parser.parse_args()
    require(sys.platform == 'linux', 'Run inside the UniXNU-Build WSL distribution')
    args.provider = args.provider.resolve()
    out = args.out.resolve()
    require(str(out).startswith('/mnt/f/UniXNU-Port-artifacts/'), 'Receipts must use isolated F artifacts')
    out.mkdir(parents=True, exist_ok=False)
    result: dict = {
        'schema': 1, 'passed': False, 'created_utc': datetime.now(timezone.utc).isoformat(),
        'repo': str(REPO), 'provider': str(args.provider), 'inputs': str(args.inputs),
        'scope': 'Host firmware qualification; verbatim worker prefixes, SonyBoard2, locked API2 parser and adapted Ath12k call sites',
        'hardware_verified': False, 'device_operations': False, 'guest_operations': False,
        'commands': [], 'sources': {}, 'tests': {},
        'limits': [
            'Worker tests execute unchanged pre-qualification prefixes to the first post-gate boundary; no electrical power sequence is executed.',
            'ROM/BID files are tested individually by requested name; actual controller ROM/BID selection requires handset runtime.',
            'The captured .ver metadata is SHA256-qualified but the actual downloader intentionally refuses .ver names.',
            'API2 tests execute the provider call sites and locked parser with host firmware requests and captured WLAN bytes. Search and variant inputs are test vectors.',
            'ASan/UBSan host checks do not qualify arm64e PAC, physical VFS, PCIe, UART, ITS, DMA or radio hardware.',
        ],
    }

    def record(path: Path) -> None:
        result['sources'][str(path)] = digest(path)

    def write(name: str, text: str) -> Path:
        path = out / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def run(label: str, command: list[str]) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env['ASAN_OPTIONS'] = 'detect_leaks=1:abort_on_error=1:strict_string_checks=1'
        env['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
        completed = subprocess.run(command, cwd=out, env=env, capture_output=True, text=True, timeout=45)
        log = write('logs/' + label + '.log', completed.stdout + completed.stderr)
        result['commands'].append({'label': label, 'argv': command, 'exit': completed.returncode, 'log': str(log), 'log_sha256': digest(log)})
        require(completed.returncode == 0, f'{label} unexpected exit {completed.returncode}; see {log}')
        return completed

    try:
        record(Path(__file__).resolve())
        source = args.provider / 'source'
        provider_receipt = args.provider / 'result.json'
        receipt = json.loads(provider_receipt.read_text())
        require(receipt['passed'], 'Provider compile receipt is not passed')
        record(provider_receipt)
        for archive, sha_key in [('libSonyRadioPlatform069.a', 'provider_sha256'), ('libSonyWcn.a', 'board_sha256'), ('libSonyAth12kCore.a', 'core_sha256')]:
            require(digest(args.provider / archive) == receipt[sha_key], f'Provider archive drift: {archive}')

        def provider_source(name: str) -> Path:
            path = source / name
            record(path)
            require(result['sources'][str(path)] == receipt['inputs'][str(path)], f'Provider source drift: {path}')
            return path

        driver = REPO / 'drivers/SonyWcn/platform069'
        adapter = driver / 'adapt069.py'
        address_adapter = REPO / 'ci/platform069/radio_address.py'
        # Suppress repository __pycache__ writes: only new tests/checker and F are owned.
        sys.dont_write_bytecode = True
        record(adapter)
        record(address_adapter)
        module = load_adapter(adapter)
        address = load_adapter(address_adapter)
        for name, adapt in [('WifiFirmware.c', module.raw_firmware), ('BluetoothFirmware.c', module.bluetooth_firmware),
                            ('WifiProbe.cpp', lambda text: address.wifi(module.wifi(text))), ('BluetoothProbe.cpp', module.bluetooth)]:
            old = args.old / 'source' / name
            record(old)
            require(adapt(old.read_text()) == provider_source(name).read_text(), f'Current adapter does not reproduce provider source {name}')
        for name in ['SonyWcnQualification.c', 'SonyBoard2.c', 'SonyBoard2.h']:
            record(driver / name)
            require(digest(driver / name) == digest(provider_source(name)), f'Worktree/provider source differs: {name}')
        for name in ['WifiFirmware.h', 'BluetoothFirmware.h', 'SonyFirmware.generated.h']:
            provider_source(name)

        manifest_path = args.inputs / 'firmware-manifest.json'
        manifest = json.loads(manifest_path.read_text())
        require(len(manifest['files']) == 53, 'Expected4WLAN+49BTcaptured files')
        record(manifest_path)
        entries = []
        expected_header = {}
        for f in manifest['files']:
            real, staged = Path(f['path']), Path(f['staged'])
            require(f['phone_hash_matches'] and len(real.read_bytes()) == f['bytes'] and digest(real) == f['sha256'], f'Captured file mismatch {real}')
            require(staged.stat().st_size == f['bytes'] and digest(staged) == f['sha256'], f'Staged file mismatch {staged}')
            wifi = '/ath12k/' in str(staged)
            name = staged.name if wifi else 'qca/' + staged.name
            expected_header[name] = (f['bytes'], f['sha256'])
            entries.append('{' + ','.join([json.dumps(name), json.dumps(str(real)), str(f['bytes']), str(int(wifi)), 'NULL']) + '},')
        header = (source / 'SonyFirmware.generated.h').read_text()
        actual_header = {}
        for name, size, sha in re.findall(r'\{"([^"]+)",(\d+),\{([^}]+)\}\}', header):
            actual_header[name] = (int(size), bytes(int(x, 16) for x in sha.split(',')).hex())
        require(actual_header == expected_header, 'Actual compiled SHA manifest does not match all53captured/staged entries')
        result['firmware_manifest'] = {'captured_files': len(entries), 'wifi': sum(not n.startswith('qca/') for n in actual_header), 'bluetooth': sum(n.startswith('qca/') for n in actual_header), 'compiled_header_matches': True, 'files': expected_header}
        write('fixtures.inc', 'struct host_fixture host_files[]={\n' + '\n'.join(entries) + '\n};\n')

        shims = out / 'shims'
        for name in ['sys/param.h', 'sys/systm.h', 'sys/proc.h', 'sys/vnode.h', 'sys/uio.h', 'sys/fcntl.h', 'sys/kauth.h', 'sys/errno.h', 'IOKit/IOLib.h']:
            write('shims/' + name, '#pragma once\n#include "sony_radio069_host.h"\n')
        write('shims/libkern/crypto/sha2.h', '#pragma once\n#include <openssl/sha.h>\n')
        # Copy unchanged qualified sources to avoid quote-include precedence
        # selecting generated headers from an unrelated/native work directory.
        for name in ['WifiFirmware.c', 'BluetoothFirmware.c', 'WifiFirmware.h', 'BluetoothFirmware.h',
                     'SonyFirmware.generated.h', 'SonyWcnQualification.c', 'SonyBoard2.c', 'SonyBoard2.h']:
            shutil.copyfile(source / name, out / name)
        tests = REPO / 'tests'
        for name in ['sony_radio069_host.h', 'sony_radio069_vfs.c', 'sony_radio069_firmware.c', 'sony_radio069_gates.cpp', 'sony_radio069_board2.c']:
            record(tests / name)
            shutil.copyfile(tests / name, out / name)

        locked_path = args.old / 'components/Ath12kWifi/out/ath12k-src/core.c'
        record(locked_path)
        locked = locked_path.read_text()
        names = ['__ath12k_core_create_board_name', 'ath12k_core_create_board_name',
                 'ath12k_core_create_fallback_board_name', 'ath12k_core_create_bus_type_board_name',
                 'ath12k_core_free_bdf', 'ath12k_core_parse_bd_ie_board',
                 'ath12k_core_fetch_board_data_api_n', 'ath12k_core_fetch_board_data_api_1']
        blocks = {name: function(locked, name) for name in names}
        adapted = provider_source('core.c').read_text()
        require(module.ath12k_core(locked) == adapted, 'Provider core is not the expected board-key adaptation')
        for name, block in blocks.items():
            require(function(adapted, name) == block, f'Provider changed locked Ath12k helper {name}')
        hw_path = locked_path.with_name('hw.h'); qmi_path = locked_path.with_name('qmi.h'); core_h_path = locked_path.with_name('core.h')
        hw, qmi, core_h = hw_path.read_text(), qmi_path.read_text(), core_h_path.read_text()
        for path in [hw_path, qmi_path, core_h_path]:record(path)
        constants = []
        for text, name in [(hw, 'ATH12K_BOARD_MAGIC'), (hw, 'ATH12K_BOARD_API2_FILE'),
                           (hw, 'ATH12K_DEFAULT_BOARD_FILE'), (hw, 'ATH12K_REGDB_FILE_NAME'),
                           (qmi, 'ATH12K_QMI_BDF_EXT_STR_LENGTH'), (qmi, 'ATH12K_BOARD_ID_DEFAULT'),
                           (locked, 'BOARD_NAME_SIZE')]:
            match = re.search(r'^#define[ \t]+' + name + r'[ \t]+[^\n]+', text, re.M)
            require(match is not None, 'Missing locked constant ' + name)
            constants.append(match.group())
        start, end = hw.index('struct ath12k_fw_ie {'), hw.index('static inline const char *ath12k_bd_ie_type_str')
        enum_match = re.search(r'enum\s+\w+\s*\{\s*ATH12K_BDF_SEARCH_DEFAULT,\s*ATH12K_BDF_SEARCH_BUS_AND_BOARD,?\s*\};', core_h)
        require(enum_match is not None, 'Locked search-mode enum differs')
        helpers = write('ath12k-board-verbatim.inc', '\n'.join(constants) + '\ntypedef uint32_t __le32;\n'
                        + enum_match.group() + '\n' + hw[start:end] + '\n' + '\n'.join(blocks.values()))
        callsite_blocks = []
        callsite_receipt = {}
        for caller, role, fallback in [('ath12k_core_fetch_bdf', 'BOARD', 'fallback_boardname'),
                                       ('ath12k_core_fetch_regdb', 'REGDB', 'default_boardname')]:
            original, current = function(locked, caller), function(adapted, caller)
            expected = [(key, f'ATH12K_BD_IE_{role}', f'ATH12K_BD_IE_{role}_NAME', f'ATH12K_BD_IE_{role}_DATA')
                        for key in ('boardname', fallback)]
            require(api2_calls(original) == api2_calls(current) == expected, f'API2 call-site arguments drift: {caller}')
            callsite_blocks.append(current)
            callsite_receipt[caller] = {'locked_sha256': hashlib.sha256(original.encode()).hexdigest(),
                                        'adapted_sha256': hashlib.sha256(current.encode()).hexdigest(),
                                        'api2_arguments': [dict(zip(('key', 'outer_ie', 'name_ie', 'data_ie'), call)) for call in expected]}
        callsites = write('ath12k-api2-callsites.inc', '\n'.join(callsite_blocks))
        result['locked_core'] = {
            'path': str(locked_path), 'sha256': digest(locked_path),
            'adapted_path': str(source / 'core.c'), 'adapted_sha256': digest(source / 'core.c'),
            'extracted_functions': {name: hashlib.sha256(block.encode()).hexdigest() for name, block in blocks.items()},
            'adapted_call_sites': callsite_receipt,
            'includes': {str(path): digest(path) for path in (helpers, callsites)},
            'extraction': 'Verbatim locked helpers and provider call-site bodies. Host observer records API2 arguments then invokes the locked parser.',
        }
        wifi_worker = function((source / 'WifiProbe.cpp').read_text(), 'wifiThread')
        bt_worker = function((source / 'BluetoothProbe.cpp').read_text(), 'worker')
        wifi_prefix = wifi_worker[:wifi_worker.index('    publishMac();')]
        bt_prefix = bt_worker[:bt_worker.index('    struct qbt_platform ops=')]
        require('sony_wcn_wifi_inputs_ready()' in wifi_prefix and 'sony_wcn_bluetooth_inputs_ready()' in bt_prefix, 'Worker prefix lacks actual qualification call')
        bt_failure = function((source / 'BluetoothProbe.cpp').read_text(), 'bootFailure069')
        write('worker-gates.inc', wifi_prefix + '    host_power_boundary();\n}\n' + bt_failure + bt_prefix + '    host_power_boundary();\n}\n')
        result['worker_prefixes'] = {'wifi_sha256': hashlib.sha256(wifi_prefix.encode()).hexdigest(), 'bluetooth_sha256': hashlib.sha256(bt_prefix.encode()).hexdigest(), 'endpoints': ['before publishMac()/first mapWindow', 'before qbt_platform ops/qbt_create/first powerOn']}

        cflags = ['-std=gnu11', '-O1', '-g', '-fno-omit-frame-pointer', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-Wno-unused-function', '-Wno-deprecated-declarations', '-I' + str(shims), '-I' + str(out)]
        objects = []
        for name in ['WifiFirmware.c', 'BluetoothFirmware.c', 'SonyWcnQualification.c', 'sony_radio069_vfs.c']:
            obj = out / (name + '.o')
            run('compile-' + name, [args.cc, *cflags, '-c', str(out / name), '-o', str(obj)])
            objects.append(str(obj))
        firmware_exe = out / 'firmware-tests'
        run('link-firmware', [args.cc, *cflags, str(out / 'sony_radio069_firmware.c'), *objects, '-lcrypto', '-o', str(firmware_exe)])
        firmware = run('run-firmware', [str(firmware_exe)])
        result['tests']['firmware'] = json.loads(firmware.stdout.splitlines()[-1])
        gate_exe = out / 'worker-gate-tests'
        cxxflags = [f for f in cflags if f != '-std=gnu11']
        run('link-gates', [args.cxx, '-std=c++17', *cxxflags, str(out / 'sony_radio069_gates.cpp'), *objects, '-lcrypto', '-o', str(gate_exe)])
        gates = run('run-gates', [str(gate_exe)])
        result['tests']['worker_gates'] = json.loads(gates.stdout.splitlines()[-1])
        board_exe = out / 'board2-tests'
        run('link-board2', [args.cc, *cflags, str(out / 'sony_radio069_board2.c'), str(out / 'sony_radio069_vfs.c.o'), '-o', str(board_exe)])
        board = run('run-board2', [str(board_exe)])
        rows = [json.loads(line) for line in board.stdout.splitlines()]
        *vectors, summary = rows
        require(summary['passed'] is True and len(vectors) == summary['role_vectors'], 'Incomplete Board2 vector results')
        result['tests']['board2'] = {**summary, 'vectors': vectors}
        # Keep the original 16-byte writer as an independent negative control.
        frozen_receipt_path = OLD16_PROVIDER / 'result.json'
        record(frozen_receipt_path)
        frozen = json.loads(frozen_receipt_path.read_text())
        require(frozen['passed'], 'Frozen 007 compile receipt is not passed')
        negative = out / 'negative007'
        negative.mkdir()
        for name in ['SonyBoard2.c', 'SonyBoard2.h']:
            old_file = OLD16_PROVIDER / 'source' / name
            record(old_file)
            require(digest(old_file) == frozen['inputs'][str(old_file)], f'Old16byte source drift: {name}')
            require(digest(old_file) != digest(source / name), f'Expected distinct old16byte source: {name}')
            shutil.copyfile(old_file, negative / name)
        shutil.copyfile(tests / 'sony_radio069_board2.c', negative / 'sony_radio069_board2.c')
        negative_exe = negative / 'old007-board2-tests'
        run('link-old007-negative', [args.cc, *cflags, '-DSONY_RADIO069_OLD16_NEGATIVE=1', str(negative / 'sony_radio069_board2.c'), str(out / 'sony_radio069_vfs.c.o'), '-o', str(negative_exe)])
        rejected = run('run-old007-negative', [str(negative_exe)])
        old16 = json.loads(rejected.stdout)
        require(old16['passed'] is True, 'Frozen 16-byte negative control did not pass')
        result['tests']['old007_negative'] = {**old16, 'exit': rejected.returncode,
                                               'source_sha256': digest(negative / 'SonyBoard2.c')}

        resources_exe = out / 'resource-tests'
        resource_test = tests / 'sony_radio069_resources.c'
        record(resource_test)
        resource_sources = [driver / n for n in ['SonyRpmh.c', 'SonyVotes.c', 'SonyCommandDb.c', 'SonyIts.c']]
        for path in resource_sources:record(path)
        run('link-resources', [args.cc, *cflags, '-I' + str(driver), str(resource_test), *map(str, resource_sources), '-o', str(resources_exe)])
        resources = run('run-resources', [str(resources_exe)])
        result['tests']['resources'] = {'passed': True, 'stdout': resources.stdout.strip()}
        # Detect source changes during a run instead of attributing a moving
        # source tree to a single qualification receipt.
        for path, sha in result['sources'].items():
            require(digest(Path(path)) == sha, 'Source changed during test: ' + path)
        result['passed'] = True
    except Exception as exc:
        result['error'] = f'{type(exc).__name__}: {exc}'
    finally:
        result_path = out / 'result.json'
        result_path.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'passed': result['passed'], 'receipt': str(result_path), 'sha256': digest(result_path), 'error': result.get('error')}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
