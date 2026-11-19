#!/usr/bin/env python3
"""Verify isolated069 crash storage deltas, exact068 findings and composable runtime request."""
from collections import Counter
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import subprocess
import sys
import importlib.util
import re

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ci/platform069/crashes'))
from audit import NATIVE, NATIVE_SHA, FRESH, PINS, sha, analyze
from runtime import selected_jobs, ICON_LABEL, ICON_ENVIRONMENT, apply_to_cache_bytes
sys.path.insert(0, str(ROOT / 'ci'))
from compile_dependencies import valid
from block_descriptor_abi import enabled
from platform069.integration import validate, expected_adapters


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n')


def members(path):
    names = subprocess.check_output(['llvm-ar', 't', str(path)], text=True).splitlines()
    if len(names) != len(set(names)):
        raise ValueError('Duplicate archive member')
    return {n: hashlib.sha256(subprocess.check_output(['llvm-ar', 'p', str(path), n])).hexdigest() for n in names}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build', type=Path, default=FRESH / 'crashes-build-001')
    p.add_argument('--policy-tests', type=Path, default=FRESH / 'crashes-policy-tests-002')
    p.add_argument('--capture-tests', type=Path, default=FRESH / 'crashes-capture-tests-001')
    p.add_argument('--out', type=Path, default=FRESH / 'crashes-qualified-001')
    a = p.parse_args()
    out = a.out.resolve()
    if out.exists() or not out.is_relative_to(FRESH):
        raise ValueError('Fresh069artifact qualification output required')
    r = json.loads((a.build / 'result.json').read_text())
    if sha(NATIVE / 'native.macho') != NATIVE_SHA or r['baseline_native_sha256'] != NATIVE_SHA:
        raise ValueError('Exact actual068 baseline changed')
    for test in [a.policy_tests / 'result.json', a.capture_tests / 'result.json']:
        if not json.loads(test.read_text())['passed']:
            raise ValueError('Required host tests failed')
    out.mkdir()
    tests_cmd = [sys.executable, '-B', str(ROOT / 'tests/sony_crashes069_audit.py'), '-v']
    test = subprocess.run(tests_cmd, capture_output=True, text=True, timeout=90)
    (out / 'unit-tests.log').write_text(test.stdout + test.stderr)
    if test.returncode:
        raise ValueError('Audit/composition unit tests failed')
    inputs = dict(r['inputs'])
    for path in [ROOT / 'ci/platform069/crashes/qualify.py', ROOT / 'ci/platform069/crashes/source.py',
                 ROOT / 'ci/platform069/crashes/runtime.py', ROOT / 'ci/platform069/crashes/audit.py',
                 Path(__file__), ROOT / 'scripts/ci/build-sony-crashes069.py',
                 a.policy_tests / 'result.json', a.capture_tests / 'result.json',
                 ROOT / 'tests/sony_crashes069_audit.py', ROOT / 'tests/sony_crashes069_policy.py',
                 ROOT / 'tests/sony_crashes069_capture.py']:
        inputs[str(path)] = sha(path)
    for row in r['builds']:
        receipt = json.loads(Path(row['dependency_receipt']).read_text())
        if not valid(receipt) or not enabled(receipt['command']) or sha(row['object']) != row['object_sha256']:
            raise ValueError('Compile receipt/object changed')
    # Compose only two reviewed archive members in a private proof archive.
    old_archive = Path(r['builds'][0]['archive'])
    proof = out / 'libShengUfs.crashes069-proof.a'
    proof.write_bytes(old_archive.read_bytes())
    subprocess.run(['llvm-ar', 'r', str(proof), *[row['object'] for row in r['builds']]], check=True, timeout=30)
    old_members, new_members = members(old_archive), members(proof)
    changed = sorted(n for n, digest in old_members.items() if new_members.get(n) != digest)
    if old_members.keys() != new_members.keys() or changed != ['BootLog.o', 'BootWatchdogPolicy.o']:
        raise ValueError('Unexpected archive change: ' + repr(changed))
    inputs[str(proof)] = sha(proof)
    source_updates = []
    for row in r['builds']:
        key = 'crashes069-persistent-lines' if row['member'] == 'BootLog.o' else 'crashes069-official-launch-policy'
        source_updates.append({'native_source_patch': key, 'source': row['source'], 'source_sha256': row['source_sha256'],
                               'original_source': row['input_source'], 'original_source_sha256': row['input_source_sha256']})
    plan = {'baseline_native_sha256': NATIVE_SHA, 'inputs': inputs, 'compile_receipts': r['compile_receipts'],
            'member_replacements': r['member_replacements'], 'object_replacements': [],
            'block_replacement_updates': [], 'source_patch_updates': source_updates,
            'source_qualifiers': [{'module': 'platform069.crashes.qualify', 'sha256': sha(ROOT / 'ci/platform069/crashes/qualify.py')}],
            'virtual_backends_selected': False, 'device_operations': False,
            'inherited_block_descriptor_objects': 66, 'all_baseline_archive_members_retained': True}
    validate(plan)
    adapters = expected_adapters(plan)
    for row in source_updates:
        actual = adapters[row['native_source_patch']](Path(row['original_source']).read_text())
        if actual != Path(row['source']).read_text():
            raise ValueError('Source qualifier does not reproduce staged object source')
    cache = FRESH / 'd27-radio-userland-original-003/files/os/System/Library/xpc/launchd.plist'
    if sha(cache) != 'ba3565e6f0682df14a46bcb50c72b1a39bd7aa4fb166064506e0057a262e39cd':
        raise ValueError('Original D27 cache identity changed')
    jobs = selected_jobs(cache)
    _, env_check = apply_to_cache_bytes(cache.read_bytes())
    policy = Path(r['builds'][1]['source']).read_text()
    # Exact original and current selected lite lists; no daemon category switch.
    def lite(text):
        section = text.split('static const char lite_jobs[]=', 1)[1].split(';', 1)[0]
        section = '\n'.join(line.split('//', 1)[0] for line in section.splitlines())
        return ''.join(re.findall(r'"([^"\n]*)"', section)).split(',')
    old_lite = lite(Path(r['builds'][1]['input_source']).read_text())
    current_lite = lite((FRESH / 'sheng/package/BootWatchdogPolicy.c').read_text())
    if old_lite != current_lite or old_lite != lite(policy):
        raise ValueError('Unreviewed change to selected lite job set')
    actual = json.loads((ROOT / 'ci/platform069/crashes/actual068.json').read_text())
    runtime = {'schema': 1, 'original_d27_cache': {'path': str(cache), 'sha256': sha(cache), 'jobs': 729},
               'jobs': jobs, 'selected_068_lite': old_lite, 'latest_sheng_lite': current_lite,
               'lite_lists_equal': True, 'lite2_disabled_icon_agent_not_selected': True,
               'runtime_request': {'launchd_job_environment': {ICON_LABEL: ICON_ENVIRONMENT},
                                   'launchd_job_overrides': {}, 'disabled_jobs': []},
               'composable_cache_function': {'module': 'platform069.crashes.runtime', 'sha256': sha(ROOT / 'ci/platform069/crashes/runtime.py'),
                                             'function': 'apply_to_cache_bytes', 'environment_merge_function': 'merge_icon_environment'},
               'original_cache_test_result': env_check, 'budget_changes': [], 'identity_changes': [],
               'seed_changes': [], 'stagedfiles': [], 'owner_must_serialize_and_detached_sign': True,
               'active_cache_provenance': {'source_mounts': 'SystemOS read-only union over root, optional owner /private/var/ngpu/xpc union over /System/Library/xpc',
                                           '068_addon_has_xpc_cache': False, 'seed_ngpu_xpc_presence': 'not-yet-read-back',
                                           'systemos_cache_presence': 'not-yet-read-back',
                                           'os_original_cache_is_available_input_not_claimed_active': True},
               'appsync': {'official_selected_source_present': True, '068_appsync_arg_enabled': False,
                           '068_addon_has_appsync_files': False, 'pin_is_ipados24A446_not_D27_executable_qualified': True,
                           'do_not_enable_unbuilt_runtime_by_argument_only': True,
                           'not_a_demonstrated_cause_of_apple_system_app_crashes': True},
               'limits': ['No changes to fskitd/pfd/bluetoothd launch policy until underlying failure branch/provider identified.',
                          'Current sheng only supplies enable-jobs/POLICY_CALL, not an automatic remedy for these three exactD27 loops.',
                          '15MiB inactivehard icon budget is observed on actualD27; activeD27 quota not independently extracted, J8201224MiB is not copied.']}
    save(out / 'runtime-request.json', runtime)
    source_delta = []
    for category, paths in [('core-architecture', [FRESH / 'UniXNU/patches/xnu-12377', FRESH / 'UniXNU/profiles/arch/arm64e']),
                            ('sheng-patches', [FRESH / 'sheng/patches/xnu-12377'])]:
        same, different = [], []
        for path in paths:
            old = Path(str(path).replace('/platform069-20261118/', '/platform067-20261118/'))
            for current in path.rglob('*'):
                if not current.is_file():continue
                before = old / current.relative_to(path)
                (same if before.is_file() and sha(current) == sha(before) else different).append(str(current))
        source_delta.append({'category': category, 'unchanged_files': same, 'changed_files': different})
    save(out / 'source-delta.json', source_delta)
    metadata = {'passed': True, 'baseline_native_sha256': NATIVE_SHA, 'pins': PINS,
                'member_objects': [{k: v for k, v in row.items() if k != 'command'} for row in r['builds']],
                'qualified_archive': str(proof), 'qualified_archive_sha256': sha(proof), 'changed_members': changed,
                'source_qualifier_module': 'platform069.crashes.qualify', 'source_qualifier_sha256': sha(ROOT / 'ci/platform069/crashes/qualify.py'),
                'adapters': sorted(adapters), 'block_rows_changed': [], 'all66_inherited_blocks_objects_retained': True,
                'actual068_evidence': str(ROOT / 'ci/platform069/crashes/actual068.json'), 'actual068_evidence_sha256': sha(ROOT / 'ci/platform069/crashes/actual068.json'),
                'runtime_request': str(out / 'runtime-request.json'), 'runtime_request_sha256': sha(out / 'runtime-request.json'),
                'tests': {'unit': str(out / 'unit-tests.log'), 'unit_passed': True,
                          'policy': str(a.policy_tests / 'result.json'), 'policy_sha256': sha(a.policy_tests / 'result.json'),
                          'capture': str(a.capture_tests / 'result.json'), 'capture_sha256': sha(a.capture_tests / 'result.json')},
                'does_not_fix_all_app_crashes': True, 'runtime_qualified': False, 'device_operations': False,
                'native_link_executed': False, 'seed_untouched': True,
                'proven_remaining_app_findings': ['Spotlight886highwater300MiB', 'WidgetRenderer1134highwater',
                                                'iconservices1042highwater+1149inactivehard15MiB', 'MapKit1061highwater',
                                                'Preferences corpse notifications only; actual exit status/PID absent from retained tail'],
                'daemon_churn': {name: actual['exit_by_name'][name] for name in ('bluetoothd', 'fskitd', 'pfd')},
                'shutdown_is_not_a_proven_kernel_panic': actual['shutdown_requests']}
    plan['result_metadata'] = {'platform069_crashes': metadata}
    save(out / 'integration-fragment.json', plan)
    save(out / 'result.json', metadata)
    print(json.dumps({'passed': True, 'out': str(out), 'members': changed, 'source_qualifiers': plan['source_qualifiers'],
                      'no_block_object_replacements': True, 'stagedfiles': []}))


if __name__ == '__main__':
    main()
