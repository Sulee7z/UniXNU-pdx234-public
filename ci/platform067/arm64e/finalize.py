#!/usr/bin/env python3
"""Join reviewed patch dispositions, exact066 code receipts and local-only fix artifacts."""
from collections import Counter
import copy
import json
from pathlib import Path
import subprocess
import sys

from audit import BASE, HERE, REPO, FRESH, NATIVE_SHA, STRICT_SHA, load, sha, path_info


def save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')


def main():
    detail_path = HERE / 'details.json'
    data = load(detail_path)
    manual = load(HERE / 'dispositions.json')
    coverage = []
    final_files = {f['file']: f for f in data['final_official_comparison']}
    for patch in data['patches']:
        category, name = patch['category'], patch['name']
        if category == 'soc-replay-input':
            disposition = {'status': 'replay-prerequisite-only',
                           'reason': manual['replay_input_dispositions'][patch['id']]}
        elif name in manual.get(category, {}):
            disposition = manual[category][name]
        else:
            # After all later official patches, unchanged final affected files prove
            # the result, even where an earlier hunk was modified by a later patch.
            different = []
            for f in patch['files']:
                for source in final_files[f['file']]['sources']:
                    for edit in source['edits']:
                        if patch['id'] in edit['patch_owners']:
                            different.append({'file': f['file'], 'source': source['source'],
                                              'official_lines': edit['official_lines']})
            if different:
                raise ValueError('Manual disposition missing for final official delta: ' + patch['id'])
            disposition = {'status': 'present-final-official-result',
                           'reason': 'All surviving official changes are present after the later declared patches; local additions, if any, are recorded per file.'}
        files = []
        for f in patch['files']:
            files.append({'file': f['file'], 'effective': [
                {'source': s['source'], 'sha256': s['sha256'], 'role': s['role'],
                 'selected_objects': s['selected_objects'], 'hunk_statuses': dict(Counter(h['status'] for h in s['hunks']))}
                for s in f.get('sources', [])]})
        coverage.append({'id': patch['id'], 'patch_sha256': patch['sha256'],
                         'declaring_series': patch['declaring_series'], **disposition, 'files': files})
    coverage_path = HERE / 'coverage.json'
    save(coverage_path, {'schema': 1, 'patches': coverage,
                         'counts': dict(Counter(p['id'].split('/')[0] for p in coverage)),
                         'scope_complete_inventory': True, 'full_parity_claim': False})

    overlay = load(HERE / 'addon-size-compile-001/result.json')
    source_native = load(BASE / 'native-sony-touch-066-002/result.json')
    updated_row = copy.deepcopy(next(r for r in source_native['block_descriptor_abi']['replacements']
                                    if r['new_object'] == overlay['selected_object']))
    # Keep the original063 old_object provenance, replace only actual selected
    # source/new_object/receipt. The runtime and its exact test source do not change.
    updated_row.update(new_object=overlay['object'], new_sha256=overlay['object_sha256'],
                       source=overlay['staged_source'], source_sha256=overlay['staged_source_sha256'],
                       command=load(Path(overlay['dependency_receipt']))['command'],
                       dependency_receipt=overlay['dependency_receipt'], dependency_sha256=overlay['dependency_receipt_sha256'])
    from source import adapt_source
    source_row = copy.deepcopy(next(r for r in source_native['native_source_patches']
                                    if r['native_source_patch'] == 'audit-d27-addon-reference'))
    if adapt_source(Path(source_row['original_source']).read_text()) != Path(overlay['staged_source']).read_text():
        raise ValueError('Exact composed qualifier differs from the compiled staged source')
    source_row.update(source=overlay['staged_source'], source_sha256=overlay['staged_source_sha256'])
    block_update = {'replace_selected_object': overlay['selected_object'],
                    'replacement_index': next(i for i, r in enumerate(source_native['block_descriptor_abi']['replacements'])
                                              if r['new_object'] == overlay['selected_object']),
                    'replacement_row': updated_row,
                    'native_source_patch_row': source_row,
                    'exact_composed_source_adapter': path_info(HERE / 'source.py'),
                    'runtime_header_and_test_unchanged': True,
                    'new_native_sha256_must_be_updated_after_link': True,
                    'new_objects_must_match_actual_link_filelist': True,
                    'note': 'native_source_patches audit-d27-addon-reference provenance must retain the earlier G14 change plus this exact official size hunk; do not pretend the staged source still equals the old adapter output.'}
    save(HERE / 'block-replacement-update.json', block_update)
    input_paths = [HERE / 'addon-size-compile-001/result.json', HERE / 'addon-size-compile-001/official-addon-size.patch',
                   Path(overlay['object']), Path(overlay['staged_source']), Path(overlay['dependency_receipt']),
                   Path(overlay['official_patch']), HERE / 'block-replacement-update.json']
    input_paths.append(HERE / 'source.py')
    fragment = {'baseline_native_sha256': NATIVE_SHA, 'inputs': {str(p): sha(p) for p in input_paths},
                'object_replacements': [{'old': overlay['selected_object'], 'new': overlay['object']}],
                'compile_receipts': [overlay['dependency_receipt']], 'virtual_backends_selected': False,
                'metadata_obligations': 'block-replacement-update.json and composed native_source_patches adapter qualification',
                'linked': False, 'device_operations': False}
    sys.path.insert(0, str(REPO / 'ci'))
    from platform067.integration import validate
    validate(fragment)
    from block_descriptor_abi import validate_record
    qualified = copy.deepcopy(source_native['block_descriptor_abi'])
    qualified['replacements'][block_update['replacement_index']] = updated_row
    validate_record(qualified)
    save(HERE / 'integration-fragment.json', fragment)

    tests_command = [sys.executable, '-B', str(HERE / 'test_audit.py'), '-v']
    unit_tests = subprocess.run(tests_command, capture_output=True, text=True, timeout=30)
    unit_log = HERE / 'unit-tests.log'
    unit_log.write_text(unit_tests.stdout + unit_tests.stderr)
    if unit_tests.returncode:
        raise ValueError('Audit parser/overlay regression failed; see ' + str(unit_log))
    tests_receipt = {'passed': True, 'unit_test_cases': 12, 'command': tests_command,
                     'log': path_info(unit_log), 'updated_66_block_replacements_valid': True,
                     'exact_composed_source_adapter_valid': True, 'integration_fragment_valid': True,
                     'target_compile': path_info(HERE / 'addon-size-compile-001/result.json'),
                     'actual_body_asan_ubsan': path_info(HERE / 'addon-writer-tests-003/result.json')}
    save(HERE / 'tests.json', tests_receipt)

    evidence = load(REPO / 'evidence/d27-platform067-arm64e.json')
    capture = Path('/mnt/g/UniXNU-Port/evidence/Xperia-XQ-DQ72/20261118-platform-post066-readonly-001')
    raw_log = capture / 'ios-log-window.bin'
    if sha(raw_log) != '410af3f05a7e1669ec48672f7a7e597c44e08ad7c0b0932140acf482932d2ccf':
        raise ValueError('066 persistent log identity changed')
    final_code = HERE / 'final-instructions-002/result.json'
    supplemental = HERE / 'supplemental-code-003/result.json'
    writer_tests = HERE / 'addon-writer-tests-003/result.json'
    if not all(load(p)['passed'] for p in (final_code, supplemental, writer_tests)):
        raise ValueError('Required exact-code/writer tests failed')
    evidence.update(
        complete_patch_inventory={'architecture': 69, 'os': 4, 'sheng_board': 25, 'historical_soc_replay_inputs': 2,
                                  'files': 129, 'files_equal_final_official_result': 112,
                                  'comparison_is_pristine_git_blob_replay_not_patch_name_presence': True},
        coverage=path_info(coverage_path), dispositions=path_info(HERE / 'dispositions.json'),
        archives={'count': len(data['archives']['archives']), 'members': data['archives']['members'],
                  'members_bound_to_exact_selected_object_bytes': data['archives']['hash_bound_members'],
                  'unique_dependency_paths': data['archives']['unique_dependencies'],
                  'drift': data['archives']['dependency_mismatches']},
        exact_code_verification=[path_info(final_code), path_info(supplemental)],
        tests=path_info(HERE / 'tests.json'),
        helpers={p.name: sha(p) for p in sorted(HERE.glob('*.py'))},
        raw_log=path_info(raw_log), phone_boot066_hash=(capture / 'boot066-hash.txt').read_text().strip(),
        official_generic_functional_missing_hunks=1,
        isolated_official_fix={'receipt': path_info(HERE / 'addon-size-compile-001/result.json'),
                               'source': path_info(Path(overlay['staged_source'])), 'object': path_info(Path(overlay['object'])),
                               'tests': path_info(writer_tests), 'test_cases': 12, 'sanitizers': ['address', 'undefined'],
                               'old_smaller_overwrite_tail_reproduced': True, 'baseline_shared_sources_unchanged': True,
                               'integrated': False, 'new_image_created': False,
                               'integration_fragment': path_info(HERE / 'integration-fragment.json'),
                               'block_row_update': path_info(HERE / 'block-replacement-update.json')},
        missing_current_sheng_patches=[p['id'] for p in coverage if p['status'].startswith('missing')],
        application_findings=[
            {'type': 'data-enospc', 'proven': True,
             'evidence': 'msgbuf.txt has91 ENOSPC/no-space matching lines across SpringBoard/iconservices/logd/assetsd/chronod; errno28 also in periodic slots.',
             'interpretation': 'Real APFS Data transaction/allocation failure, not PAC. Host2GiB seed preparation is owned by main; no storage/device write in this audit.'},
            {'type': 'per-process-memory-limits', 'proven': True,
             'evidence': 'slots.txt6 fatal limits+6 specific per-process kills; MapKit14MB, iconservices15MB;2 highwater kills including WidgetRenderer588 at596.159s.',
             'interpretation': 'Specific process budgets, not proof all4864MiB exhausted; many pages remain at kills.165 long-idle reaps must not be called165 crashes.'},
            {'type': 'webkit-mach-guard', 'proven': True,
             'evidence': 'slots569/570 WebKitGPU731/Networking732 type1 flavor0 code2000000000000000 subcode0.',
             'interpretation': 'Actual Mach-port guard report. Preceding sandbox persona494 denial is a separate observation; exact guard origin/caller unproved. Do not bypass guards.'},
            {'type': 'widget-swift-site', 'proven_this_run': False,
             'evidence': 'Older pinned057/058 fault maps WidgetKit ControlAction.swift58 CHSIntentReference fatal text;066 retained excerpts do not contain its SIGTRAP PC/message.',
             'interpretation': 'Do not transfer old widget Swift site to every066 app. Obtain full exact-run exception/exit reports.'},
            {'type': 'pac-causality', 'proven': False,
             'evidence': 'No PAC_EXCEPTION literal in retained066 msgbuf/slots; exact strict key pairs/EL0 transitions/type discriminators/86Block slots pass.',
             'interpretation': 'Absence in rolling/truncated logs is not proof every authentication succeeded. No current evidence justifies disabling PAC/AMFI/trust/error paths.'}],
        source_mutated=False, shared_source_mutated=False, compile_or_link_executed=True,
        target_compile_only=True, link_executed=False, device_operations=False,
        audit_inventory_complete=True, parity_complete=False,
        main_parallel_boundary={'touch_cleanup_native_sha256': '740fa1a30288f08150081c15f520246481f8f81f280bc5ec6ef24c7885738666',
                                'touch_cleanup_strict_sha256': '1a806c75b9ccf416e6c80728375e0baafd826f7749eca4154bb6b54d5d200944',
                                'audit_baseline_is_still_exact066': True, 'main_current_sonytouch_source_drift_expected': True},
        limits=['One old lastkernelconstructor.last.o tail has no direct compile receipt;25 legacy assembly records have no full dependency schema. Actual executable PAC bodies separately inspected.',
                'All639 archive members hash-match available objects; late-section-transformed members are hash-bound but their original compile receipt predates the transformation.',
                'Current SonyTouch.cpp differs because main is cleaning it in parallel; no repair/revert attempted. Original066 object/archive hashes remain intact.',
                'Two conservative replay conflicts retained: historicalSoC MAX_CPUS context already superseded, and currentSheng startup-failure hunk expects an absent target-specific branch. No fuzzy source application was performed.',
                'Stock verifier with --touch was refused by parallel SonyTouch source change. Architecture-only stock verifier and supplemental final code verifier passed against exact066.',
                'No new067 linked artifact/image is claimed by this report. Global porting checker historical missing out/qemu-common-002/summary.json remains.'])
    save(REPO / 'evidence/d27-platform067-arm64e.json', evidence)
    print(json.dumps({'coverage': len(coverage), 'statuses': dict(Counter(r['status'] for r in coverage)),
                      'evidence': str(REPO / 'evidence/d27-platform067-arm64e.json'),
                      'missing_functional_hunks': 1, 'overlay_compiled_not_linked': True}))


if __name__ == '__main__':
    main()
