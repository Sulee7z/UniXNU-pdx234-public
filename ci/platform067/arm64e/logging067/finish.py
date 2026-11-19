#!/usr/bin/env python3
"""Validate logging targets/tests; emit source/Block/member replacement receipts only."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from audit import BASE, REPO, NATIVE_SHA, load, sha, ar_members
sys.path.insert(0, str(REPO / 'ci'))
from compile_dependencies import valid
from block_descriptor_abi import validate_record, enabled
from platform067.integration import validate as integration_validate


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build', type=Path, default=HERE / 'build-002')
    p.add_argument('--tests', type=Path, default=HERE / 'tests-003')
    p.add_argument('--out', type=Path, default=HERE / 'qualified-001')
    p.add_argument('--stream-tests', type=Path, default=HERE / 'stream-tests-001')
    a = p.parse_args()
    build = a.build.resolve()
    out = a.out.resolve()
    if not build.is_relative_to(HERE):
        raise ValueError('Only assigned output may be finalized')
    if not out.is_relative_to(HERE) or out == HERE or out.exists():
        raise ValueError('Fresh qualification output required')
    report = load(build / 'result.json')
    tests = load(a.tests / 'result.json')
    stream_tests = load(a.stream_tests / 'result.json')
    if not report['compiled'] or not tests['passed'] or tests['target_result_sha256'] != sha(build / 'result.json'):
        raise ValueError('Need matching completed build and sanitizer test receipts')
    if not stream_tests['passed'] or stream_tests['target_build_result_sha256'] != sha(build / 'result.json'):
        raise ValueError('Need matching actual-body message-stream regression')
    original = load(BASE / 'native-sony-touch-066-002/result.json')
    block_record = copy.deepcopy(original['block_descriptor_abi'])
    blocks = []
    objects = []
    sources = []
    receipts = []
    inputs = dict(report['official_patch_inputs'])
    inputs[str(HERE / 'build.py')] = sha(HERE / 'build.py')
    inputs[str(HERE / 'source.py')] = sha(HERE / 'source.py')
    inputs[str(HERE / 'qualify.py')] = sha(HERE / 'qualify.py')
    inputs[str(a.tests / 'result.json')] = sha(a.tests / 'result.json')
    inputs[str(a.stream_tests / 'result.json')] = sha(a.stream_tests / 'result.json')
    changes = {'osfmk/kern/startup.c': 'official067-log-startup', 'osfmk/kern/debug.c': 'official067-log-debug',
               'bsd/kern/kern_exit.c': 'official067-log-exit', 'bsd/kern/bsd_init.c': 'usb27-worker',
               'bsd/kern/kern_exec.c': 'audit-d27-addon-reference'}
    prior = {r['native_source_patch']: r for r in original['native_source_patches']}
    provider = None
    for row in report['jobs']:
        receipt_path = Path(row['dependency_receipt'])
        rec = load(receipt_path)
        if not valid(rec) or not enabled(rec['command']) or sha(row['new']) != row['new_sha256']:
            raise ValueError('Target compiler/dependency identity changed')
        for path in [Path(row['new']), Path(row['source']), receipt_path, Path(row['input_source']), Path(row['old_receipt'])]:
            inputs[str(path)] = sha(path)
        receipts.append(str(receipt_path))
        if row.get('archive'):
            provider = row
        else:
            objects.append({'old': row['old'], 'new': row['new']})
        if 'block_replacement_index' in row:
            index = row['block_replacement_index']
            updated = copy.deepcopy(block_record['replacements'][index])
            updated.update(source=row['source'], source_sha256=row['source_sha256'], new_object=row['new'],
                           new_sha256=row['new_sha256'], command=rec['command'],
                           dependency_receipt=str(receipt_path), dependency_sha256=sha(receipt_path))
            block_record['replacements'][index] = updated
            blocks.append({'index': index, 'prior_selected_object': row['old'], 'new_row': updated})
        relative = row.get('xnu_relative')
        if relative in changes:
            key = changes[relative]
            if key in prior:
                original_source = prior[key]['original_source']
            else:
                original_source = row['input_source']
            sources.append({'native_source_patch': key, 'source': row['source'], 'source_sha256': row['source_sha256'],
                            'original_source': original_source, 'original_source_sha256': sha(original_source)})
    validate_record(block_record)
    # Construct a local member-only proof archive. It is NOT the native link
    # output and no other member may differ, including Sony storage policy.
    archive = Path(provider['archive'])
    out.mkdir(parents=True)
    archive_out = out / 'libShengUfs.logging-proof.a'
    archive_out.write_bytes(archive.read_bytes())
    subprocess.run(['llvm-ar', 'r', str(archive_out), provider['new']], check=True, capture_output=True, timeout=30)
    old_members = ar_members(archive)
    new_members = ar_members(archive_out)
    if [n for n, _, _ in old_members] != [n for n, _, _ in new_members]:
        raise ValueError('Archive member order/set changed')
    modified = [n for (n, h, _), (_, hn, _) in zip(old_members, new_members) if h != hn]
    if modified != ['BootLog.o']:
        raise ValueError('Unexpected archive changes: ' + repr(modified))
    inputs[str(archive)] = sha(archive)
    inputs[str(archive_out)] = sha(archive_out)
    inputs[str(build / 'include/kern/boot_progress.h')] = sha(build / 'include/kern/boot_progress.h')
    member = {'archive': str(archive), 'object': provider['new']}
    integration = {'baseline_native_sha256': NATIVE_SHA, 'inputs': inputs, 'compile_receipts': receipts,
                   'object_replacements': objects, 'member_replacements': [member], 'virtual_backends_selected': False}
    integration_validate(integration)
    # Resolve every newly introduced provider import against exact066 native
    # symbol table, not against a permissive weak-default fiction.
    old_nm = subprocess.check_output(['llvm-nm', '--format=posix', provider['old']], text=True)
    new_nm = subprocess.check_output(['llvm-nm', '--format=posix', provider['new']], text=True)
    symbols = lambda s: {x.split()[0]: x.split()[1] for x in s.splitlines() if len(x.split()) >= 2}
    before, after = symbols(old_nm), symbols(new_nm)
    introduced = [n for n, typ in after.items() if typ == 'U' and n not in before]
    strict = BASE / 'strict-sony-touch-066-002'
    sys.path.insert(0, str(strict / 'XnuPrelink'))
    from kc_image import Image
    raw = (strict / 'kernel.macho').read_bytes()
    im = Image(raw)
    kernel = Image(raw, im.entries['com.apple.kernel'][1])
    names = {n: addr for addr, values in kernel.symbols().items() for n in values}
    if any(n not in names for n in introduced):
        raise ValueError('Missing newly required provider symbol: ' + repr(introduced))
    # Provider functions and symbols must correspond to all5consumer patches.
    expected = {'_boot_log_checkpoint', '_boot_log_startup_stage', '_boot_log_startup_result',
                '_boot_log_process_exit', '_boot_log_panic_record'}
    if any(after.get(n) != 'T' for n in expected):
        raise ValueError('Missing actual logging provider function')
    metadata = {'passed': True, 'baseline_native_sha256': NATIVE_SHA, 'inputs': inputs,
                'compile_receipts': receipts, 'source_overlay_rows': sources,
                'block_replacement_updates': blocks,
                'header_overlay': {'original': report['header_input'], 'original_sha256': report['header_input_sha256'],
                                   'staged': report['staged_header'], 'staged_sha256': report['staged_header_sha256'],
                                   'all_selected_direct_consumers_rebuilt': 9,
                                   'main_owned_bootprogress_archive_member_active_branch_unchanged': tests.get('active_header_branch_preprocessed_identical', False)},
                'storage_archive': str(archive), 'old_storage_archive_sha256': sha(archive),
                'new_provider_object': provider['new'], 'new_provider_sha256': provider['new_sha256'],
                'archive_proof': str(archive_out), 'archive_proof_sha256': sha(archive_out),
                'changed_members': modified, 'new_provider_imports_resolved': {n: hex(names[n]) for n in introduced},
                'exact_official_provider_subset': True, 'official_consumer_patch_count': 5,
                'd27_conflicting_hunk_precisely_rebased': True, 'platform_sleep_enabled': False,
                'corelinuxvm_selected': False, 'preserved': report['preserved'],
                'device_operations': False, 'native_link_executed': False,
                'runtime_qualified': False, 'tests': str(a.tests / 'result.json'), 'tests_sha256': sha(a.tests / 'result.json'),
                'stream_tests': str(a.stream_tests / 'result.json'), 'stream_tests_sha256': sha(a.stream_tests / 'result.json'),
                'required_main_actions': [
                    'Merge object/member replacements; remove any older addon-only kern_exec replacement targeting the same old selected object.',
                    'Update063 block_descriptor_abi.replacements indices1and8 with new rows and final native hash; runtime/header test unchanged.',
                    'Replace existing native_source_patches rows usb27-worker/audit-d27-addon-reference with supplied rows; add startup/debug/exit rows.',
                    'When official_logging_067 is selected, call logging067.qualify.validate(record), then update expected adapters using logging067.qualify.expected_adapters().',
                    'Select storage-probe=1 separately only if durable checkpoint/panic sinks are desired; no boot argument edited by this helper.',
                    'Keep current Sony NativeUfs/SourceStorage/RamBlock/window binding, data-persist0, corelinuxVM-off and no platform-sleep.']}
    spec = importlib.util.spec_from_file_location('sony_logging067_qualify', HERE / 'qualify.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.validate(metadata)
    save(out / 'integration-fragment.json', integration)
    save(out / 'logging-metadata.json', metadata)
    save(out / 'block-replacement-updates.json', {'updates': blocks, 'runtime_header_unchanged': True,
                                                  'final_native_sha256_update_required': True})
    save(out / 'finish.json', {'passed': True, 'objects': len(report['jobs']), 'source_overlays': len(sources),
                                 'member_changes': modified, 'block_indices': [x['index'] for x in blocks],
                                 'qualified_inputs': len(inputs), 'tests_sha256': sha(a.tests / 'result.json'),
                                 'stream_tests_sha256': sha(a.stream_tests / 'result.json'),
                                 'integration_fragment_sha256': sha(out / 'integration-fragment.json'),
                                 'logging_metadata_sha256': sha(out / 'logging-metadata.json'),
                                 'device_operations': False, 'native_link_executed': False})
    print(json.dumps({'passed': True, 'build': str(build), 'qualified': str(out), 'direct_objects': len(objects), 'member': 'BootLog.o',
                      'block_indices': [r['index'] for r in blocks], 'native_linked': False}))


if __name__ == '__main__':
    main()
