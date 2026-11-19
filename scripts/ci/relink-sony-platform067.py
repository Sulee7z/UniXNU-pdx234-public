#!/usr/bin/env python3
"""Integrate isolated, hash-bound peripheral/performance work over actual066.

A reviewed JSON plan selects archive member replacements, archive replacements,
new archives and direct objects. No source tree or earlier build is rewritten.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
sys.path.insert(0, str(ROOT / 'ci'))
from platform067.integration import BASE_SHA, sha, validate
from compile_dependencies import run_recorded
from native_source_overlays import validate_overlays


def strip_deps(command):
    result, index = [], 0
    while index < len(command):
        if command[index] in ('-MF', '-MT', '-MQ'):
            index += 2
        elif command[index] in ('-MD', '-MMD'):
            index += 1
        else:
            result.append(command[index]); index += 1
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--touch', type=Path, required=True)
    parser.add_argument('--screen', type=Path, required=True)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    previous = BASE / 'native-sony-touch-066-002'
    before = json.loads((previous / 'result.json').read_text())
    if sha(previous / 'native.macho') != BASE_SHA or before['native_sha256'] != BASE_SHA:
        raise ValueError('Exact physical066 baseline required')
    validate_overlays(before, sha)
    plan = json.loads(args.plan.read_text())
    if plan['baseline_native_sha256'] != BASE_SHA:
        raise ValueError('Wrong integration baseline')
    for path, digest in plan['inputs'].items():
        if sha(path) != digest:
            raise ValueError('Reviewed input changed: ' + path)
    touch = json.loads((args.touch / 'result.json').read_text())
    if not touch.get('temporary_probes_removed') or touch['virtual_backend_included']:
        raise ValueError('Qualified cleaned physical touch archive required')
    for section in ('sources', 'objects'):
        for path, digest in touch[section].items():
            if sha(path) != digest:
                raise ValueError('Touch build identity differs: ' + path)
    if sha(touch['archive']) != touch['sha256']:
        raise ValueError('Touch archive differs')
    screen = json.loads((args.screen / 'result.json').read_text())
    if not screen['passed'] or not screen['guarded_handoff_unchanged'] or not screen['thirty_ms_worker_removed']:
        raise ValueError('Reviewed display ownership and worker cleanup required')
    if sha(screen['source']) != screen['source_sha256'] or sha(args.screen / 'BootProgress.o') != screen['object_sha256']:
        raise ValueError('Screen cleanup object differs')
    args.out.mkdir(parents=True, exist_ok=False)
    out = args.out.resolve()
    command = json.loads((previous / 'native-link.command.json').read_text())
    result = copy.deepcopy(before)
    changes = []
    archive_changes = {}

    def replace_archive(old, new):
        token = '-Wl,-force_load,' + old
        if command.count(token) != 1:
            raise ValueError('Unique physical archive required: ' + old)
        command[command.index(token)] = '-Wl,-force_load,' + str(new)
        archive_changes[old] = str(new)

    # Preserve all other066 members, including any earlier ABI fixes.
    display = out / 'libPhysicalDisplayPlatform067.a'
    display_base = Path(plan.get('display_base_archive', before['display_source']['archive']))
    if str(display_base) not in plan['inputs'] and str(display_base) != before['display_source']['archive']:
        raise ValueError('Replacement display base lacks a reviewed hash')
    display.write_bytes(display_base.read_bytes())
    startup = previous / 'LegacyDisplayProbe.cpp'
    text = startup.read_text()
    anchor = '    native_sony_touch_start();\n'
    if text.count(anchor) != 1:
        raise ValueError('Qualified066 startup anchor differs')
    calls = plan.get('startup_calls', [])
    if len(calls) != len(set(calls)) or any(not name.replace('_', '').isalnum() for name in calls):
        raise ValueError('Invalid startup entry points')
    if calls:
        text = ''.join('extern "C" void ' + name + '(void);\n' for name in calls) + text.replace(
            anchor, anchor + ''.join('    ' + name + '();\n' for name in calls))
    staged = out / 'LegacyDisplayProbe.cpp'
    staged.write_text(text)
    dependencies = json.loads((previous / 'LegacyDisplayProbe.o.dependencies.json').read_text())
    compile_command = strip_deps(dependencies['command'])
    compile_command[compile_command.index(str(startup))] = str(staged)
    startup_object = out / 'LegacyDisplayProbe.o'
    compile_command[compile_command.index('-o') + 1] = str(startup_object)
    from block_descriptor_abi import FLAGS, enabled
    if not enabled(compile_command):
        compile_command += FLAGS
    directory = Path(next(path for path in dependencies['dependencies'] if Path(path).name == 'meta_features.h')).parent
    with (out / 'startup.log').open('x') as log:
        done = run_recorded(compile_command, cwd=directory, stdout=log, stderr=subprocess.STDOUT, timeout=120)
    if done.returncode:
        raise RuntimeError((out / 'startup.log').read_text()[-10000:])
    subprocess.run(['llvm-ar', 'r', str(display), str(startup_object)], check=True)
    replace_archive(before['display_source']['archive'], display)
    result['display_source'].update(archive=str(display), sha256=sha(display),
        staged_probe_sha256=sha(staged), sony_touch_start_connected=True, platform067_calls=calls)
    boot = out / 'libBootProgressPlatform067.a'
    boot.write_bytes(Path(before['boot_screen']['archive']).read_bytes())
    subprocess.run(['llvm-ar', 'r', str(boot), str(args.screen / 'BootProgress.o')], check=True)
    replace_archive(before['boot_screen']['archive'], boot)
    result['boot_screen'].update(archive=str(boot), sha256=sha(boot), sony_touch_rows_enabled=False,
                                touch_test_painter_removed=True, thirty_ms_touch_worker_removed=True)
    row = next(row for row in result['boot_screen']['sources'] if Path(row['source']).name == 'BootProgress.c')
    row.update(source=screen['source'], sha256=screen['source_sha256'])
    replace_archive(before['sony_touch']['archive'], touch['archive'])
    result['sony_touch'] = touch
    # Each member replacement is named, not a whole unchecked old archive copy.
    for item in plan.get('member_replacements', []):
        old = item['archive']
        if old not in archive_changes:
            target = out / Path(old).name
            if target.exists():
                raise ValueError('Colliding archive basename: ' + str(target))
            target.write_bytes(Path(old).read_bytes())
            replace_archive(old, target)
        target = Path(archive_changes[old])
        members = subprocess.check_output(['llvm-ar', 't', str(target)], text=True).splitlines()
        obj = Path(item['object'])
        if members.count(obj.name) != 1:
            raise ValueError('Member must replace exactly one existing member: ' + obj.name)
        subprocess.run(['llvm-ar', 'r', str(target), str(obj)], check=True)
        changes.append(item)
    for item in plan.get('archive_replacements', []):
        if item['old'] in archive_changes:
            raise ValueError('Overlapping whole/member replacement: ' + item['old'])
        replace_archive(item['old'], item['new'])
        changes.append(item)
    for archive in plan.get('added_archives', []):
        if any(value.endswith(',' + archive) for value in command):
            raise ValueError('Duplicate added archive: ' + archive)
        command.append('-Wl,-force_load,' + archive)
    files = Path(command[command.index('-filelist') + 1]).read_text().splitlines()
    for item in plan.get('object_replacements', []):
        if files.count(item['old']) != 1:
            raise ValueError('Unique direct object required: ' + item['old'])
        files[files.index(item['old'])] = item['new']
        changes.append(item)
    for update in plan.get('block_replacement_updates', []):
        if sha(update['path']) != update['sha256']:
            raise ValueError('Reviewed Blocks metadata update differs')
        replacement = json.loads(Path(update['path']).read_text())
        index = replacement['replacement_index']
        old = result['block_descriptor_abi']['replacements'][index]
        new = replacement['replacement_row']
        if (old['new_object'] != replacement['replace_selected_object'] or
                new['old_object'] != old['old_object'] or new['old_sha256'] != old['old_sha256'] or
                files.count(new['new_object']) != 1 or
                not any(item['old'] == old['new_object'] and item['new'] == new['new_object']
                        for item in plan.get('object_replacements', []))):
            raise ValueError('Blocks update does not describe the actual selected object transition')
        result['block_descriptor_abi']['replacements'][index] = new
    for update in plan.get('source_patch_updates', []):
        rows = [row for row in result['native_source_patches'] if row['native_source_patch'] == update['native_source_patch']]
        if len(rows) > 1 or sha(update['source']) != update['source_sha256']:
            raise ValueError('Unique hash-bound native source overlay update required')
        if rows:
            rows[0].update(source=update['source'], source_sha256=update['source_sha256'])
        else:
            if (not update.get('original_source') or
                    sha(update['original_source']) != update['original_source_sha256']):
                raise ValueError('New source overlay requires exact original source identity')
            result['native_source_patches'].append(dict(update))
    filelist = out / 'link.filelist'
    filelist.write_text('\n'.join(files) + '\n')
    command[command.index('-filelist') + 1] = str(filelist)
    command[command.index('-o') + 1] = str(out / 'native.macho')
    # The inherited sectcreate reserve otherwise follows text at four-byte
    # alignment. A renderer entry needs16-byte alignment even when tail padding
    # is too small, so qualify the dedicated fallback's alignment at link time.
    alignment = '-Wl,-sectalign,__TEXT_EXEC,__pdxpanic,0x10'
    if any('__pdxpanic' in value for value in command) and alignment not in command:
        command.append(alignment)
    for key in ('display_source', 'boot_screen', 'gpu_source'):
        old = before[key]['archive']
        if old in archive_changes:
            result[key].update(archive=archive_changes[old], sha256=sha(archive_changes[old]))
    for old,new in archive_changes.items():
        if Path(old).name in result.get('archive_sha256', {}):
            result['archive_sha256'][Path(old).name] = sha(new)
    for key, value in plan.get('result_metadata', {}).items():
        if key in ('native', 'native_sha256', 'block_descriptor_abi', 'sony_touch', 'platform067'):
            raise ValueError('Protected metadata override: ' + key)
        result[key] = value
    receipt_inputs = dict(plan['inputs'])
    for path in (args.plan, args.touch / 'result.json', args.screen / 'result.json',
                 staged, startup_object, display, boot, filelist):
        receipt_inputs[str(path)] = sha(path)
    for value in command:
        if value.startswith('-Wl,-force_load,'):
            path = value.split('-Wl,-force_load,', 1)[1]
            receipt_inputs[path] = sha(path)
    # No stale063 receipt may claim an old, now unlinked Blocks producer.
    for row in result['block_descriptor_abi']['replacements']:
        if files.count(row['new_object']) != 1:
            raise ValueError('Signed Blocks replacement is not the actual linked input: ' + row['new_object'])
    integration = dict(baseline_native_sha256=BASE_SHA, inputs=receipt_inputs,
        compile_receipts=[str(out / 'LegacyDisplayProbe.o.dependencies.json'),
                          str(args.screen / 'BootProgress.o.dependencies.json'), *plan.get('compile_receipts', [])],
        virtual_backends_selected=False, changes=changes, startup_calls=calls,
        inherited_block_descriptor_objects=66, device_operations=False)
    validate(integration)
    result['platform067'] = integration
    result['physical_066_derived'] = True
    validate_overlays(result, sha)
    env = dict(os.environ, CROSS_CLANG='/root/unixnu-build/pdx234-pac-toolchain/llvm/bin/clang-24',
               DARWIN_TRIPLE='arm64e-apple-ios27.0', CROSS_EXTRA_FLAGS=result['pac_flag'], TMPDIR=str(out))
    env['PATH'] = str(Path(command[0]).parent) + ':' + env['PATH']
    with (out / 'link.log').open('x') as log:
        done = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=300)
    if done.returncode:
        raise RuntimeError((out / 'link.log').read_text()[-12000:])
    result.update(native=str(out / 'native.macho'), native_sha256=sha(out / 'native.macho'),
                  runtime_qualified=False, device_operations=False)
    if plan.get('block_replacement_updates'):
        result['block_descriptor_abi'].update(native_sha256=result['native_sha256'],
            source_text_changed=True, source_updates_067=plan['block_replacement_updates'])
    (out / 'native-link.command.json').write_text(json.dumps(command, indent=2) + '\n')
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(native=result['native'], sha256=result['native_sha256'], changes=changes), indent=2))


if __name__ == '__main__':
    main()
