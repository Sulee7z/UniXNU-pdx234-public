#!/usr/bin/env python3
"""Continue a verified D27 QEMU fixture with both original readonly disks."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tomllib

DEVICE = Path(__file__).resolve().parents[2]
PROJECT = DEVICE.parents[1]
D27_LAUNCHD_SHA256 = 'c640246d38aaeb2d2372aff1e5aa0de59dec267f53c0dfc155f7837e717af68b'


def launchd_main_offset(path):
    image = path.read_bytes()
    if len(image) < 32:
        raise ValueError('Truncated original launchd')
    magic, cpu, subtype, kind, count, size = struct.unpack_from('<6I', image)
    if (magic, cpu, subtype & 0xffffff, kind) != (0xfeedfacf, 0x100000c, 2, 2):
        raise ValueError('Need original arm64e MH_EXECUTE launchd')
    end, cursor, entries = 32+size, 32, []
    if end > len(image):
        raise ValueError('Truncated launchd load commands')
    for _ in range(count):
        if cursor+8 > end:
            raise ValueError('Truncated launchd command')
        command, length = struct.unpack_from('<2I', image, cursor)
        if length < 8 or cursor+length > end:
            raise ValueError('Invalid launchd command extent')
        if command == 0x80000028 and length == 24:
            entries.append(struct.unpack_from('<Q', image, cursor+8)[0])
        cursor += length
    if cursor != end or len(entries) != 1 or not 0 < entries[0] < len(image) or entries[0] & 3:
        raise ValueError('Need one bounded original LC_MAIN entry')
    return entries[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--checkpoint', default='_native_owner_root_accepted_checkpoint')
    parser.add_argument('--timeout', type=int, default=240)
    parser.add_argument('--finish-function', action='store_true')
    parser.add_argument('--kernel', type=Path, help='A newly qualified strict kernel')
    parser.add_argument('--strict-report', type=Path)
    parser.add_argument('--data-seed', type=Path, help='Packed original D27 Data seed')
    parser.add_argument('--trust-cache', type=Path, help='Unchanged target static/system trust bundle')
    parser.add_argument('--gdb-runner', type=Path, help='Local read-only observer variant for the exact D27 arm64e ABI')
    parser.add_argument('--manifest-expectation', type=Path,
                        help='Compare the actual IOKit-published hash with a host expectation; never inject it')
    parser.add_argument('--follow-launchd-main', type=Path,
                        help='Follow original dyld to this unchanged launchd LC_MAIN, using its actual startup header')
    parser.add_argument('--hardlink-readonly-esp', action='store_true',
                        help='Save space by linking frozen ESP files; copy every payload/config this runner may change')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    out = args.out.resolve()
    esp = out/'esp'
    if args.hardlink_readonly_esp:
        runner = args.gdb_runner or Path(json.loads((args.base/'inputs.json').read_text())['command'][2])
        if 'readonly=on,file=fat:' not in runner.read_text():
            raise ValueError('Hardlinked ESP requires the pinned read-only FAT QEMU transport')
        mutable = {'kernel.macho', 'kernel.macho.adt', 'kernel.macho.trustcache',
                   'unixnu.toml', 'scratch-data.img'}
        def copy_payload(source, destination):
            if Path(source).name in mutable:
                return shutil.copy2(source, destination)
            os.link(source, destination)
            return destination
        shutil.copytree(args.base/'esp', esp, copy_function=copy_payload)
    else:
        shutil.copytree(args.base/'esp', esp)
    kernel = esp/'EFI/UniXNU/Payloads/kernel.macho'
    if args.kernel:
        strict = json.loads(args.strict_report.read_text()) if args.strict_report else {}
        digest = hashlib.sha256(args.kernel.read_bytes()).hexdigest()
        if (strict.get('missing')!={} or strict.get('stubbed')!={} or strict.get('allow_missing') is not False or
                strict.get('candidate_sha256')!=digest or not strict.get('candidate_written')):
            raise ValueError('Need a strict-complete new kernel')
        shutil.copyfile(args.kernel,kernel)
    sys.path.insert(0, str(DEVICE/'ci/XnuPrelink'))
    from kc_image import Image
    data = kernel.read_bytes()
    collection = Image(data)
    native = Image(data, collection.entries['com.apple.kernel'][1])
    names = {name: va for va, entries in native.symbols().items() for name in entries}
    spec = importlib.util.spec_from_file_location('qemu_adt', PROJECT/'sources/UniXNU-qemu-20261110/scripts/make-qemu-adt.py')
    codec = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(codec)
    profile = tomllib.loads((DEVICE/'profiles/ios-27.0.1-24A446-iphone14/profile.toml').read_text())
    adt = esp/'EFI/UniXNU/Payloads/kernel.macho.adt'
    tree, end = codec.parse(adt.read_bytes())
    if end != adt.stat().st_size:
        raise ValueError('Incomplete ADT')
    chosen = codec.child(tree, 'chosen')
    uuid = profile['root']['os_volume_uuid']
    matching = ('<dict><key>IOProviderClass</key><string>IOMedia</string><key>IOPropertyMatch</key>'
                '<dict><key>UUID</key><string>'+uuid+'</string></dict></dict>\0').encode()
    codec.put(chosen, 'root-matching', matching)
    codec.put(tree, 'model', b'iPhone14,7\0')
    codec.put(tree, 'target-type', b'D27\0')
    codec.put(chosen, 'chip-id', struct.pack('<I', 0x8110))
    codec.put(chosen, 'board-id', struct.pack('<I', 24))
    memory_map = codec.child(chosen,'memory-map')
    if args.data_seed:
        shutil.copyfile(args.data_seed, esp/'EFI/UniXNU/Payloads/scratch-data.img')
        config = esp/'EFI/UniXNU/unixnu.toml'
        text = config.read_text()
        marker = 'path="Payloads/kernel.macho"\n'
        if text.count(marker)!=1:
            raise ValueError('Unexpected QEMU entry format')
        config.write_text(text.replace(marker,marker+'initrd="Payloads/scratch-data.img"\n'))
        codec.put(memory_map,'PackedRAMDisk',bytes(16))
        codec.put(chosen,'ephemeral-storage',struct.pack('<I',1))
    trust_cache=args.trust_cache
    if trust_cache:
        shutil.copyfile(trust_cache,kernel.with_suffix('.macho.trustcache'))
        codec.put(memory_map,'TrustCache',bytes(16))
    adt.write_bytes(codec.serialize(tree))
    policies = json.loads((DEVICE/'out/d27-owner-policies-001/report.json').read_text())
    os_disk = Path(next(row['image'] for row in policies['policies'] if row['component']=='OS'))
    systemos = Path(next(row['image'] for row in policies['policies'] if row['component']=='SystemOS'))
    base = json.loads((args.base/'inputs.json').read_text())
    command = base['command']
    if args.gdb_runner:
        command[2]=str(args.gdb_runner.resolve())
    command[3] = hex(names[args.checkpoint])
    if args.follow_launchd_main:
        if args.finish_function or args.checkpoint != '_thread_setentrypoint':
            raise ValueError('LC_MAIN observation requires thread_setentrypoint without finish-function')
        if hashlib.sha256(args.follow_launchd_main.read_bytes()).hexdigest() != D27_LAUNCHD_SHA256:
            raise ValueError('Original D27 launchd bytes changed')
        plan = DEVICE/'out/d27-process-layout-001/process-plan-with-upcb.json'
        layout = json.loads(plan.read_text())['process_layout']
        command += ['--follow-entrypoint-arg', '1', '--follow-main-entry-offset',
                    hex(launchd_main_offset(args.follow_launchd_main)), '--process-layout-plan', str(plan),
                    '--allproc-address', hex(names['_allproc']), '--proc-pid-offset', str(layout['pid']),
                    '--proc-comm-offset', str(layout['comm']), '--read-frame-locals']
    command[command.index('--esp')+1] = str(esp)
    command[command.index('--kernel')+1] = str(kernel)
    command[command.index('--fixture')+1] = str(out/'observation')
    command[command.index('--timeout')+1] = str(args.timeout)
    # Addresses in this base fixture belong to the same exact kernel.
    if not args.kernel and hashlib.sha256(data).hexdigest() != base['kernel_sha256']:
        raise ValueError('Base kernel identity changed')
    # Guards and observer addresses are always derived from the selected kernel.
    for flag in ('--also-stop','--read-memory','--virtio-extra-block-image'):
        while flag in command:
            at=command.index(flag)
            del command[at:at+2]
    for name in ('_panic','_panic_with_options','_Assert','_unixnu_fileset_unmapped'):
        if names[name]!=names[args.checkpoint]:
            command += ['--also-stop',hex(names[name])]
    command += ['--virtio-extra-block-image', str(systemos)]
    if '--capture-screen' not in command:
        command.append('--capture-screen')
    command[command.index('--virtio-block-image')+1] = str(os_disk)
    if args.finish_function:
        command.append('--finish-function')
    fields = {'_rootvnode':8, '_rootdev':4, '_native_owner_root_trust_enabled':4,
              '_native_owner_root_apple_autherr':4, '_native_owner_root_decision':4,
              '_native_owner_root_accepted':4, '_native_owner_root_readonly':4,
              '_native_owner_root_mount_device':4, '_native_owner_root_selected_device':4,
              '_native_verified_block_root_uuid':37, '_native_verified_block_root_uuid_match':4,
              '_native_verified_block_wrong_uuid_refused':4, '_native_verified_block_root_media_matches':4,
              '_native_virtio_verified_devices':4, '_native_virtio_verified_blocks':8,
              '_native_virtio_integrity_failures':4, '_native_virtio_read_failures':4}
    fields.update({name:size for name,size in {
        '_native_owner_cache_status':4,'_native_owner_cache_stage':4,'_native_owner_cache_authorized':4,
        '_native_owner_cache_mount_status':4,'_native_owner_cache_native_union':4,
        '_native_owner_boot_manifest_status':4,'_native_owner_data_stage':4,'_native_owner_data_status':4,
        '_native_owner_data_readonly':4,'_native_ram_block_ready':4,'_native_ram_block_reads':8,
        '_native_ram_block_writes':8,'_native_ram_block_failures':8,
        '_native_owner_cache_carrier_accepts':8,'_native_owner_cache_carrier_rejects':8,
        '_native_owner_cache_carrier_root_device':4,'_native_owner_cache_carrier_file_device':4,
        '_dyld_flags':8,'_native_owner_cache_dyld_flags':8,
        '_cs_validate_page_bad_hash':8,'_cs_validate_page_no_hash':8,
        '_cs_native4k_page_checks':8,'_cs_native4k_ready_blobs':8,
        '_cs_native4k_full_blocks':8,'_cs_native4k_bytes':8,
        '_cs_native4k_read_ticks':8,'_cs_native4k_hash_ticks':8,
        '_native_owner_boot_manifest_hash':48,
        '_PAGE_SHIFT_CONST':4,'_page_shift':4,'_page_shift_user32':4,'_page_size':8}.items() if name in names})
    for name, size in fields.items():
        command += ['--read-memory', f'{names[name]:x}:{size:x}']
    kernel_sha=hashlib.sha256(data).hexdigest()
    inputs = dict(command=command, kernel_sha256=kernel_sha, os_disk=str(os_disk),
                  systemos_disk=str(systemos), root_uuid=uuid, device_operations=False)
    if args.follow_launchd_main:
        inputs.update(launchd=str(args.follow_launchd_main),
                      launchd_sha256=hashlib.sha256(args.follow_launchd_main.read_bytes()).hexdigest(),
                      launchd_main_offset=launchd_main_offset(args.follow_launchd_main))
    (out/'inputs.json').write_text(json.dumps(inputs, indent=2)+'\n')
    with (out/'run.log').open('w') as log:
        done = subprocess.run(command, env=dict(os.environ,TMPDIR=str(out),PYTHONDONTWRITEBYTECODE='1'),
                              stdout=log, stderr=subprocess.STDOUT)
    f = out/'observation/gdb-stop.json'
    observation = json.loads(f.read_text()) if f.exists() else {}
    values = {}
    for name, size in fields.items():
        value = observation.get('memory', {}).get(f'{names[name]:x}:{size:x}')
        if value is not None:
            raw = bytes.fromhex(value)
            values[name] = (raw.split(b'\0')[0].decode() if size == 37 else
                            raw.hex() if size == 48 else int.from_bytes(raw,'little'))
    result = dict(exit_code=done.returncode, pc=observation.get('pc'), checkpoint=args.checkpoint,
        bounded_timeout_interrupted=observation.get('bounded_timeout_interrupted'),
        function_return_stack_matched=observation.get('function_return_stack_matched'),
        function_return_target=observation.get('function_return_target'), x0=observation.get('x0'),
        reached_checkpoint=observation.get('pc')==hex(names[args.checkpoint]),
        argument_memory=observation.get('argument_memory'), values=values,
        owner_root_accepted=values.get('_native_owner_root_accepted')==1,
        userland_started=False, springboard_verified=False, device_operations=False)
    if args.follow_launchd_main:
        main_entry = observation.get('followed_main_entry', {})
        result.update(followed_main_entry=main_entry, actual_process=observation.get('actual_process'),
                      process_list=observation.get('process_list'),
                      userland_started=main_entry.get('observed') is True and
                                       main_entry.get('first_instruction_completed') is True)
        process = observation.get('actual_process', {})
        result['launchd_main_verified'] = (result['userland_started'] and
                                          process.get('pid')==1 and process.get('name')=='launchd')
    if args.manifest_expectation:
        expected = json.loads(args.manifest_expectation.read_text())
        result['manifest_hash_matches_expected'] = (
            expected.get('host_expectation_only') is True and
            expected.get('injected_into_device_tree') is False and
            values.get('_native_owner_boot_manifest_status')==0 and
            values.get('_native_owner_boot_manifest_hash')==expected['sha384'])
    (out/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))
    returned = (args.finish_function and result['function_return_stack_matched'] is True and
                result['pc']==result['function_return_target'])
    raise SystemExit(0 if done.returncode==0 and not result['bounded_timeout_interrupted'] and
                    (result['reached_checkpoint'] or returned or result['userland_started']) else 1)


if __name__ == '__main__':
    main()
