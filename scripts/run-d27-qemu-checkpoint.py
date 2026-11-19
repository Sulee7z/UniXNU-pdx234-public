#!/usr/bin/env python3
"""Run the strict D27 kernel through the official read-only QEMU/GDB fixture."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

DEVICE = Path(__file__).resolve().parents[1]
PROJECT = DEVICE.parents[1]
EXPECTED = '098469d880049ad9f1811c3e893874fa56cba72957200fcb4dad756627af0efe'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--checkpoint', default='_IOFindBSDRoot', help='Exact defined native symbol')
    parser.add_argument('--kernel', type=Path, help='New strict D27 candidate')
    parser.add_argument('--strict-report', type=Path, help='Required report for a new candidate')
    parser.add_argument('--diagnostic-report', type=Path, help='Traced patches to the strict candidate')
    parser.add_argument('--virtio-read', action='store_true', help='Observe the actual OS disk first-sector read')
    parser.add_argument('--owner-policy-report', type=Path, help='Verified source-block archive report with sidecar')
    parser.add_argument('--boot-arg', action='append', default=[], help='Override one argument by name')
    parser.add_argument('--capture-screen', action='store_true')
    parser.add_argument('--finish-function', action='store_true')
    parser.add_argument('--timeout', type=int, default=150)
    parser.add_argument('--owned-memory-size', type=lambda value: int(value, 0),
                        help='QEMU DarwinBoot owned RAM window for root policies and userland')
    parser.add_argument('--apfs-metadata', action='store_true',
                        help='Use the existing offline APFS load probe and read actual D27 metaclasses')
    args = parser.parse_args()
    if bool(args.kernel) != bool(args.strict_report):
        parser.error('--kernel and --strict-report must be supplied together')
    if args.virtio_read and (not args.kernel or args.checkpoint != '_native_virtio_read_checkpoint' or
                             args.apfs_metadata or args.finish_function):
        parser.error('VirtIO read requires a new strict kernel and its exact read checkpoint')
    if args.owner_policy_report and not args.virtio_read:
        parser.error('Owner policy handoff requires the actual VirtIO read test')
    args.out.mkdir(parents=True, exist_ok=False)
    esp = args.out / 'esp'
    previous = Path('/root/unixnu-build/pdx234-strict5-native-001/qemu-004/esp')
    for relative in ('EFI/BOOT/BOOTAA64.EFI', 'EFI/UniXNU/Drivers/DarwinBoot.efi',
                     'EFI/UniXNU/unixnu.toml', 'EFI/UniXNU/Payloads/kernel.macho.adt',
                     'EFI/UniXNU/Payloads/kernel.macho'):
        target = esp / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        source = args.kernel if args.kernel and relative.endswith('/kernel.macho') else previous / relative
        shutil.copyfile(source, target)
    kernel = esp / 'EFI/UniXNU/Payloads/kernel.macho'
    data = kernel.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    expected = EXPECTED
    if args.strict_report:
        strict = json.loads(args.strict_report.read_text())
        if (strict.get('missing') != {} or strict.get('stubbed') != {} or strict.get('allow_missing') is not False or
                strict.get('candidate_written') is not True or
                strict.get('inputs', {}).get('kernelcache_sha256') !=
                'c28f4fc9b83cde00087e81f890c82d566b9e98b5ac228dfecd83afdf34070445'):
            raise ValueError('New candidate has not achieved strict completeness')
        expected = strict['candidate_sha256']
        if args.diagnostic_report:
            derivative = json.loads(args.diagnostic_report.read_text())
            if derivative['source_kernel_sha256'] != expected:
                raise ValueError('Diagnostic source identity differs')
            expected = derivative['patched_kernel_sha256']
    if digest != expected:
        raise ValueError('Historical ESP no longer contains the strict D27 input')
    sys.path.insert(0, str(DEVICE / 'ci/XnuPrelink'))
    from kc_image import Image
    collection = Image(data)
    native = Image(data, collection.entries['com.apple.kernel'][1])
    names = {}
    for address, symbols in native.symbols().items():
        for name in symbols:
            if name in names and names[name] != address and name in (
                    args.checkpoint, '_panic', '_Assert', '_unixnu_fileset_unmapped'):
                raise ValueError(f'Ambiguous checkpoint symbol: {name}')
            names[name] = address
    if args.apfs_metadata:
        if args.checkpoint != '_native_apfs_probe_checkpoint' or args.finish_function:
            parser.error('APFS metadata requires its exact checkpoint, without --finish-function')
        config = esp / 'EFI/UniXNU/unixnu.toml'
        text = config.read_text()
        marker = 'args="'
        if text.count(marker) != 1 or 'offline-apfs-load=' in text:
            raise ValueError('Historical ESP boot argument declaration changed')
        config.write_text(text.replace(marker, marker + 'offline-apfs-load=1 '))
    disk = None
    expected_first_sector = None
    if args.virtio_read:
        owner = json.loads((DEVICE / 'out/d27-owner-policies-001/report.json').read_text())
        policy = next(p for p in owner['policies'] if p['component'] == 'OS')
        disk = Path(policy['image'])
        if not policy['verification']['real_c_signature_and_block_verification']:
            raise ValueError('Actual target disk has not passed host verification')
        with disk.open('rb') as stream:
            expected_first_sector = hashlib.sha256(stream.read(512)).hexdigest()
        fdt = args.out / 'qemu-virt.dtb'
        subprocess.run(['qemu-system-aarch64', '-M',
                        f'virt,virtualization=off,secure=off,gic-version=3,dumpdtb={fdt}',
                        '-cpu', 'cortex-a710', '-m', '4096', '-smp', '1', '-display', 'none', '-nodefaults'],
                       check=True, capture_output=True)
        make_dt = ['python3', '-B', str(PROJECT / 'sources/UniXNU-main-20261109/scripts/qemu-entry/make-dt.py'),
                        '--armvirt', '--armcpu', '--nvram-proxy', '--qemu-vmm-present',
                        '--crypto-hash-method', 'sha2-384', '--osenvironment', 'main', '--amfi-platform-only',
                        '--dram-size', '0x100000000', '--virtio-mmio-fdt', str(fdt),
                        '--output', str(esp / 'EFI/UniXNU/Payloads/kernel.macho.adt')]
        if args.owned_memory_size is not None:
            make_dt += ['--owned-memory-size', str(args.owned_memory_size)]
        subprocess.run(make_dt, check=True)
        # Use the community QEMU tree codec to retire the official UFS test nodes.
        spec = importlib.util.spec_from_file_location('qemu_adt_codec',
            PROJECT / 'sources/UniXNU-qemu-20261110/scripts/make-qemu-adt.py')
        codec = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(codec)
        adt = esp / 'EFI/UniXNU/Payloads/kernel.macho.adt'
        tree, end = codec.parse(adt.read_bytes())
        if end != adt.stat().st_size:
            raise ValueError('Incomplete official ADT parse')
        arm_io = codec.child(tree, 'arm-io')
        codec.put(codec.child(tree, 'chosen'), 'kernel-ctrr-to-be-enabled', bytes(4))
        arm_io[2] = [node for node in arm_io[2] if node[0] not in ('ufshc', 'ufsphy')]
        if args.owner_policy_report:
            archive_record = json.loads(args.owner_policy_report.read_text())
            policy = archive_record['owner_policy_inputs']
            bundle = args.owner_policy_report.parent / 'root-policies.bin'
            if hashlib.sha256(bundle.read_bytes()).hexdigest() != policy['bundle_sha256']:
                raise ValueError('Owner policy sidecar identity differs')
            shutil.copyfile(bundle, kernel.with_suffix(kernel.suffix + '.vroot'))
            codec.put(codec.child(codec.child(tree, 'chosen'), 'memory-map'), 'RootPolicies', bytes(16))
        adt.write_bytes(codec.serialize(tree))
        config = esp / 'EFI/UniXNU/unixnu.toml'
        text = config.read_text()
        if text.count('args="') != 1 or 'native-qemu-storage=' in text:
            raise ValueError('Unexpected storage boot arguments')
        config.write_text(text.replace('args="', 'args="native-qemu-storage=1 '))
    if args.boot_arg:
        import tomllib
        config = esp / 'EFI/UniXNU/unixnu.toml'
        text = config.read_text()
        old_args = tomllib.loads(text)['entry'][0]['args']
        selected = old_args.split()
        for argument in args.boot_arg:
            if not argument or any(c.isspace() or c in '"\\' for c in argument):
                raise ValueError('Boot overrides require a single plain argument')
            key = argument.split('=', 1)[0].lstrip('-')
            selected = [a for a in selected if a.split('=', 1)[0].lstrip('-') != key]
            selected.append(argument)
        text = text.replace('args="' + old_args + '"', 'args="' + ' '.join(selected) + '"')
        config.write_text(text)
    if args.diagnostic_report:
        import tomllib
        boot_args = tomllib.loads((esp / 'EFI/UniXNU/unixnu.toml').read_text())['entry'][0]['args']
        seal_env = dict(os.environ, UNIXNU_XNU_ARCH='arm64e', UNIXNU_IOS_VERSION='27.0')
        subprocess.run(['python3', '-B', str(PROJECT / 'references/pdx234-mainline-20261108/scripts/seal-source-crypto-kernel.py'),
                        str(kernel), '--kernel-args', boot_args], env=seal_env, check=True)
        digest = hashlib.sha256(kernel.read_bytes()).hexdigest()
    command = ['python3', '-B', str(PROJECT / 'sources/UniXNU-main-20261109/scripts/qemu-entry/gdb-stop.py'),
               hex(names[args.checkpoint]), '--esp', str(esp), '--kernel', str(kernel),
               '--fixture', str(args.out / 'observation'), '--gic-version', '3',
               '--qemu-memory-mib', '4096', '--system-registers', '--qemu-ramfb',
               '--firmware', '/usr/share/AAVMF/AAVMF_CODE.fd', '--timeout', str(args.timeout)]
    for name in ('_panic', '_Assert', '_unixnu_fileset_unmapped'):
        if args.diagnostic_report and name in ('_panic', '_Assert'):
            continue  # Follow the real linked diagnostic renderer to its park.
        if name in names:
            command += ['--also-stop', hex(names[name])]
    if args.finish_function:
        command.append('--finish-function')
    if args.capture_screen:
        command.append('--capture-screen')
    if args.apfs_metadata:
        for address, length in ((0xfffffff00af07060, 0x50),
                                (names['__ZN9IOService10gMetaClassE'], 0x50),
                                (names['_native_apfs_load_status'], 4),
                                (names['_native_apfs_registered'], 4)):
            command += ['--read-memory', f'{address:x}:{length:x}']
    storage_fields = {'_native_qemu_storage_state': 4, '_native_virtio_ready': 4,
                      '_native_virtio_read_requests': 4, '_native_virtio_read_failures': 4,
                      '_native_virtio_sectors': 8, '_native_virtio_mmio_physical': 8,
                      '_native_virtio_first_sector_sha256': 32}
    if args.owner_policy_report:
        storage_fields.update(_native_virtio_manifest_ready=4, _native_virtio_verified_devices=4,
                              _native_virtio_verified_blocks=8, _native_virtio_integrity_failures=4,
                              _verified_root_policy_count=8)
    if disk:
        command += ['--virtio-block-image', str(disk)]
        for name, length in storage_fields.items():
            command += ['--read-memory', f'{names[name]:x}:{length:x}']
    record = dict(kernel_sha256=digest, checkpoint=args.checkpoint,
                  checkpoint_address=hex(names[args.checkpoint]), command=command,
                  official_reference='https://unixnu.com/zh/reference/qemu',
                  target='iPhone14,7 / D27AP / 24A446',
                  platform='QEMU virt; no Sony peripheral addresses or handset operations',
                  input_files={str(p.relative_to(esp)):hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in esp.rglob('*') if p.is_file()})
    (args.out / 'inputs.json').write_text(json.dumps(record, indent=2)+'\n')
    env = dict(os.environ, TMPDIR=str(args.out.resolve()), PYTHONDONTWRITEBYTECODE='1')
    with (args.out / 'run.log').open('w') as log:
        result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
    report_path = args.out / 'observation/gdb-stop.json'
    observation = json.loads(report_path.read_text()) if report_path.is_file() else {}
    reached = observation.get('pc') == hex(names[args.checkpoint])
    apfs_status = None
    if reached and args.apfs_metadata:
        key = f'{names["_native_apfs_load_status"]:x}:4'
        value = observation.get('memory', {}).get(key)
        if value:
            apfs_status = int.from_bytes(bytes.fromhex(value), 'little', signed=True)
    storage = {}
    if disk and reached:
        for name, length in storage_fields.items():
            value = bytes.fromhex(observation['memory'][f'{names[name]:x}:{length:x}'])
            if len(value) != length:
                raise ValueError('Incomplete actual VirtIO observation')
            storage[name] = value.hex() if length == 32 else int.from_bytes(value, 'little')
    real_read = bool(storage and storage['_native_virtio_ready'] == 1 and
                     storage['_native_virtio_read_requests'] > 0 and storage['_native_virtio_read_failures'] == 0 and
                     storage['_native_virtio_first_sector_sha256'] == expected_first_sector and
                     storage['_native_virtio_sectors'] * 512 == disk.stat().st_size)
    authenticated_read = bool(real_read and args.owner_policy_report and
                              storage['_native_virtio_manifest_ready'] == 1 and
                              storage['_native_virtio_verified_devices'] >= 1 and
                              storage['_native_virtio_verified_blocks'] >= 1 and
                              storage['_native_virtio_integrity_failures'] == 0 and
                              storage['_verified_root_policy_count'] == 2)
    result_record = dict(exit_code=result.returncode, reached_requested_checkpoint=reached,
                         pc=observation.get('pc'), argument_memory=observation.get('argument_memory'),
                         kernel_sha256=observation.get('kernel_sha256'),
                         apfs_load_status=apfs_status,
                         storage=storage, actual_virtio_first_sector_read=real_read,
                         actual_authenticated_first_sector_read=authenticated_read,
                         root_mounted=False, userland_started=False, handset_operations=False)
    (args.out / 'result.json').write_text(json.dumps(result_record, indent=2)+'\n')
    print(json.dumps(result_record, indent=2))
    success = (result.returncode == 0 and reached and not args.finish_function and
               (not args.apfs_metadata or apfs_status == 0) and (not disk or real_read))
    success = success and (not args.owner_policy_report or authenticated_read)
    raise SystemExit(0 if success else result.returncode or 1)


if __name__ == '__main__':
    main()
