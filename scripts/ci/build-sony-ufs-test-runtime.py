#!/usr/bin/env python3
"""Combine real UFS/crypto objects with an opt-in Sony diagnostic coordinator."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

DEVICE = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree', type=Path, required=True)
    parser.add_argument('--mainline', type=Path, required=True)
    parser.add_argument('--ufs', type=Path, required=True)
    parser.add_argument('--verified', type=Path, required=True)
    parser.add_argument('--virtio', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--verified-virtio', action='store_true',
                        help='Use the owner-verified VirtIO transport and enable the real policy loader')
    parser.add_argument('--verified-transport', type=Path,
                        help='Audited owner-verified transport variant')
    parser.add_argument('--display-archive', type=Path,
                        help='D27 ABI-audited late Legacy display archive')
    parser.add_argument('--data-ram', action='store_true', help='Register the shared RAM Data provider in QEMU')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    out = args.out.resolve()
    if args.verified_transport and not args.verified_virtio:
        parser.error('--verified-transport requires --verified-virtio')
    virtio = args.verified_transport or (args.verified if args.verified_virtio else args.virtio)
    objects = [args.verified / 'IOBlockStorageDevice.late.o', virtio / 'NativeVirtioBlock.late.o',
               args.ufs / 'NativeUfs.late.o', args.verified / 'SourceRootPolicies.o',
               args.verified / 'verified_root.o', args.verified / 'xnu_crypto.o', args.verified / 'RootAnchor.o']
    if args.display_archive:
        receipt = json.loads((args.display_archive.parent/'report.json').read_text())
        if receipt.get('kernelcache_sha256') != 'c28f4fc9b83cde00087e81f890c82d566b9e98b5ac228dfecd83afdf34070445':
            raise ValueError('Display archive is not bound to original D27/24A446')
        objects.append(args.display_archive.resolve())
    # Authenticate every externally prepared object against its build receipt.
    receipt_dirs = [args.ufs, args.verified, args.virtio]
    if args.verified_transport:
        receipt_dirs.append(args.verified_transport)
    receipts = [json.loads((directory / 'report.json').read_text()) for directory in receipt_dirs]
    for obj in objects:
        if obj.name == 'NativeUfs.late.o':
            # UFS archive receipt covers this object through the actual ar member.
            member = subprocess.check_output(['/usr/lib/llvm-18/bin/llvm-ar', 'p',
                                               str(args.ufs / 'libSonyUfsAdapter.a'), obj.name])
            if member != obj.read_bytes():
                raise ValueError('UFS late object differs from audited archive')
        else:
            digest = hashlib.sha256(obj.read_bytes()).hexdigest()
            if not any(row['object_sha256'] == digest for receipt in receipts for row in receipt.get('sources', [])):
                raise ValueError('Object has no matching build receipt: ' + str(obj))
    recipe = args.tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json'
    record = json.JSONDecoder().raw_decode(recipe.read_text())[0]
    spec = importlib.util.spec_from_file_location('sony_runtime_compiler', args.mainline / 'scripts/build-sheng-source-drivers.py')
    compiler = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(compiler)
    if args.data_ram:
        if not args.verified_virtio:
            parser.error('--data-ram requires --verified-virtio')
        source = args.mainline / 'drivers/RamBlock/NativeRamBlock.cpp'
        obj = out / 'NativeRamBlock.o'
        command = compiler.compile_command(record, source, obj,
            ['-I', str(args.tree / 'build/storage-abi/include'), '-I', str(args.tree / '.cache/xnu-work/osfmk')],
            ['-Wno-missing-designated-field-initializers'])
        (out / 'NativeRamBlock.command.json').write_text(json.dumps(command, indent=2)+'\n')
        done = subprocess.run(command, cwd=record['directory'], capture_output=True, text=True)
        (out / 'NativeRamBlock.log').write_text(done.stdout+done.stderr)
        done.check_returncode()
        late = out / 'NativeRamBlock.late.o'
        subprocess.run(['/root/unixnu-build/pdx234-pac-clang-build/bin/llvm-objcopy',
            '--remove-section=__DATA,__mod_init_func', '--globalize-symbol=__GLOBAL__sub_I_NativeRamBlock.cpp',
            str(obj), str(late)], check=True)
        audit_spec = importlib.util.spec_from_file_location('ram_block_audit', DEVICE/'scripts/ci/audit-d27-block-interface.py')
        audit = importlib.util.module_from_spec(audit_spec)
        audit_spec.loader.exec_module(audit)
        table = audit.object_vtable(late.read_bytes(), '__ZTV14NativeRamBlock')
        interface = json.loads((args.verified/'interface-audit.json').read_text())
        if len(table)!=190 or any(tuple(a['pac'])!=tuple(b['pac']) for a,b in zip(interface['methods'],table)):
            raise ValueError('RAM block dispatch differs from D27')
        objects.append(late)
    sources = (DEVICE / 'ci/qemu/SourceBlockStorage.cpp', DEVICE / 'ci/ufs/SonyUfsTest.cpp')
    for source in sources:
        obj = out / (source.stem + '.o')
        flags = ['-DSONY_UFS_TEST=1', '-Wno-missing-designated-field-initializers']
        if args.verified_virtio:
            flags += ['-DNATIVE_VERIFIED_BLOCK=1', '-DNATIVE_VERIFIED_BLOCK_MULTI_POLICY=1',
                      '-DNATIVE_VERIFIED_POLICY_HANDOFF=1']
        if args.data_ram:
            flags.append('-DD27_QEMU_DATA=1')
        command = compiler.compile_command(record, source, obj,
            ['-I', str(args.tree / 'build/storage-abi/include'), '-I', str(args.tree / '.cache/xnu-work/osfmk')],
            flags)
        (out / (source.stem + '.command.json')).write_text(json.dumps(command, indent=2) + '\n')
        r = subprocess.run(command, cwd=record['directory'], capture_output=True, text=True, timeout=180)
        (out / (source.stem + '.log')).write_text(r.stdout + r.stderr)
        r.check_returncode()
        objects.append(obj)
    archive = out / 'libSonyUfsTestRuntime.a'
    subprocess.run(['/usr/lib/llvm-18/bin/llvm-ar', 'rcs', str(archive), *map(str, objects)], check=True)
    report = dict(archive=str(archive), archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
                  verified_transport=str(virtio),
                  objects={str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in objects},
                  sony_diagnostic_modes=[2, 10], root_mode_disabled=True, data_and_log_writes_disabled=True,
                   qemu_virtio_transport_unverified_diagnostic=not args.verified_virtio,
                   qemu_owner_policy_loader_enabled=args.verified_virtio,
                   d27_display_archive=str(args.display_archive) if args.display_archive else None,
                    qemu_data_ram_enabled=args.data_ram,
                  ufs_verified_read_code_enabled=True, kernel_linked=False, device_operations=False)
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
