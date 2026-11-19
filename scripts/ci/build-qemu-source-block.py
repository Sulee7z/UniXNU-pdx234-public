#!/usr/bin/env python3
"""Build a QEMU-only late source block archive from a prepared D27 XNU tree.

No kernel/configuration is changed. The caller must still integrate the BSD
startup caller, actual QEMU disks/ADT, and validate real block/root I/O.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tomllib

DEVICE = Path(__file__).resolve().parents[2]
STORAGE_REVISION = '7edb88fbae296fb7c8ce2f64e115e116e566d51c'
VIRTIO_REVISION = '4e1013eb8c45077b57f8d38d61b389fe899ea1c3'
REGISTRATION_MACRO = 'OSDefineMetaClassAndAbstractStructors(IOBlockStorageDevice,IOService)'
LATE_REGISTRATION = '''
extern "C" const OSMetaClass *native_source_storage_parent(void);
OSDefineMetaClassWithInit(IOBlockStorageDevice, IOService, )
IOBlockStorageDevice::MetaClass::MetaClass()
    : OSMetaClass("UniXNUBlockStorageDevice", native_source_storage_parent(), sizeof(IOBlockStorageDevice)) {}
OSDefineAbstractStructors(IOBlockStorageDevice, IOService)
OSDefineOperatorMethods(IOBlockStorageDevice)
'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pinned(path, revision):
    actual = subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()
    dirty = subprocess.check_output(['git', '-C', str(path), 'status', '--porcelain'], text=True).strip()
    if actual != revision or dirty:
        raise ValueError(f'{path}: require clean source at {revision}')


def late_source(text):
    if text.count(REGISTRATION_MACRO) != 1:
        raise ValueError('Pinned storage registration macro changed')
    return text.replace(REGISTRATION_MACRO, LATE_REGISTRATION)


def validate_tables(original, base, transport):
    if len(original) != 190 or len(base) != 190 or len(transport) != 190:
        raise ValueError('D27 block class method count changed')
    for expected, actual, concrete in zip(original, base, transport):
        if (expected['name'] != actual['name'] or tuple(expected['pac']) != tuple(actual['pac']) or
                tuple(expected['pac']) != tuple(concrete['pac'])):
            raise ValueError('Source or concrete block dispatch differs at slot ' + str(expected['slot']))
        if concrete['name'] == '___cxa_pure_virtual':
            raise ValueError('Concrete transport leaves an abstract operation unimplemented')


def has_module_initializers(data):
    if len(data) < 32 or struct.unpack_from('<I', data)[0] != 0xfeedfacf:
        raise ValueError('Invalid object for initializer check')
    at = 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        command, size = struct.unpack_from('<II', data, at)
        if size < 8 or at + size > len(data):
            raise ValueError('Invalid object load command')
        if command == 0x19:
            count = struct.unpack_from('<I', data, at + 64)[0]
            if size < 72 + 80 * count:
                raise ValueError('Invalid object section command')
            for index in range(count):
                site = at + 72 + 80 * index
                name = data[site:site + 16].split(b'\0')[0]
                extent = struct.unpack_from('<Q', data, site + 40)[0]
                if name == b'__mod_init_func' and extent:
                    return True
        at += size
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree', required=True, type=Path)
    parser.add_argument('--mainline', required=True, type=Path)
    audit_inputs = parser.add_mutually_exclusive_group(required=True)
    audit_inputs.add_argument('--interface-audit', type=Path)
    audit_inputs.add_argument('--kernelcache', type=Path,
                              help='Build and verify a fresh reference object on this host')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--objcopy', type=Path)
    parser.add_argument('--ar', type=Path)
    parser.add_argument('--owner-policies', type=Path, help='Fully verified D27 OS/SystemOS policy directory')
    parser.add_argument('--policy-source', type=Path, help='Pinned sheng checkout supplying SourceRootPolicies.cpp')
    args = parser.parse_args()
    if bool(args.owner_policies) != bool(args.policy_source):
        parser.error('--owner-policies and --policy-source must be supplied together')
    tree, mainline, out = args.tree.resolve(), args.mainline.resolve(), args.output.resolve()
    interface_reader = load('qemu_block_interface', DEVICE / 'scripts/ci/audit-d27-block-interface.py')
    storage = tree / 'refer/IOStorageFamily'
    virtio = mainline / 'drivers/VirtioMmioBlock'
    pinned(storage, STORAGE_REVISION)
    pinned(virtio, VIRTIO_REVISION)
    compiler = load('qemu_block_compile', mainline / 'scripts/build-sheng-source-drivers.py')
    recipe = tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json'
    record = json.loads(recipe.read_text().strip().rstrip(','))
    if not any('arm64e-apple-ios27.' in value for value in record['arguments']):
        parser.error('Compilation record is not the selected arm64e iOS27 target')
    if '-Wno-missing-designated-field-initializers' not in record['arguments']:
        parser.error('Native macro-initializer warning policy changed')
    out.mkdir(parents=True, exist_ok=False)
    base = out / 'IOBlockStorageDevice.cpp'
    base.write_text(late_source((storage / base.name).read_text()))
    coordinator = DEVICE / 'ci/qemu/SourceBlockStorage.cpp'
    transport = virtio / 'NativeVirtioBlock.cpp'
    sources = [base, transport, coordinator]
    policy_flags, policy_inputs = [], None
    if args.owner_policies:
        policies = args.owner_policies.resolve()
        policy_source = args.policy_source.resolve()
        if subprocess.check_output(['git', '-C', str(policy_source), 'rev-parse', 'HEAD'], text=True).strip() != \
                'a68ee4ee67cc71792fbf519de7e3e28072c717b5':
            parser.error('Source policy reader revision changed')
        if subprocess.check_output(['git', '-C', str(policy_source), 'status', '--porcelain', '--',
                                    'package/SourceRootPolicies.cpp'], text=True).strip():
            parser.error('Source policy reader is modified')
        profile = tomllib.loads((DEVICE / 'profiles/ios-27.0.1-24A446-iphone14/profile.toml').read_text())['root']
        key = (policies / 'OS/trusted-key.bin').read_bytes()
        if len(key) != 395 or (policies / 'SystemOS/trusted-key.bin').read_bytes() != key:
            parser.error('Policies require the same independent complete anchor')
        manifests = []
        for name, prefix in (('OS', 'os'), ('SystemOS', 'systemos')):
            verification = json.loads((policies / name / 'verification.json').read_text())
            manifest = (policies / name / 'manifest.bin').read_bytes()
            metadata = json.loads((policies / name / 'manifest.json').read_text())
            if (not verification['real_c_signature_and_block_verification'] or
                    verification['image_sha256'] != profile[prefix + '_image_sha256'] or
                    verification['volume_uuid'] != profile[prefix + '_volume_uuid'] or
                    verification['trusted_key_sha256'] != hashlib.sha256(key).hexdigest() or
                    metadata['hash_table_sha256'] != hashlib.sha256(manifest[544:]).hexdigest() or
                    len(manifest) != 544 + verification['blocks_verified'] * 32 or
                    manifest[56:88].hex() != verification['image_sha256']):
                parser.error(name + ': incomplete or mismatched policy input')
            manifests.append(manifest)
        cursor = 32 + 16 * len(manifests)
        entries = bytearray()
        for manifest in manifests:
            entries += struct.pack('<QQ', cursor, len(manifest))
            cursor += len(manifest)
        bundle = struct.pack('<8sQQQ', b'VROOTB01', 1, len(manifests), cursor) + entries + b''.join(manifests)
        if len(bundle) > 128 * 1024**2:
            parser.error('Policy bundle exceeds the original reader bound')
        (out / 'root-policies.bin').write_bytes(bundle)
        anchor = out / 'RootAnchor.c'
        anchor.write_text('#include <stdint.h>\nconst uint8_t verified_root_key[395] = {' +
                          ','.join(str(b) for b in key) + '};\n')
        sources += [policy_source / 'package/SourceRootPolicies.cpp',
                    mainline / 'kits/VerifiedRoot/src/verified_root.c',
                    mainline / 'kits/VerifiedRoot/adapters/xnu_crypto.c', anchor]
        policy_flags = ['-DNATIVE_VERIFIED_BLOCK=1', '-DNATIVE_VERIFIED_BLOCK_MULTI_POLICY=1',
                        '-DNATIVE_VERIFIED_POLICY_HANDOFF=1']
        # The upstream verified transport predates the selected XNU's private
        # allocation header split. Keep its operations and permission semantics.
        transport = out / 'NativeVirtioBlock.cpp'
        transport_text = (virtio / transport.name).read_text()
        old_protect = ('vm_map_protect(kernel_map, verifiedStorage, verifiedStorage + verifiedStorageBytes,\n'
                       '      VM_PROT_READ, TRUE)')
        if transport_text.count(old_protect) != 1:
            parser.error('Original transport protection operation changed')
        transport_text = transport_text.replace('#include <vm/vm_kern.h>',
            '#include <vm/vm_kern.h>\n#include <vm/vm_kern_xnu.h>\n#include <mach/mach_vm.h>')
        transport_text = transport_text.replace(old_protect,
            'mach_vm_protect(kernel_map, verifiedStorage, verifiedStorageBytes, TRUE, VM_PROT_READ)')
        transport.write_text(transport_text)
        sources[1] = transport
        policy_inputs = dict(bundle_sha256=sha(out / 'root-policies.bin'), bundle_bytes=len(bundle),
                             trusted_key_sha256=hashlib.sha256(key).hexdigest(),
                             policy_reader_revision='a68ee4ee67cc71792fbf519de7e3e28072c717b5')
    tools = Path(record['arguments'][0]).parent
    objcopy = args.objcopy or (tools / 'llvm-objcopy' if (tools / 'llvm-objcopy').is_file()
                               else Path(shutil.which('llvm-objcopy') or '/nonexistent/llvm-objcopy'))
    ar = args.ar or (tools / 'llvm-ar' if (tools / 'llvm-ar').is_file()
                    else Path(shutil.which('llvm-ar') or '/nonexistent/llvm-ar'))
    if not objcopy.is_file() or not ar.is_file():
        parser.error('Need explicit or available LLVM objcopy/ar')
    includes = ['-I', str(tree / 'build/storage-abi/include'), '-I', str(tree / '.cache/xnu-work/osfmk')]
    if policy_inputs:
        includes += ['-I', str(mainline / 'kits/VerifiedRoot/include'), '-I', str(virtio)]
    c_record = json.loads((tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/osfmk/DEVELOPMENT/startup.o.json')
                          .read_text().strip().rstrip(','))
    if args.kernelcache:
        reference = out / 'IOBlockStorageDevice.reference.o'
        command = compiler.compile_command(record, storage / 'IOBlockStorageDevice.cpp', reference, includes,
                                            ['-Wno-missing-designated-field-initializers', '-Wno-error'])
        (out / 'reference.command.json').write_text(json.dumps(command, indent=2) + '\n')
        done = subprocess.run(command, cwd=record['directory'], capture_output=True, text=True, timeout=180)
        (out / 'reference.log').write_text(done.stdout + done.stderr)
        if done.returncode:
            raise RuntimeError((done.stdout + done.stderr)[-6000:])
        interface = interface_reader.audit(args.kernelcache.resolve(), reference, DEVICE / 'ci/XnuPrelink')
        args.interface_audit = out / 'interface-audit.json'
        args.interface_audit.write_text(json.dumps(interface, indent=2) + '\n')
    else:
        interface = json.loads(args.interface_audit.read_text())
    if (interface.get('kernelcache_sha256') != interface_reader.KERNELCACHE_SHA256 or
            interface.get('class') != 'IOBlockStorageDevice' or interface.get('original_class_size') != 0x90 or
            interface.get('method_slots') != 190 or interface.get('pac_layout_matches') is not True):
        parser.error('Require the exact D27 static block-class audit')
    objects, reports = [], []
    for source in sources:
        output = out / (source.stem + '.o')
        flags = ['-Wno-missing-designated-field-initializers', *policy_flags]
        if source == base:
            flags.append('-Wno-error')  # Unmodified public implementation; the owned sources retain -Werror.
        selected_record = c_record if source.suffix == '.c' else record
        command = compiler.compile_command(selected_record, source, output, includes, flags)
        (out / (source.stem + '.command.json')).write_text(json.dumps(command, indent=2) + '\n')
        done = subprocess.run(command, cwd=selected_record['directory'], capture_output=True, text=True, timeout=180)
        (out / (source.stem + '.log')).write_text(done.stdout + done.stderr)
        if done.returncode:
            raise RuntimeError((done.stdout + done.stderr)[-6000:])
        data = output.read_bytes()
        if len(data) < 32 or data[:12] != bytes.fromhex('cffaedfe0c00000102000080'):
            raise ValueError('Compiled output is not an arm64e object')
        late_initialization = source in (base, transport)
        if late_initialization:
            if not has_module_initializers(data):
                raise ValueError('Expected class initializer section is absent')
            late = output.with_suffix('.late.o')
            subprocess.run([str(objcopy), '--remove-section=__DATA,__mod_init_func',
                            f'--globalize-symbol=__GLOBAL__sub_I_{source.name}', str(output), str(late)], check=True)
            if has_module_initializers(late.read_bytes()):
                raise ValueError('Class still has automatic initialization before the original family loads')
            output = late
        objects.append(output)
        reports.append({'source': str(source), 'source_sha256': sha(source),
                        'object_sha256': sha(output), 'late_initialization': late_initialization})
    archive = out / 'libQemuSourceBlock.a'
    subprocess.run([str(ar), 'rcs', str(archive), *map(str, objects)], check=True)
    base_table = interface_reader.object_vtable(objects[0].read_bytes(), '__ZTV20IOBlockStorageDevice')
    transport_table = interface_reader.object_vtable(objects[1].read_bytes(), '__ZTV17NativeVirtioBlock')
    validate_tables(interface['methods'], base_table, transport_table)
    nm = tools / 'llvm-nm' if (tools / 'llvm-nm').is_file() else Path(shutil.which('llvm-nm') or '/nonexistent/llvm-nm')
    if not nm.is_file():
        raise ValueError('LLVM nm is required to verify late initializer symbols')
    globals_text = subprocess.check_output([str(nm), '-g', '--defined-only', str(archive)], text=True)
    globals_defined = {line.split()[-1] for line in globals_text.splitlines() if line.strip() and not line.endswith(':')}
    for source in sources[:2]:
        if '__GLOBAL__sub_I_' + source.name not in globals_defined:
            raise ValueError('Late source initializer was not exported')
    report = {'archive': str(archive), 'archive_sha256': sha(archive), 'sources': reports,
              'storage_revision': STORAGE_REVISION, 'virtio_revision': VIRTIO_REVISION,
              'tools': {name: {'path': str(path.resolve()), 'sha256': sha(path),
                              'version': subprocess.check_output([str(path), '--version'], text=True).strip()}
                        for name, path in (('objcopy', objcopy), ('ar', ar), ('nm', nm))},
              'complete_block_pac_slots_checked': 190, 'late_initializer_symbols_exported': True,
              'early_class_initializer_sections_removed': True,
              'interface_audit_sha256': sha(args.interface_audit), 'caller_integrated': False,
               'fresh_reference_object_built': bool(args.kernelcache),
               'reference_object_linked_or_executed': False,
               'owner_policy_inputs': policy_inputs,
              'kernel_linked': False, 'actual_io_qualified': False, 'device_operations': False}
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
