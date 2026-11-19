#!/usr/bin/env python3
"""Apply the pinned owner-cache carrier to D27 identities and link strictly."""
import argparse
import hashlib
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

DEVICE = Path(__file__).resolve().parents[2]
PROJECT = DEVICE.parents[1]
ROOT_UUID = 'CA0FF65B-3E73-4D62-9000-EC719E1B6DB1'
CACHE_UUID = '79A22534-CAB8-4277-A9A7-C5B9656E6C0A'
WRONG_UUID = '79A22534-CAB8-4277-A9A7-C5B9656E6C0B'
CACHE_DIRECTORY = '/System/Library/Caches/com.apple.dyld'
BOOT_SET_DOMAIN = b'VerifiedRoot.OwnerBootSet.v1\0'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


class VerifiedView(ctypes.Structure):
    _fields_ = [('hashes', ctypes.c_void_p), ('image_bytes', ctypes.c_uint64),
               ('block_count', ctypes.c_uint64), ('generation', ctypes.c_uint64),
               ('volume_uuid', ctypes.c_uint8 * 16), ('image_sha256', ctypes.c_uint8 * 32)]


def owner_manifest_expectation(directory):
    """Host expectation only. The existing IOKit publisher remains authoritative."""
    report = json.loads((directory/'report.json').read_text())
    library = directory/'verified-root.so'
    if sha(library) != report['library_sha256']:
        raise ValueError('VerifiedRoot host library identity changed')
    provider = ctypes.CDLL(str(library))
    provider.vr_host_open.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                                    ctypes.c_uint64, ctypes.POINTER(VerifiedView)]
    provider.vr_host_open.restype = ctypes.c_int
    records = []
    for component, role, expected in [('OS', 1, ROOT_UUID), ('SystemOS', 2, CACHE_UUID)]:
        rows = [row for row in report['policies'] if row['component'] == component]
        if len(rows) != 1:
            raise ValueError('Ambiguous policy component: '+component)
        row = rows[0]
        manifest = (directory/component/'manifest.bin').read_bytes()
        key = (directory/component/'trusted-key.bin').read_bytes()
        verification = row['verification']
        if (hashlib.sha256(manifest).hexdigest() != row['manifest_sha256'] or
                hashlib.sha256(key).hexdigest() != verification['trusted_key_sha256'] or
                not verification['real_c_signature_and_block_verification']):
            raise ValueError('Verified policy inputs changed: '+component)
        view = VerifiedView()
        envelope = ctypes.create_string_buffer(manifest)
        anchor = ctypes.create_string_buffer(key)
        if len(key) != 395 or provider.vr_host_open(envelope, len(manifest), anchor, 1,
                                                  ctypes.byref(view)) != 0:
            raise ValueError('Original C owner signature/table verification refused: '+component)
        identity = str(uuid.UUID(bytes=bytes(view.volume_uuid))).upper()
        if (identity != expected or view.image_bytes != verification['image_bytes'] or
                bytes(view.image_sha256).hex() != verification['image_sha256']):
            raise ValueError('Signed D27 policy identity differs: '+component)
        records.append(dict(role=role, component=component, volume_uuid=identity,
                            manifest_bytes=len(manifest), manifest_sha384=hashlib.sha384(manifest).hexdigest()))
    digest = hashlib.sha384(BOOT_SET_DOMAIN+b''.join(
        bytes([row['role']])+bytes.fromhex(row['manifest_sha384']) for row in records)).hexdigest()
    return dict(domain=BOOT_SET_DOMAIN[:-1].decode(), sha384=digest, policies=records,
                original_c_policy_verification=True, host_expectation_only=True,
                injected_into_device_tree=False, kernel_publication_verified=False)


def compile_record(record, source, obj, wrong_uuid=False):
    """Replace paths and the two carrier defines, retaining the private XNU ABI."""
    definitions = {'XNU_OWNER_CACHE_CARRIER': 1,
                   'XNU_OWNER_CACHE_CARRIER_WRONG_UUID': int(wrong_uuid)}
    command = []
    arguments = record['arguments']
    index = 0
    while index < len(arguments):
        value = arguments[index]
        if value == record['file']:
            command.append(str(source))
        elif value == '-o':
            command.extend(['-o', str(obj)]); index += 1
        elif value in ('-MF', '-MT', '-MQ', '-MJ'):
            index += 1
        elif value in ('-MD', '-MMD', '-MP'):
            pass
        elif value == '-D' and arguments[index+1].split('=')[0] in definitions:
            name = arguments[index+1].split('=')[0]
            command.extend(['-D', name+'='+str(definitions[name])]); index += 1
        elif value.startswith('-D') and value[2:].split('=')[0] in definitions:
            name = value[2:].split('=')[0]
            command.append('-D'+name+'='+str(definitions[name]))
        elif value == '-Xclang' and index+1 < len(arguments) and arguments[index+1].startswith('-W'):
            index += 1
        else:
            command.append(value)
        index += 1
    if command.count(str(source)) != 1 or command.count(str(obj)) != 1:
        raise ValueError('Recorded vm_unix paths were not replaced exactly once')
    for name, value in definitions.items():
        if not any(arg == name+'='+str(value) or arg == '-D'+name+'='+str(value) for arg in command):
            raise ValueError('Carrier define missing from recorded command: '+name)
    command += [f'-DD27_OWNER_ROOT_UUID="{ROOT_UUID}"', f'-DD27_OWNER_CACHE_UUID="{CACHE_UUID}"',
                f'-DD27_OWNER_CACHE_WRONG_UUID="{WRONG_UUID}"',
                f'-DD27_OWNER_CACHE_DIRECTORY="{CACHE_DIRECTORY}"', '-Wno-unknown-warning-option']
    return command


def replace_vm_object(files, obj):
    hits = [i for i, path in enumerate(files) if path.endswith('/bsd/DEVELOPMENT/vm_unix.o')]
    if len(hits) != 1:
        raise ValueError('Ambiguous vm_unix object in startup linker list')
    updated = files.copy()
    updated[hits[0]] = str(obj)
    return updated


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree',type=Path,required=True)
    parser.add_argument('--mainline',type=Path,required=True)
    parser.add_argument('--native',type=Path,required=True)
    parser.add_argument('--runtime',type=Path,required=True)
    parser.add_argument('--startup-native',type=Path,required=True,
                        help='Owner-root/Data BSD+IOKit native linked with the selected verified runtime')
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--strict-out',required=True)
    parser.add_argument('--policy-dir',type=Path,default=DEVICE/'out/d27-owner-policies-001')
    parser.add_argument('--wrong-uuid',action='store_true',help='Build the upstream negative UUID control')
    args=parser.parse_args()
    args.out.mkdir(parents=True,exist_ok=False);out=args.out.resolve()
    text=(args.tree/'.cache/xnu-work/bsd/vm/vm_unix.c').read_text()
    ancestor = json.loads((args.native.resolve().parent.parent/'strict-result.json').read_text())
    if (ancestor.get('candidate_sha256') != sha(args.native) or ancestor.get('missing') != {} or
            ancestor.get('stubbed') != {} or ancestor.get('allow_missing') is not False):
        raise ValueError('Need the unchanged strict D27 ancestor')
    state = owner_manifest_expectation(args.policy_dir)
    (out/'owner-boot-manifest.json').write_text(json.dumps(state,indent=2)+'\n')
    substitutions={
        'const char *root_uuid = "04769D26-2CA0-4825-B443-E2E5F88300F2";':
            'const char *root_uuid = D27_OWNER_ROOT_UUID;',
        'const char *cache_uuid = "9846FE78-2910-4297-AF97-D59BB6F8FC16";':
            'const char *cache_uuid = D27_OWNER_CACHE_WRONG_UUID;',
        'const char *cache_uuid = "8846FE78-2910-4297-AF97-D59BB6F8FC16";':
            'const char *cache_uuid = D27_OWNER_CACHE_UUID;',
        'const char *directory = "/private/preboot/System/Library/Caches/com.apple.dyld";':
            'const char *directory = D27_OWNER_CACHE_DIRECTORY;',
    }
    for before,after in substitutions.items():
        if text.count(before)!=1: raise ValueError('Pinned upstream carrier source changed: '+before)
        text=text.replace(before,after)
    source=out/'vm_unix.c';source.write_text(text)
    recipe=args.tree/'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/bsd/DEVELOPMENT/vm_unix.o.json'
    record=json.JSONDecoder().raw_decode(recipe.read_text())[0]
    obj=out/'vm_unix.o'
    command=compile_record(record,source,obj,args.wrong_uuid)
    (out/'compile.command.json').write_text(json.dumps(command,indent=2)+'\n')
    env=dict(os.environ,TMPDIR=str(out),PYTHONDONTWRITEBYTECODE='1')
    with (out/'compile.log').open('w') as log:
        result=subprocess.run(command,cwd=record['directory'],env=env,stdout=log,stderr=subprocess.STDOUT)
    if result.returncode:raise RuntimeError((out/'compile.log').read_text()[-6000:])
    startup_input=args.startup_native.resolve()
    native_dir=startup_input if startup_input.is_dir() else startup_input.parent
    startup_report=json.loads((native_dir/'report.json').read_text())
    if sha(native_dir/'native.macho') != startup_report['native_sha256']:
        raise ValueError('Selected startup native identity changed')
    link=json.loads((native_dir/'native-link.command.json').read_text())
    original_list=Path(link[link.index('-filelist')+1])
    files=replace_vm_object(original_list.read_text().splitlines(),obj)
    startup_objects = [native_dir/'bsd_init.o', native_dir/'kern_exec.o', native_dir/'IOKitBSDInit.cpo']
    if any(files.count(str(path))!=1 for path in startup_objects):
        raise ValueError('Owner-root, SystemOS/Data or manifest startup object was lost')
    filelist=out/'link.filelist';filelist.write_text('\n'.join(files)+'\n')
    link[link.index('-filelist')+1]=str(filelist)
    link[link.index('-o')+1]=str(out/'native.macho')
    archive=next(arg for arg in link if arg.startswith('-Wl,-force_load,') and
                 arg.endswith('/libSonyUfsTestRuntime.a'))
    if link.count(archive)!=1:raise ValueError('Owner startup runtime differs')
    link[link.index(archive)]='-Wl,-force_load,'+str(args.runtime.resolve())
    (out/'native-link.command.json').write_text(json.dumps(link,indent=2)+'\n')
    env.update(CROSS_CLANG='/root/unixnu-build/pdx234-pac-toolchain/llvm/bin/clang-24',DARWIN_TRIPLE='arm64e-apple-ios27.0')
    env['PATH']='/root/unixnu-build/pdx234-pac-toolchain/CommandLineTools/usr/bin:'+env['PATH']
    with (out/'native-link.log').open('w') as log:
        result=subprocess.run(link,cwd=args.tree/'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837',env=env,stdout=log,stderr=subprocess.STDOUT)
    if result.returncode:raise RuntimeError((out/'native-link.log').read_text()[-6000:])
    report=dict(native_sha256=hashlib.sha256((out/'native.macho').read_bytes()).hexdigest(),
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),carrier_enabled=True,
        target_root_uuid=ROOT_UUID,target_systemos_uuid=CACHE_UUID,
        owner_carrier_directory=CACHE_DIRECTORY,wrong_uuid_refusal_uuid=WRONG_UUID,
        original_shared_region_policy_retained=True,baseline_source_unchanged=True,
        wrong_uuid_control=args.wrong_uuid, ancestor_kernel_sha256=ancestor['candidate_sha256'],
        startup_filelist=str(original_list), startup_objects_preserved={str(p):sha(p) for p in startup_objects},
        boot_manifest_expected_sha384=state['sha384'],device_tree_identity_injected=False,
        runtime_qualified=False,device_operations=False)
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    command=[sys.executable,'-B',str(DEVICE/'scripts/ci/finish-strict5-prelink.py'),
        '--tree',str(args.tree),'--mainline',str(args.mainline),'--native',str(out/'native.macho'),
        '--output',args.strict_out]
    with (out/'strict.log').open('w') as log:
        result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT)
    print((out/'strict.log').read_text()[-2500:])
    raise SystemExit(result.returncode)


if __name__=='__main__':main()
