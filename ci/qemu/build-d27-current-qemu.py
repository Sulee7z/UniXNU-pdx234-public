#!/usr/bin/env python3
"""Build a bounded 058-derived QEMU native kernel with genuine verified VirtIO.

The current native inputs, display/GPU archives, assym and IIG products are
immutable. Only the private BSD caller and complete storage ownership unit differ.
"""
import argparse
import copy
import difflib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

DEVICE = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
NATIVE_SHA = '2ce2ed908371689c5d41e4da9c2cf8d23c96450084c91718aaa5dc440c9ff1e8'
PAC = '-fptrauth-function-pointer-type-discrimination'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n')


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def budget():
    free = shutil.disk_usage('/mnt/g').free
    if free < 8 * 1024**3:
        raise RuntimeError('G: below the 8 GiB reserve')
    return free


def run(command, log, cwd=None, env=None):
    budget()
    save(log.with_suffix('.command.json'), list(map(str, command)))
    with log.open('w') as stream:
        done = subprocess.run(list(map(str, command)), cwd=cwd, env=env,
                              stdout=stream, stderr=subprocess.STDOUT, timeout=360)
    if done.returncode:
        raise RuntimeError(str(log) + '\n' + log.read_text()[-10000:])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, default=BASE/'qemu-current-20261117-001')
    parser.add_argument('--stage', choices=('native','strict'), default='native')
    args = parser.parse_args()
    work = args.work.resolve()
    source_native = BASE/'native-first-frame-058-001'
    cache_native = BASE/'native-screen007-055-001'
    parent = json.loads((source_native/'result.json').read_text())
    if sha(source_native/'native.macho') != NATIVE_SHA or parent['native_sha256'] != NATIVE_SHA:
        raise ValueError('Exact current058 native input required')
    if parent['auth_instruction_patches'] or not parent['pac_authentication_retained']:
        raise ValueError('Current native PAC qualification changed')
    sys.path.insert(0, str(DEVICE/'ci'))
    from native_source_overlays import validate_overlays
    validate_overlays(parent, sha)
    plan = json.loads((cache_native/'plan.json').read_text())
    jobs = plan['jobs']
    records = {Path(j['source']).stem:j for j in jobs if j['group']=='storage'}
    record_bsd = next(j for j in jobs if j['source'].endswith('/bsd_init.c'))
    if args.stage == 'strict':
        result = json.loads((work/'native/result.json').read_text())
        if sha(work/'native/native.macho') != result['native_sha256']:
            raise ValueError('New native identity changed')
        for item in result['qemu_current_sources']:
            if sha(item['source']) != item['source_sha256'] or sha(item['object']) != item['object_sha256']:
                raise ValueError('QEMU source/object identity changed')
        if result['qemu_block_pac_slots_checked'] != 190:
            raise ValueError('Fresh block PAC audit required')
        # Keep the established emitter and every strict check. The inherited
        # native overlays are validated above; the QEMU-only derivative receives
        # the additional hash-bound source/object selection checks here.
        finish = DEVICE/'scripts/ci/finish-d27-pac-abi.py'
        sys.argv = [str(finish), '--build', str(work/'native'), '--out', str(work/'strict'),
                    '--profile', str(DEVICE/'profiles/ios-27.0.1-24A446-iphone14/graphics-prelink.toml'),
                    '--expanded-native-data', '--symbol-evidence', str(BASE/'strict-first-frame-058-001/XnuPrelink/fixtures/fileset-d27-graphics-symbols.json')]
        import runpy
        runpy.run_path(str(finish), run_name='__main__')
        return

    work.mkdir(parents=True, exist_ok=False)
    out = work/'storage';out.mkdir()
    native = work/'native';native.mkdir()
    save(work/'parent-result.json', parent)
    compiler = Path(plan['compiler'])
    objcopy = Path('/root/unixnu-build/pdx234-pac-clang-build/bin/llvm-objcopy')
    ar = Path('/usr/lib/llvm-18/bin/llvm-ar')
    nm = Path('/usr/lib/llvm-18/bin/llvm-nm')
    if sha(compiler) != plan['compiler_sha256']:
        raise ValueError('Current compiler differs')
    source_tree = Path(plan['tree'])
    selected = []
    def compile_source(record, source, target, flags=(), late=False):
        command = list(record['command'])
        if PAC not in command:
            raise ValueError('Current PAC compile flag absent')
        command[command.index(record['source'])] = str(source)
        command[command.index('-o')+1] = str(target)
        # Same selected native policy for partial designated initializers in
        # upstream XNU typed-allocation macros; keep all other errors enabled.
        command += ['-Wno-missing-designated-field-initializers', *flags]
        run(command, target.with_suffix('.log'), cwd=record['directory'])
        output = target
        if late:
            output = target.with_suffix('.late.o')
            run([objcopy, '--remove-section=__DATA,__mod_init_func',
                 '--globalize-symbol=__GLOBAL__sub_I_'+source.name, target, output],
                target.with_suffix('.late.log'))
            legacy = module('qemu_late_check', DEVICE/'scripts/ci/build-qemu-source-block.py')
            if legacy.has_module_initializers(output.read_bytes()):
                raise ValueError('Early storage class initializer remains')
        selected.append(dict(source=str(source), source_sha256=sha(source), object=str(output),
                             object_sha256=sha(output), pac_flag=PAC, late=late,
                             compile_recipe_sha256=sha(target.with_suffix('.command.json'))))
        return output

    # Recompile the current late base and RAM class with the same private headers.
    base_job=records['IOBlockStorageDevice']
    base_object=compile_source(base_job, Path(base_job['source']), out/'IOBlockStorageDevice.o', late=True)
    ram_job=records['NativeRamBlock']
    ram_object=compile_source(ram_job, Path(ram_job['source']), out/'NativeRamBlock.o', late=True)

    virtio = BASE/'sources/UniXNU/drivers/VirtioMmioBlock/NativeVirtioBlock.cpp'
    text = virtio.read_text()
    old = 'clock_interval_to_deadline(1000, kMillisecondScale, &deadline);\n  while (used[1] == usedIndex)'
    new = 'clock_interval_to_deadline(30000, kMillisecondScale, &deadline);\n  while (used[1] == usedIndex)'
    if text.count(old)!=1 or text.count('clock_interval_to_deadline(1000, kMillisecondScale, &deadline);')!=2:
        raise ValueError('VirtIO deadline sites changed')
    changed = text.replace(old,new)
    old_protect = ('vm_map_protect(kernel_map, verifiedStorage, verifiedStorage + verifiedStorageBytes,\n'
                   '      VM_PROT_READ, TRUE)')
    if changed.count(old_protect)!=1:
        raise ValueError('VirtIO protection site changed')
    changed=changed.replace('#include <vm/vm_kern.h>',
        '#include <vm/vm_kern.h>\n#include <vm/vm_kern_xnu.h>\n#include <mach/mach_vm.h>')
    changed=changed.replace(old_protect,
        'mach_vm_protect(kernel_map, verifiedStorage, verifiedStorageBytes, TRUE, VM_PROT_READ)')
    adapted=out/'NativeVirtioBlock.cpp';adapted.write_text(changed)
    (out/'virtio.patch').write_text(''.join(difflib.unified_diff(text.splitlines(True),changed.splitlines(True),
                                                           fromfile=str(virtio),tofile=str(adapted))))
    transport=compile_source(ram_job, adapted, out/'NativeVirtioBlock.o', late=True)
    coordinator=DEVICE/'ci/qemu/SourceBlockStorage.cpp'
    coordinator_object=compile_source(ram_job, coordinator, out/'SourceBlockStorage.o',
                                     ['-DD27_QEMU_DATA=1'])
    objects=[base_object,transport,ram_object,coordinator_object]
    # Genuine current optional providers are still referenced by the unchanged
    # display and diagnostics. Keep their actual implementation inactive: the
    # sole late coordinator never calls the NativeUfs class initializer, and
    # the virt ADT contains no UFS provider. No replacement stubs are introduced.
    ufs_job=records['NativeUfs']
    objects.append(compile_source(ufs_job,Path(ufs_job['source']),out/'NativeUfs.o',late=True))
    # Current real policy/crypto/anchor and established weak-import semantics.
    # No UFS transport, UFS coordinator, or UFS-specific root binding is selected.
    for name in ('SourceRootPolicies','BootLog','BootLogDefaults','BootReset','verified_root',
                 'xnu_crypto','RootAnchor','BootWatchdogPolicy','WifiFirmware','SonyWeakDefaults'):
        record=records[name]
        if sha(record['source']) != record['source_sha256']:
            raise ValueError('Current storage source changed: '+name)
        objects.append(compile_source(record, Path(record['source']), out/(name+'.o')))
    archive=out/'libQemuCurrentStorage.a'
    run([ar,'rcs',archive,*objects],out/'archive.log')

    # Compare the fresh current base and concrete transport with the exact D27.
    audit=module('d27_current_block_audit',DEVICE/'scripts/ci/audit-d27-block-interface.py')
    strict_command=json.loads((BASE/'strict-first-frame-058-001/command.json').read_text())
    original=Path(strict_command[strict_command.index('--prelinked')+1])
    interface=audit.audit(original,base_object,DEVICE/'ci/XnuPrelink')
    old=module('d27_current_block_tables',DEVICE/'scripts/ci/build-qemu-source-block.py')
    old.validate_tables(interface['methods'],audit.object_vtable(base_object.read_bytes(),'__ZTV20IOBlockStorageDevice'),
                        audit.object_vtable(transport.read_bytes(),'__ZTV17NativeVirtioBlock'))
    ram_table=audit.object_vtable(ram_object.read_bytes(),'__ZTV14NativeRamBlock')
    if len(ram_table)!=190 or any(tuple(a['pac'])!=tuple(b['pac']) for a,b in zip(interface['methods'],ram_table)):
        raise ValueError('RAM concrete PAC dispatch differs')
    save(out/'interface-audit.json',interface)

    # New strong QEMU caller directly after the existing vfsinit; preserve all
    # current startup, diagnostics, declarations and authenticated dispatch.
    bsd_text=Path(record_bsd['source']).read_text()
    old_caller=('\t/* Optional source storage runtime registers after the IOKit bootstrap. */\n'
                '\textern void native_source_storage_start(void) __attribute__((weak_import));\n'
                '\tif (&native_source_storage_start)\n\t\tnative_source_storage_start();')
    new_caller=('\t/* QEMU-only real late storage; coordinator independently checks virt ADT. */\n'
                '\textern void native_qemu_storage_start(void);\n\tnative_qemu_storage_start();')
    if bsd_text.count(old_caller)!=1:
        raise ValueError('Current BSD storage caller differs')
    bsd=native/'bsd_init.c';bsd.write_text(bsd_text.replace(old_caller,new_caller))
    (native/'caller.patch').write_text(''.join(difflib.unified_diff(bsd_text.splitlines(True),bsd.read_text().splitlines(True),
                                                               fromfile=record_bsd['source'],tofile=str(bsd))))
    caller=compile_source(record_bsd,bsd,native/'bsd_init.o')
    imports=subprocess.check_output([str(nm),'-u',str(caller)],text=True).split()
    if '_native_qemu_storage_start' not in imports or '_native_source_storage_start' in imports:
        raise ValueError('BSD object imports the wrong storage coordinator')
    command=json.loads((source_native/'native-link.command.json').read_text())
    filelist=Path(command[command.index('-filelist')+1])
    lines=filelist.read_text().splitlines()
    if lines.count(record_bsd['output'])!=1:
        raise ValueError('Current BSD object is not unique in filelist')
    receipts=[]
    for value in lines+[v for v in command if v.endswith('.o')]:
        obj=Path(value)
        trace=parent.get('framebuffer_call_trace',{})
        if value==trace.get('object'):
            if not trace.get('verified') or sha(obj)!=trace['object_sha256']:
                raise ValueError('Current qualified framebuffer dispatcher changed')
            receipts.append(dict(path=value,sha256=trace['object_sha256'],receipt='framebuffer_call_trace'))
            continue
        receipt=obj.with_name(obj.name+'.json');field='sha256'
        if not receipt.exists() and obj.name=='lastkernelconstructor.last.o':
            receipt=obj.with_name('lastkernelconstructor.o.json');field='archive_object_sha256'
        r=json.loads(receipt.read_text())
        if r['exit'] or sha(obj)!=r[field]:raise ValueError('Cached object changed: '+value)
        receipts.append(dict(path=value,sha256=r[field]))
    new_list=native/'link.filelist'
    new_list.write_text('\n'.join(str(caller) if value==record_bsd['output'] else value for value in lines)+'\n')
    command[command.index('-filelist')+1]=str(new_list)
    command[command.index('-o')+1]=str(native/'native.macho')
    before='-Wl,-force_load,'+str(cache_native/'archives/libShengUfs.a')
    if command.count(before)!=1:raise ValueError('Current UFS archive selection changed')
    command[command.index(before)]='-Wl,-force_load,'+str(archive)
    for key in ('gpu_source','display_source'):
        if sha(parent[key]['archive'])!=parent[key]['sha256']:
            raise ValueError('Current display/GPU archive changed')
    env=dict(os.environ,CROSS_CLANG=str(compiler),DARWIN_TRIPLE='arm64e-apple-ios27.0',
             CROSS_EXTRA_FLAGS=PAC,TMPDIR=str(native),PYTHONDONTWRITEBYTECODE='1')
    env['PATH']=str(Path(command[0]).parent)+':'+env['PATH']
    save(native/'native-link.command.json',command)
    run(command,native/'native-link.log',env=env)
    defined=subprocess.check_output([str(nm),'-g','--defined-only',str(native/'native.macho')],text=True).split()
    if '_native_source_storage_start' in defined:
        raise ValueError('Sony UFS coordinator still linked')
    for name in ('_native_qemu_storage_start','_native_virtio_verified_devices','_native_source_root_policies_load'):
        if name not in defined:raise ValueError('Required real QEMU implementation absent: '+name)
    result=copy.deepcopy(parent)
    result.update(native=str(native/'native.macho'),native_sha256=sha(native/'native.macho'),
                  current_derived_from=NATIVE_SHA,qemu_current_sources=selected,
                  qemu_storage_archive=str(archive),qemu_storage_archive_sha256=sha(archive),
                  qemu_block_pac_slots_checked=190,qemu_ram_pac_slots_checked=190,
                  qemu_storage_unique_ownership=True,ufs_transport_linked=True,
                  ufs_class_initializer_selected=False,ufs_coordinator_linked=False,
                  qemu_current_verified=True,device_operations=False,runtime_qualified=False)
    save(native/'result.json',result)
    save(native/'reused-object-identities.json',receipts)
    save(work/'build-result.json',dict(native_sha256=result['native_sha256'],storage_archive_sha256=sha(archive),
         current_derived_from=NATIVE_SHA,complete_block_pac_slots_checked=190,ram_pac_slots_checked=190,
         read_deadline_ms=30000,reset_deadline_ms=1000,reused_objects=len(receipts)-1,
         display_archive_unchanged=True,gpu_archive_unchanged=True,g_free_bytes=budget(),device_operations=False))
    print(json.dumps(json.loads((work/'build-result.json').read_text()),indent=2),flush=True)


if __name__=='__main__':main()
