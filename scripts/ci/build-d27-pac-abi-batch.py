#!/usr/bin/env python3
"""Rebuild the native kernel and every linked source archive with one PAC ABI.

Replays recorded compile/link inputs into a NEW directory. The source
snapshots, earlier objects, kernelcache and handset remain untouched.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import struct

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'ci'))
from compile_dependencies import capture as capture_dependencies, valid as dependencies_valid

BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
TREE = BASE / 'sources/UniXNU/out/pdx234/ios-27.0.1-24A446-iphone14/pdx234_sheng27_bulk/tree'
OBJ = TREE / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
CLANG = Path('/root/unixnu-build/pdx234-pac-toolchain/llvm/bin/clang-24')
CXX = Path('/root/unixnu-build/pdx234-pac-toolchain/CommandLineTools/usr/bin/clang++')
PAC_FLAG = '-fptrauth-function-pointer-type-discrimination'
BASELINE_SHA = '0eabc5cb006c3e2001fec3516368af2886be637cbcdc746e381253a89e08c6c5'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def first_json(path):
    return json.JSONDecoder().raw_decode(Path(path).read_text().lstrip())[0]


def replay(arguments, source, output):
    args, index = [], 0
    while index < len(arguments):
        value = str(arguments[index])
        if value == '-o':
            args += ['-o', str(output)]
            index += 2
            continue
        if value in ('-MF', '-MT', '-MQ', '-MJ'):
            index += 2
            continue
        if value in ('-MD', '-MMD', '-MP'):
            index += 1
            continue
        args.append(value)
        index += 1
    if args[0] == 'xcrun':
        tool = next(i for i, v in enumerate(args) if v in ('clang', 'clang++'))
        args = [str(CLANG), *(['--driver-mode=g++'] if args[tool] == 'clang++' else []), *args[tool+1:]]
    targets = []
    for index, value in enumerate(args):
        if value.startswith(('--target=', '-target=')):
            targets.append(value.split('=', 1)[1])
        elif index and args[index - 1] in ('--target', '-target'):
            targets.append(value)
    if (str(output) not in args or not targets or
            not re.fullmatch(r'arm64e-apple-ios27\.0(?:\.0)?', targets[-1])):
        raise ValueError('Need an explicit recorded arm64e/iOS27 compile')
    if any(v.startswith('-fno-ptrauth') or v == 'arm64-apple-ios27.0' for v in args):
        raise ValueError('PAC-disabled/arm64 compile is not permitted')
    if source.suffix not in ('.s', '.S'):
        if PAC_FLAG not in args:
            args += [PAC_FLAG]
        from block_descriptor_abi import FLAGS as block_flags, enabled as block_enabled
        if not block_enabled(args):
            args += block_flags
    return args


def check_arm64e_object(path):
    data = Path(path).read_bytes()
    magic, cpu, subtype, kind, count = struct.unpack_from('<5I', data)
    if (magic, cpu, subtype & 0xff, kind) != (0xfeedfacf, 0x100000c, 2, 1):
        raise ValueError('Not an arm64e relocatable object: ' + str(path))
    offset, deployment = 32, None
    for _ in range(count):
        cmd, size = struct.unpack_from('<II', data, offset)
        if cmd == 0x32:
            deployment = struct.unpack_from('<II', data, offset + 8)
        offset += size
    if deployment != (2, 27 << 16):
        raise ValueError('Not iOS27.0: ' + str(path))


def generated_assym(out):
    """Replay the native genassym feature gate with the same PAC flag."""
    folder = out / 'generated-assym'
    if folder.exists():
        saved = first_json(folder / 'result.json')
        if (saved['source_sha256'] != sha(saved['source']) or
                saved['original_assym_sha256'] != sha(OBJ / 'osfmk/DEVELOPMENT/assym.s') or
                saved['generated_assym_sha256'] != sha(folder / 'assym.s') or PAC_FLAG not in saved['command']):
            raise ValueError('Generated ABI cache changed')
        return folder
    folder.mkdir()
    record = first_json(OBJ / 'osfmk/DEVELOPMENT/startup.o.json')
    source = TREE / '.cache/xnu-work/osfmk/arm64/genassym.c'
    arguments = [str(source) if v == record['file'] else v for v in record['arguments']]
    output = folder / 'genassym.o'
    command = [v for v in replay(arguments, source, output) if v != '-c']
    command += ['-S', '-fno-integrated-as']
    with (folder / 'compile.log').open('x') as log:
        subprocess.run(command, cwd=record['directory'], stdout=log, stderr=subprocess.STDOUT,
                       check=True, timeout=120)
    defines = dict(re.findall(r'DEFINITION__define__([A-Za-z0-9_]+):\s*\.ascii\s*"([^"\n]+)"', output.read_text()))
    old_path = OBJ / 'osfmk/DEVELOPMENT/assym.s'
    old = dict(re.findall(r'^#define\s+(\w+)\s+([^\n]+)$', old_path.read_text(), re.M))
    generated = {}
    for key, value in defines.items():
        generated[key] = value
        generated[key + '_NUM'] = value.lstrip('$#')
    changes = {key: (old.get(key), value) for key, value in generated.items() if old.get(key) != value}
    expected = {'THREAD_CONTINUE_T_DISC', 'THREAD_CONTINUE_T_DISC_NUM',
                'TH_EXPECTED_FAULT_HANDLER_DIVERSIFIER', 'TH_EXPECTED_FAULT_HANDLER_DIVERSIFIER_NUM'}
    if set(generated) != set(old) or set(changes) != expected or int(generated['THREAD_CONTINUE_T_DISC_NUM']) == 0:
        raise ValueError('Unexpected generated native ABI changes: ' + repr(changes))
    lines = old_path.read_text().splitlines()
    text = '\n'.join(re.sub(r'^(#define\s+)(\w+)(\s+)([^\n]+)$',
                           lambda m: m[1] + m[2] + m[3] + generated[m[2]], line)
                     if line.startswith('#define ') else line for line in lines) + '\n'
    (folder / 'assym.s').write_text(text)
    receipt = dict(command=command, directory=record['directory'], source=str(source),
                   source_sha256=sha(source), original_assym_sha256=sha(old_path),
                   generated_assym_sha256=sha(folder / 'assym.s'), changed_defines=changes,
                   discriminator=hex(int(generated['THREAD_CONTINUE_T_DISC_NUM'])),
                   source_changes=False, auth_instruction_patches=False)
    (folder / 'result.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print('Generated THREAD_CONTINUE_T_DISC:', receipt['discriminator'], flush=True)
    return folder


def compile_job(job):
    output = Path(job['output'])
    output.parent.mkdir(parents=True, exist_ok=True)
    log = output.with_name(output.name + '.log')
    receipt_path = output.with_name(output.name + '.json')
    if sha(job['source']) != job['source_sha256']:
        raise ValueError('Recorded source changed: ' + job['source'])
    if job.get('original_source') and sha(job['original_source']) != job['original_source_sha256']:
        raise ValueError('Original generated source changed: ' + job['original_source'])
    if receipt_path.exists():
        previous = first_json(receipt_path)
        if (previous.get('exit') == 0 and dependencies_valid(previous) and all(previous.get(k) == v for k, v in job.items()) and
                output.is_file() and sha(output) == previous.get('sha256') and
                (not job.get('archive_output') or
                 sha(job['archive_output']) == previous.get('archive_object_sha256'))):
            check_arm64e_object(output)
            return previous
    # Preserve this owned attempt's failed/partial artifacts before retrying.
    for path in (output, log, receipt_path):
        if path.exists():
            index = 1
            while path.with_name(path.name + f'.previous-{index:03d}').exists():
                index += 1
            path.rename(path.with_name(path.name + f'.previous-{index:03d}'))
    depfile = output.with_name(output.name + '.d')
    command = list(job['command'])
    # Include system and generated headers, not only user headers. Assembly is
    # rebuilt on every cross-build reuse and is never accepted without a receipt.
    track_dependencies = Path(job['source']).suffix not in ('.s', '.S')
    if track_dependencies:
        command += ['-MD', '-MF', str(depfile), '-MT', 'pdx_object']
    with log.open('x') as stream:
        env = dict(os.environ, CCC_OVERRIDE_OPTIONS='# +-Wno-missing-designated-field-initializers +-Wno-unused-but-set-global')
        done = subprocess.run(command, cwd=job['directory'], env=env, stdout=stream,
                              stderr=subprocess.STDOUT, timeout=300)
    receipt = dict(job, exit=done.returncode)
    if done.returncode == 0:
        if track_dependencies:
            receipt.update(capture_dependencies(depfile, job['directory'], command[0]))
        receipt['executed_command'] = command
        check_arm64e_object(output)
        receipt['sha256'] = sha(output)
        if job.get('lastdata_rename'):
            data = bytearray(output.read_bytes())
            at, changed = 32, 0
            for _ in range(struct.unpack_from('<I', data, 16)[0]):
                cmd, size = struct.unpack_from('<II', data, at)
                if cmd == 0x19:
                    for index in range(struct.unpack_from('<I', data, at + 64)[0]):
                        section = at + 72 + 80 * index
                        if data[section + 16:section + 32].rstrip(b'\0') == b'__DATA':
                            data[section + 16:section + 32] = b'__LASTDATA_CONST'
                            changed += 1
                at += size
            if changed != 1:
                raise ValueError('Unexpected last constructor section layout')
            Path(job['archive_output']).write_bytes(data)
        for transform in job.get('transforms', []):
            subprocess.run(transform, check=True, timeout=60)
        if job.get('archive_output'):
            check_arm64e_object(job['archive_output'])
            receipt['archive_object_sha256'] = sha(job['archive_output'])
    receipt_path.write_text(json.dumps(receipt, indent=2) + '\n')
    if done.returncode:
        raise RuntimeError(f'{job["source"]}\n' + log.read_text(errors='replace')[-4500:])
    return receipt


def plan_jobs(out, iig_compat=None, sparse_recount=False, native_jop=False, single_cluster=False, vfs_diagnostic=False, usb_console=False, launchd_trace=False, upstream_startup=False, launchd_transport=False, launchd_shutdown=False, display_source=None, boot_screen=None, audit_repairs=False):
    jobs, replacements, groups = [], {}, {}
    assym = generated_assym(out)
    device = Path(__file__).resolve().parents[2]
    usb_module = device / 'drivers/QcomXnuUsbDebug'

    def add(arguments, source, output, directory, group):
        source_argument = str(source)
        source, output = Path(source), Path(output)
        if not source.is_absolute():
            source = (Path(directory) / source).resolve()
        arguments = [str(source) if str(v) == source_argument else str(v) for v in arguments]
        if not source.is_file():
            raise ValueError('Missing recorded source: ' + str(source))
        original_source = source
        original_source_sha256 = sha(source)
        adaptation = None
        if iig_compat and source.name.endswith('.iig.cpp'):
            sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'ci'))
            from linux_iig import adapt_generated
            source = out / 'generated-iig' / output.relative_to(out / 'objects').with_suffix('.cpp')
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(adapt_generated(original_source.read_text()))
            adaptation = 'authenticated-member-schema'
            arguments = [str(source) if str(v) == str(original_source) else v for v in arguments]
        elif sparse_recount and source.name == 'recount.c':
            sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'ci'))
            from recount_cpu_kinds import adapt_source
            source = out / 'native-source' / 'recount.c'
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(adapt_source(original_source.read_text()))
            adaptation = 'recount-sparse-cpu-kind-span'
            arguments = [str(source) if str(v) == str(original_source) else v for v in arguments]
        elif native_jop and source.name == 'machine_routines_apple.c':
            sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'ci'))
            from native_pac_policy import adapt_source
            source = out / 'native-source' / 'machine_routines_apple.c'
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(adapt_source(original_source.read_text()))
            adaptation = 'upstream-native-default-jop'
            arguments = [str(source) if str(v) == str(original_source) else v for v in arguments]
        elif single_cluster and source.name == 'sched_clutch.c':
            sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'ci'))
            from single_cluster_qos import adapt_source
            source = out / 'native-source' / 'sched_clutch.c'
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(adapt_source(original_source.read_text()))
            adaptation = 'single-cluster-qos-fallback'
            arguments = [str(source) if str(v) == str(original_source) else v for v in arguments]
        elif launchd_trace and (source.name == 'vfs_cache.c' or source.as_posix().endswith('/bsd/dev/arm/systemcalls.c')):
            sys.path.insert(0, str(device / 'ci'))
            from launchd_trace import adapt_source, adapt_vfs
            if launchd_transport:
                from launchd_transport_trace import adapt_source, adapt_vfs
            if launchd_shutdown:
                from launchd_shutdown_trace import adapt_source, adapt_vfs
            adapter = adapt_vfs if source.name == 'vfs_cache.c' else adapt_source
            adaptation = 'vfs-pid1-context' if source.name == 'vfs_cache.c' else 'pid1-syscall-trace'
            source = out / 'native-source' / source.name
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(adapter(original_source.read_text()))
            arguments = [str(source) if str(v) == str(original_source) else v for v in arguments]
            arguments += ['-I' + str(usb_module / 'include')]
        elif usb_console and source.name in ('pe_kprintf.c', 'serial_console.c', 'serial_general.c', 'bsd_init.c', 'vfs_cache.c'):
            sys.path.insert(0, str(device / 'ci'))
            from usb_console import UNITS, ADAPTERS
            adaptation = UNITS.get(source.name, 'vfs-parent-release-usb-diagnostic')
            source = out / 'native-source' / source.name
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(ADAPTERS[adaptation](original_source.read_text()))
            arguments = [str(source) if str(v) == str(original_source) else v for v in arguments]
            arguments += ['-I' + str(usb_module / 'include')]
        elif vfs_diagnostic and source.name in ('vfs_cache.c', 'kern_shutdown.c'):
            sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'ci'))
            from vfs_shutdown_diagnostic import adapt_cache, adapt_shutdown
            adapter = adapt_cache if source.name == 'vfs_cache.c' else adapt_shutdown
            adaptation = 'vfs-parent-release-diagnostic' if source.name == 'vfs_cache.c' else 'vfs-shutdown-request-diagnostic'
            source = out / 'native-source' / source.name
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(adapter(original_source.read_text()))
            arguments = [str(source) if str(v) == str(original_source) else v for v in arguments]
        if upstream_startup and original_source.name in ('vm_shared_region_pager.c', 'vfs_syscalls.c', 'OSMetaClass.cpp', 'OSKext.cpp'):
            sys.path.insert(0, str(device / 'ci'))
            from upstream_startup import UNITS, ADAPTERS
            if adaptation:
                raise ValueError('Unexpected overlapping startup overlay')
            adaptation = UNITS[original_source.name]
            source = out / 'native-source' / original_source.name
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(ADAPTERS[adaptation](original_source.read_text()))
            arguments = [str(source) if str(v) == str(original_source) else v for v in arguments]
        if audit_repairs and original_source.name in ('mac_vfs.c','kern_exec.c','sdt.c'):
            sys.path.insert(0,str(device/'ci'))
            from audit_source_repairs import UNITS, ADAPTERS
            if adaptation:raise ValueError('Overlapping audit repair')
            adaptation=UNITS[original_source.name]
            source=out/'native-source'/original_source.name
            source.parent.mkdir(parents=True,exist_ok=True)
            source.write_text(ADAPTERS[adaptation](original_source.read_text()))
            arguments=[str(source) if str(v)==str(original_source) else v for v in arguments]
        command = replay(arguments, source, output)
        if display_source:
            command = [v.replace('XNU_NATIVE_LEGACY_DISPLAY=0', 'XNU_NATIVE_LEGACY_DISPLAY=1') for v in command]
        if boot_screen:
            command = [v.replace('XNU_BOOT_PROGRESS=0', 'XNU_BOOT_PROGRESS=1') for v in command]
        if source != original_source:
            command += ['-iquote', str(original_source.parent)]
        if source.suffix in ('.s', '.S'):
            command[1:1] = ['-I', str(assym)]
        job = dict(group=group, source=str(source), source_sha256=sha(source), output=str(output),
                    directory=str(directory), command=command)
        if source != original_source:
            job.update(original_source=str(original_source), original_source_sha256=original_source_sha256)
            if adaptation == 'authenticated-member-schema':
                job['generated_iig_compatibility'] = adaptation
            else:
                job['native_source_patch'] = adaptation
        jobs.append(job)
        groups.setdefault(group, []).append(output)
        return output

    def object_record(path, group):
        path = Path(path)
        record = first_json(path.with_name(path.name + '.json'))
        output = out / 'objects' / group / path.relative_to(OBJ)
        add(record['arguments'], record['file'], output, record['directory'], group)
        replacements[str(path)] = str(output)
        if path.name == 'lastkernelconstructor.o':
            # Replay MakeInc.kernel's post-compile SEG_HACK step too. The
            # compile receipt alone precedes this section-name transformation.
            patched = output.with_name('lastkernelconstructor.last.o')
            jobs[-1]['archive_output'] = str(patched)
            jobs[-1]['lastdata_rename'] = True
            replacements[str(path)] = str(patched)

    original_list = (OBJ / 'link.filelist').read_text().splitlines()
    for path in original_list:
        object_record(path, 'xnu')
    tail_objects = [OBJ / name for name in ('version.o', 'lastkerneldataconst.o', 'lastkernelconstructor.o', 'nonlto.o')]
    for path in tail_objects:
        if str(path) not in replacements:
            object_record(path, 'xnu')
    filelist = out / 'link.filelist'
    filelist.write_text('\n'.join(replacements[p] for p in original_list) + '\n')

    for group in ('armcpu', 'armdt-platform'):
        arguments = first_json(TREE / 'build' / group / 'compile-command.json')
        source = next(v for v in arguments if str(v).endswith('.cpp') and Path(v).is_file())
        original_output = Path(arguments[arguments.index('-o')+1])
        record = first_json(OBJ / 'iokit/DEVELOPMENT/IOPlatformExpert.cpo.json')
        add(arguments, source, out / 'objects' / group / original_output.name, record['directory'], group)
    storage = TREE / 'build/sheng-source-storage'
    storage_report = first_json(storage / 'report.json')
    archive = TREE / 'build/sheng-ufs/libShengUfs.a'
    if sha(archive) != storage_report['archive_sha256']:
        raise ValueError('Verified storage archive changed')
    members = subprocess.check_output(['llvm-ar', 't', str(archive)], text=True).splitlines()
    for member in members:
        stem = member.removesuffix('.late.o').removesuffix('.o')
        arguments = first_json(storage / (stem + '.command.json'))
        sources = [v for v in arguments if str(v).endswith(('.c', '.cpp', '.s', '.S'))]
        if len(sources) != 1:
            raise ValueError('Need one recorded storage source: ' + member)
        source = Path(sources[0])
        expected = storage_report['sources'][str(source)]
        if not source.exists() and 'kits/VerifiedRoot' in str(source):
            original = str(TREE / 'kits/VerifiedRoot')
            recovered = str(BASE / 'sources/UniXNU/kits/VerifiedRoot')
            arguments = [str(v).replace(original, recovered) for v in arguments]
            source = Path(str(source).replace(original, recovered))
        else:
            original = str(TREE / 'kits/VerifiedRoot')
            recovered = str(BASE / 'sources/UniXNU/kits/VerifiedRoot')
            if not Path(original).exists():
                arguments = [str(v).replace(original, recovered) for v in arguments]
        old_include = str(TREE / 'drivers/VirtioMmioBlock')
        restored_include = BASE / 'sources/UniXNU/drivers/VirtioMmioBlock'
        if not Path(old_include).exists():
            if not (restored_include / 'VerifiedBlockPolicy.h').is_file():
                raise ValueError('Missing original VerifiedBlockPolicy header')
            arguments = [str(v).replace(old_include, str(restored_include)) for v in arguments]
        if sha(source) != expected:
            raise ValueError('Storage source identity changed: ' + str(source))
        destination = out / 'objects/storage' / (stem + '.o')
        if source.suffix == '.c':
            template = ('bsd/DEVELOPMENT/kern_exec.o.json' if source.name in
                        ('BootWatchdogPolicy.c', 'WifiFirmware.c') else 'osfmk/DEVELOPMENT/startup.o.json')
        else:
            template = 'iokit/DEVELOPMENT/IOPlatformExpert.cpo.json'
        record = first_json(OBJ / template)
        add(arguments, source, destination, record['directory'], 'storage')
        if member.endswith('.late.o'):
            late = destination.with_name(member)
            jobs[-1]['archive_output'] = str(late)
            jobs[-1]['transforms'] = [['/root/unixnu-build/pdx234-pac-clang-build/bin/llvm-objcopy', '--remove-section=__DATA,__mod_init_func',
                                      '--globalize-symbol=__GLOBAL__sub_I_' + source.name,
                                      str(destination), str(late)]]
            groups['storage'][-1] = late

    crypto = TREE / 'build/corecrypto-2023'
    arguments = first_json(crypto / 'compile-command-namespaced.json')
    report = first_json(crypto / 'build-report-namespaced.json')
    for item in report['objects']:
        source = TREE / 'refer/corecrypto-2023' / item['source']
        destination = out / 'objects/corecrypto' / item['object']
        add([*arguments, '-c', str(source), '-o', str(destination)], source, destination, TREE, 'corecrypto')

    framework = TREE / '.cache/fakeroot/System/Library/Frameworks/Kernel.framework/Versions/A'
    pthread = TREE / '.cache/libpthread-work'
    common = [str(CLANG), '-target', 'arm64e-apple-ios27.0', '-isysroot', str(TREE / '.cache/fakeroot'),
              '-mkernel', '-ffreestanding', '-fno-builtin', '-fno-stack-check', '-std=gnu11', '-fblocks',
              '-O2', '-mno-implicit-float', '-DKERNEL=1', '-DKERNEL_PRIVATE=1', '-DXNU_KERNEL_PRIVATE=1',
              '-DMACH_KERNEL_PRIVATE=1', '-DMACH_ASSERT=1', '-DDEBUG=1', '-D__PTHREAD_EXPOSE_INTERNALS__=1',
              '-DABSOLUTETIME_SCALAR_TYPE=1', '-DNEEDS_SCHED_CALL_T=1', '-I', str(pthread / 'private'),
              '-I', str(pthread / 'include'), '-I', str(pthread), '-I', str(framework / 'PrivateHeaders'),
              '-I', str(framework / 'Headers'), '-Wno-deprecated-declarations',
              '-include', str(TREE / 'build/libpthread-kernel/namespace.h')]
    for name in ('kern_init', 'kern_support', 'kern_synch'):
        source = pthread / 'kern' / (name + '.c')
        destination = out / 'objects/pthread' / (name + '.o')
        add([*common, '-c', str(source), '-o', str(destination)], source, destination, TREE, 'pthread')
    recipe = first_json(OBJ / 'osfmk/DEVELOPMENT/prng_random.o.json')
    source = TREE / '.cache/xnu-work/bsd/kern/source_pthread_bootstrap.c'
    destination = out / 'objects/pthread/source_pthread_bootstrap.o'
    args = [str(source) if v == recipe['file'] else v for v in recipe['arguments']]
    add(args, source, destination, recipe['directory'], 'pthread')

    rt = TREE / '.cache/linux/llvm-project/compiler-rt'
    common = [str(CLANG), '-target', 'arm64e-apple-ios27.0', '-arch', 'arm64e',
              '-isysroot', str(TREE / '.cache/fakeroot'), '-mkernel', '-DKERNEL_USE', '-O3', '-fPIC', '-w',
              '-I', str(rt / 'include'), '-I', str(TREE / '.cache/fakeroot/System/Library/Frameworks/Kernel.framework/Headers'),
              '-idirafter', str(TREE / '.cache/linux/Libc/include'),
              '-idirafter', str(TREE / '.cache/xnu-work/libsyscall/wrappers')]
    for name in ('InstrProfiling', 'InstrProfilingBuffer', 'InstrProfilingPlatformDarwin',
                 'InstrProfilingWriter', 'InstrProfilingInternal', 'InstrProfilingVersionVar'):
        source, destination = rt / ('lib/profile/' + name + '.c'), out / 'objects/cc-kext' / (name + '.o')
        add([*common, '-c', str(source), '-o', str(destination)], source, destination, TREE, 'cc-kext')
    # libfirehose_kernel is also linked (through -l rather than force_load).
    # Replay the pinned Linux build-firehose.sh recipe, not an SDK copy.
    dispatch = TREE / '.cache/libdispatch-work'
    sdk = TREE / '.cache/fakeroot'
    framework = sdk / 'System/Library/Frameworks/Kernel.framework'
    source = dispatch / 'src/firehose/firehose_buffer.c'
    destination = out / 'objects/firehose/firehose_buffer.o'
    flags = [str(CLANG), '-target', 'arm64e-apple-ios27.0', '-std=gnu11', '-Os', '-g',
             '-mkernel', '-nostdinc', '-Wno-packed', '-DKERNEL=1', '-DDISPATCH_USE_DTRACE=0',
             '-DOS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY=1', '-DOS_ATOMIC_CONFIG_STARVATION_FREE_ONLY=0']
    for include in (dispatch, framework / 'PrivateHeaders', framework / 'Headers',
                    sdk / 'usr/local/include/os', sdk / 'usr/local/include/firehose',
                    sdk / 'usr/include', sdk / 'usr/local/include', TREE / '.cache/xnu-work/EXTERNAL_HEADERS'):
        flags += ['-I', str(include)]
    add([*flags, '-c', str(source), '-o', str(destination)], source, destination, TREE, 'firehose')
    if usb_console:
        template = next(j for j in jobs if Path(j['source']).name == 'machine_routines_apple.c')
        sources = [usb_module / p for p in ('kernel/QcomXnuUsbDebug.c', 'kernel/QcomUsbScreenshot.c',
                   'usb/Dwc3.c', 'soc/QcomUsbQualify.c', 'soc/QcomUsbDmaDomain.c')]
        sources.append(device / 'ci/usb/PdxUsbWorker.c')
        for source in sources:
            arguments = [str(source) if str(v) == template['source'] else str(v) for v in template['command']]
            arguments += ['-I' + str(usb_module), '-I' + str(usb_module / 'include'),
                          '-I' + str(usb_module / 'kernel'),
                          '-DQUD_SOC_HEADER="' + str(device / 'ci/usb/Pdx234.h') + '"',
                          '-DQUD_SCREENSHOT_MAX_BYTES=4096', '-DSOC_USB_LOG_BUFFER_BYTES=524288']
            add(arguments, source, out / 'objects/usb-console' / (source.stem + '.o'), template['directory'], 'usb-console')
    return jobs, replacements, groups, tail_objects


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--jobs', type=int, default=8)
    p.add_argument('--evidence', required=True, type=Path, help='Completed three-evidence directory')
    p.add_argument('--execute', action='store_true')
    p.add_argument('--resume', action='store_true', help='Reuse hash-verified outputs of this owned attempt')
    p.add_argument('--reuse-build', type=Path, help='Copy verified unchanged objects from a completed PAC build; assembly is always rebuilt')
    p.add_argument('--iig-compat', type=Path, default=BASE / 'iig-authenticated-001',
                   help='Private patched IIG directory from prepare-linux-iig.py; required by the current Linux route')
    p.add_argument('--sparse-recount', action=argparse.BooleanOptionalAction, default=True)
    p.add_argument('--native-jop-policy', action=argparse.BooleanOptionalAction, default=True)
    p.add_argument('--single-cluster-qos', action=argparse.BooleanOptionalAction, default=True)
    p.add_argument('--vfs-shutdown-diagnostic', action='store_true')
    p.add_argument('--usb-console', action='store_true')
    p.add_argument('--launchd-trace', action='store_true')
    p.add_argument('--launchd-transport', action='store_true')
    p.add_argument('--launchd-shutdown', action='store_true')
    p.add_argument('--display-source', type=Path, help='Verified D27 display/KeyStore source-build directory')
    p.add_argument('--gpu-source', type=Path, help='Verified Sony GPU source-build directory')
    p.add_argument('--boot-screen', type=Path, help='Compiled upstream boot screen/fault archive')
    p.add_argument('--upstream-startup', action='store_true')
    p.add_argument('--audit-source-repairs', action='store_true')
    args = p.parse_args()
    if args.launchd_shutdown and not args.launchd_transport:
        p.error('--launchd-shutdown requires --launchd-transport')
    if args.launchd_transport and not args.launchd_trace:
        p.error('--launchd-transport requires --launchd-trace')
    if args.usb_console and not args.vfs_shutdown_diagnostic:
        p.error('--usb-console requires --vfs-shutdown-diagnostic for panic-screen reporting')
    if args.launchd_trace and not args.usb_console:
        p.error('--launchd-trace requires the current diagnostic composition --usb-console')
    if not 1 <= args.jobs <= 32:
        p.error('--jobs must be 1..32')
    out = args.out.resolve()
    if out.exists() and not args.resume:
        p.error('Use a new output directory')
    if args.resume and (not (out / 'plan.json').is_file() or
                        first_json(out / 'plan.json').get('baseline_native_sha256') != BASELINE_SHA):
        p.error('Only resume this script\'s recorded PAC attempt')
    if sha(OBJ / 'mach.development.bcm2837.unstripped.noctf') != BASELINE_SHA:
        raise ValueError('The verified baseline native changed')
    evidence = first_json(args.evidence / 'evidence.json')
    if (not all(evidence.get(name) for name in ('gate_passed', 'pointer_table_evidence',
                                               'compile_target_evidence', 'slot_owner_evidence')) or
            evidence.get('native_sha256') != BASELINE_SHA or
            evidence.get('permitted_build_delta') != [PAC_FLAG]):
        raise ValueError('The required PAC evidence gate has not passed')
    out.mkdir(parents=True, exist_ok=args.resume)
    iig_compat = None
    if args.iig_compat:
        iig_compat = first_json(args.iig_compat / 'result.json')
        if (not iig_compat.get('built') or not iig_compat.get('authenticated_cast') or
                iig_compat.get('raw_signature_stripping') is not False or
                sha(iig_compat['binary']) != iig_compat['binary_sha256']):
            raise ValueError('Unqualified IIG compatibility generator')
    display_source = None
    boot_screen = None
    if args.boot_screen:
        boot_screen = first_json(args.boot_screen / 'result.json')
        if sha(boot_screen['archive']) != boot_screen['sha256'] or boot_screen['pac_flag'] != PAC_FLAG:
            raise ValueError('Boot screen archive identity differs')
    gpu_source = None
    if args.gpu_source:
        gpu_source = first_json(args.gpu_source / 'result.json')
        if sha(gpu_source['archive']) != gpu_source['sha256'] or gpu_source['pac_flag'] != PAC_FLAG:
            raise ValueError('Unqualified Sony GPU source archive')
    if args.display_source:
        display_source = first_json(args.display_source / 'result.json')
        if (sha(display_source['archive']) != display_source['sha256'] or display_source['pac_flag'] != PAC_FLAG):
            raise ValueError('Unqualified D27 display source archive')
    if boot_screen and (not display_source or not display_source.get('boot_screen')):
        p.error('--boot-screen requires the matching display support build')
    jobs, replacements, groups, tail_objects = plan_jobs(out, iig_compat, args.sparse_recount, args.native_jop_policy, args.single_cluster_qos, args.vfs_shutdown_diagnostic, args.usb_console, args.launchd_trace, args.upstream_startup, args.launchd_transport, args.launchd_shutdown, display_source, boot_screen, args.audit_source_repairs)
    if args.reuse_build:
        previous = args.reuse_build.resolve()
        result = first_json(previous / 'result.json')
        cache_sources_allowed = (result['source_changes'] is False or
                                 (result.get('native_source_changes') is False and
                                  result.get('generated_iig_compat', {}).get('authenticated_cast') is True))
        if result.get('native_source_changes'):
            sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'ci'))
            from native_source_overlays import validate_overlays
            validate_overlays(result, sha)
            cache_sources_allowed = True
        if (result['pac_flag'] != PAC_FLAG or not cache_sources_allowed or
                sha(previous / 'native.macho') != result['native_sha256']):
            raise ValueError('Unqualified object cache')
        for job in jobs:
            if Path(job['source']).suffix in ('.s', '.S'):
                continue
            destination = Path(job['output'])
            old_output = previous / destination.relative_to(out)
            old_receipt = old_output.with_name(old_output.name + '.json')
            if not old_receipt.exists():
                continue
            receipt = first_json(old_receipt)
            if not dependencies_valid(receipt):
                continue
            converted = json.loads(json.dumps(receipt).replace(str(previous), str(out)))
            if (receipt.get('exit') != 0 or not all(converted.get(k) == v for k, v in job.items()) or
                    sha(old_output) != receipt['sha256'] or sha(job['source']) != job['source_sha256']):
                continue
            if not dependencies_valid(converted):
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(old_output, destination)
            if job.get('archive_output'):
                old_archive_object = Path(receipt['archive_output'])
                if sha(old_archive_object) != receipt['archive_object_sha256']:
                    raise ValueError('Archive object cache changed')
                shutil.copyfile(old_archive_object, job['archive_output'])
            converted['reused_from'] = str(old_output)
            destination.with_name(destination.name + '.json').write_text(json.dumps(converted, indent=2) + '\n')
    plan = dict(tree=str(TREE), baseline_native_sha256=BASELINE_SHA, compiler=str(CLANG),
                 compiler_sha256=sha(CLANG), pac_flag=PAC_FLAG, jobs=jobs,
                 evidence=str(args.evidence), evidence_sha256=sha(args.evidence / 'evidence.json'),
                   source_changes=bool(iig_compat) or args.sparse_recount or args.native_jop_policy or args.single_cluster_qos or args.vfs_shutdown_diagnostic,
                   native_source_changes=args.sparse_recount or args.native_jop_policy or args.single_cluster_qos or args.vfs_shutdown_diagnostic,
                   vfs_shutdown_diagnostic=args.vfs_shutdown_diagnostic,
                   usb_console=args.usb_console,
                   launchd_trace=args.launchd_trace,
                   launchd_transport=args.launchd_transport,
                   launchd_shutdown=args.launchd_shutdown,
                   display_source=display_source,
                   gpu_source=gpu_source,
                   boot_screen=boot_screen,
                   upstream_startup=args.upstream_startup,
                   audit_source_repairs=args.audit_source_repairs,
                  single_cluster_qos=args.single_cluster_qos,
                  native_jop_policy=args.native_jop_policy,
                  recount_sparse_kind_span=args.sparse_recount,
                  generated_iig_compat=iig_compat, auth_instruction_patches=False,
                 restored_compile_environment={'CCC_OVERRIDE_OPTIONS': '# +-Wno-missing-designated-field-initializers +-Wno-unused-but-set-global'},
                groups={key: len(value) for key, value in groups.items()},
                device_operations=False, pac_disabled=False, old_objects_overwritten=False)
    plan_path = out / 'plan.json'
    if plan_path.exists():
        index = 1
        while (out / f'plan-resume-{index:03d}.json').exists():
            index += 1
        plan_path = out / f'plan-resume-{index:03d}.json'
    plan_path.write_text(json.dumps(plan, indent=2) + '\n')
    print('PAC ABI batch plan:', plan['groups'], 'total', len(jobs), flush=True)
    if not args.execute:
        return
    receipts = []
    errors = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [pool.submit(compile_job, job) for job in jobs]
        for future in as_completed(futures):
            try:
                receipts.append(future.result())
            except Exception as error:
                errors.append(str(error))
            if len(receipts) % 100 == 0:
                print('Compile PASS', len(receipts), '/', len(jobs), flush=True)
    (out / 'compile-results.json').write_text(json.dumps(receipts, indent=2) + '\n')
    if errors:
        (out / 'compile-errors.json').write_text(json.dumps(errors, indent=2) + '\n')
        raise RuntimeError(f'{len(errors)} compile failures\n' + '\n'.join(errors)[:6500])
    archives = out / 'archives'
    archives.mkdir(exist_ok=args.resume)
    names = {'armcpu': 'libArmCpu.a', 'armdt-platform': 'libArmDTPlatform.a',
             'storage': 'libShengUfs.a', 'corecrypto': 'libcorecrypto_kernel_noasm-namespaced.a',
              'pthread': 'libpthread_kernel.a', 'cc-kext': 'libcc_kext.a', 'firehose': 'libfirehose_kernel.a'}
    if args.usb_console:
        names['usb-console'] = 'libQcomXnuUsbDebug.a'
    for group, name in names.items():
        subprocess.run(['llvm-ar', 'rcs', str(archives / name), *map(str, groups[group])], check=True)
    linkdir = OBJ / 'mach.development.bcm2837.link'
    linkargs = shlex.split((linkdir / 'mach.development.bcm2837.linkarguments').read_text())
    # The saved make arguments predate the baseline's final fileset relink.
    # Retain the measured baseline __LASTDATA_CONST marker; do not fold it
    # into __LAST when replaying that intermediate command.
    linkargs = [v for v in linkargs if v != '-Wl,-rename_segment,__LASTDATA_CONST,__LAST']
    linkargs = [str(archives / 'libcc_kext.a') if v.endswith('/libcc_kext.a') else v for v in linkargs]
    archive_args = shlex.split((linkdir / 'mach.development.bcm2837.linkarchives').read_text())
    archive_args = [str(archives / names['firehose']) if v == '-lfirehose_kernel' else v for v in archive_args]
    old_archives = {str(TREE / 'build/armcpu/libArmCpu.a'): str(archives / names['armcpu']),
                    str(TREE / 'build/armdt-platform/libArmDTPlatform.a'): str(archives / names['armdt-platform']),
                    str(TREE / 'build/sheng-ufs/libShengUfs.a'): str(archives / names['storage']),
                    str(TREE / 'build/corecrypto-2023/libcorecrypto_kernel_noasm-namespaced.a'): str(archives / names['corecrypto']),
                    str(TREE / 'build/libpthread-kernel/libpthread_kernel.a'): str(archives / names['pthread'])}
    archive_args = [next((v.replace(old, new) for old, new in old_archives.items() if old in v), v) for v in archive_args]
    if args.usb_console:
        archive_args += ['-Wl,-force_load,' + str(archives / names['usb-console'])]
    if display_source:
        archive_args += ['-Wl,-force_load,' + display_source['archive']]
    if gpu_source:
        archive_args += ['-Wl,-force_load,' + gpu_source['archive']]
    if boot_screen:
        archive_args += ['-Wl,-force_load,' + boot_screen['archive']]
    if display_source:
        # DTrace string literals have no pointer fixups and are referenced by
        # linker relocations. Keep them in readonly __TEXT to free one page of
        # the constrained DATA_CONST prefix; retain all assertions and probes.
        linkargs += ['-Wl,-rename_section,__DATA_CONST,__sdt_cstring,__TEXT,__sdt_cstring']
    if args.audit_source_repairs:
        linkargs += ['-Wl,-rename_section,__DATA_CONST,__sdt,__TEXT,__sdt']
    command = [str(CXX), *linkargs, '-Wl,-add_split_seg_info', '-Wl,-kernel',
               '-Wl,-alias_list,' + str(OBJ / 'all-alias.exp'),
               '-Wl,-sectcreate,__LINKINFO,__symbolsets,' + str(OBJ / 'symbolsets.plist'),
               '-Wl,-segprot,__LINKINFO,r--,r--', '-filelist', str(out / 'link.filelist'),
               *[replacements[str(p)] for p in tail_objects], '-o', str(out / 'native.macho'), *archive_args]
    for name in ('native.macho', 'native-link.log', 'native-link.command.json', 'result.json'):
        path = out / name
        if path.exists():
            index = 1
            while path.with_name(path.name + f'.previous-{index:03d}').exists():
                index += 1
            path.rename(path.with_name(path.name + f'.previous-{index:03d}'))
    (out / 'native-link.command.json').write_text(json.dumps(command, indent=2) + '\n')
    env = dict(os.environ, CROSS_CLANG=str(CLANG), DARWIN_TRIPLE='arm64e-apple-ios27.0',
               CROSS_EXTRA_FLAGS=PAC_FLAG, TMPDIR=str(out))
    env['PATH'] = str(CXX.parent) + ':' + env['PATH']
    with (out / 'native-link.log').open('x') as log:
        done = subprocess.run(command, cwd=OBJ, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=300)
    if done.returncode:
        raise RuntimeError((out / 'native-link.log').read_text()[-6500:])
    result = dict(native=str(out / 'native.macho'), native_sha256=sha(out / 'native.macho'),
                  compiled_objects=len(receipts), pac_flag=PAC_FLAG,
                  archive_sha256={name: sha(archives / name) for name in names.values()},
                    source_changes=bool(iig_compat) or args.sparse_recount or args.native_jop_policy or args.single_cluster_qos or args.vfs_shutdown_diagnostic,
                    native_source_changes=args.sparse_recount or args.native_jop_policy or args.single_cluster_qos or args.vfs_shutdown_diagnostic,
                    vfs_shutdown_diagnostic=args.vfs_shutdown_diagnostic,
                    usb_console=args.usb_console,
                    launchd_trace=args.launchd_trace,
                    launchd_transport=args.launchd_transport,
                    launchd_shutdown=args.launchd_shutdown,
                    display_source=display_source,
                    gpu_source=gpu_source,
                    boot_screen=boot_screen,
                    upstream_startup=args.upstream_startup,
                    audit_source_repairs=args.audit_source_repairs,
                    usb_sources={str(p): sha(p) for p in
                                 [*sorted((Path(__file__).resolve().parents[2] / 'drivers/QcomXnuUsbDebug').rglob('*.c')),
                                  *sorted((Path(__file__).resolve().parents[2] / 'drivers/QcomXnuUsbDebug').rglob('*.h')),
                                  Path(__file__).resolve().parents[2] / 'ci/usb/Pdx234.h',
                                  Path(__file__).resolve().parents[2] / 'ci/usb/PdxUsbWorker.c']} if args.usb_console else {},
                    single_cluster_qos=args.single_cluster_qos,
                    native_jop_policy=args.native_jop_policy,
                    recount_sparse_kind_span=args.sparse_recount,
                    native_source_patches=[{key: receipt[key] for key in
                                            ('source', 'source_sha256', 'original_source', 'original_source_sha256', 'native_source_patch')}
                                           for receipt in receipts if 'native_source_patch' in receipt],
                    generated_iig_compat=iig_compat,
                    generated_iig_objects=sum('generated_iig_compatibility' in receipt for receipt in receipts),
                    iig_source_adaptations=[{key: receipt[key] for key in
                                            ('source', 'source_sha256', 'original_source', 'original_source_sha256')}
                                           for receipt in receipts if 'generated_iig_compatibility' in receipt],
                    auth_instruction_patches=False, pac_authentication_retained=True,
                   baseline_lastdataconst_layout_retained=True,
                   generated_assym=first_json(out / 'generated-assym/result.json'),
                   reused_objects=sum('reused_from' in receipt for receipt in receipts),
                  runtime_qualified=False, device_operations=False)
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2), flush=True)


if __name__ == '__main__':
    main()
