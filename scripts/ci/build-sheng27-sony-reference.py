#!/usr/bin/env python3
"""Build the pinned iOS27 RELEASE/LTO naming reference; never replace native XNU."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

DEVICE = Path(__file__).resolve().parents[2]
CORE = '82b847c4ac3f68a57024b3082ffa3a03442defd9'
RECIPE_SHA = 'ee76b6ee880bac51c05527b4a5cd44f6a4976a5237d91153799aef1ee2dff461'
TARGET = 'arm64e-apple-ios27.0'
# This ISA supports both scheduler CAS and the DIT assembly in cswitch.s.
# The Apple-only version macros must describe the real assembler target too.
MARCH = 'armv8.5-a+lse'
FEATURE_FLAGS = ('-fptrauth-function-pointer-type-discrimination '
                 '-mllvm -disable-atexit-based-global-dtor-lowering '
                 '-march=' + MARCH + ' ' +
                 ' '.join('-D__ARM_ARCH_8_' + str(n) + '__=1' for n in range(2, 6)))
TOOLCHAIN = Path('/root/unixnu-build/pdx234-pac-toolchain')
CLANG = TOOLCHAIN / 'llvm/bin/clang-24'
NM = Path('/root/unixnu-build/pdx234-pac-clang-build/bin/llvm-nm')
LINKER = Path('/root/unixnu-build/pdx234-lto-linker/install/bin/ld')
WRAPPER = DEVICE / 'scripts/ci/local-lto-link.sh'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def adapt_recipe(text, host_arguments, storage_archive, sanitizer_runtime=None):
    """Fail closed on a changed recipe; adapt only a private copy of the pin."""
    def replace(before, after):
        nonlocal text
        if text.count(before) != 1:
            raise ValueError('Reference recipe changed: ' + before[:90])
        text = text.replace(before, after, 1)

    replace('    inputs = {',
            '    forced.append(Path(' + repr(str(storage_archive)) + '))\n    inputs = {')
    replace("        f'CFLAGS_EXTRA={flags}',",
            "        f'CFLAGS_EXTRA={flags} -march=" + MARCH + " -DXNU_NATIVE_CS_HASH_CACHE=1',")
    if sanitizer_runtime is not None:
        # The UFS archive is byte-identical to the running native archive and
        # was built with signed-overflow instrumentation. Use its real XNU
        # minimal UBSan runtime. XNU_EXTERNAL_KERNEL_ARCHIVES adds the object
        # to nonltolink.filelist; adding it to LD_KERNEL_ARCHIVES as well would
        # load it twice. This is the pinned recipe's existing archive interface.
        replace("        'XNU_EXTERNAL_KERNEL_ARCHIVES='+' '.join(map(str,archives+forced)),",
                "        'XNU_EXTERNAL_KERNEL_ARCHIVES='+' '.join(map(str,archives+forced+[Path(" +
                repr(str(sanitizer_runtime)) + ")])),")
    replace("        f'OBJROOT={output}/{mode}-obj',f'SYMROOT={output}/{mode}-sym',f'DSTROOT={output}/{mode}-dst']",
            "        f'OBJROOT={output}/{mode}-obj',f'SYMROOT={output}/{mode}-sym',f'DSTROOT={output}/{mode}-dst', *" +
            repr(list(host_arguments)) + ']')
    # Include the target and linker selection in the cache key. XNU_* alone
    # does not capture the Linux shim's DARWIN_TRIPLE/CROSS_* defaults.
    replace("        'versions': {", "        'host_arguments': " + repr(list(host_arguments)) + ",\n"
            "        'host_environment': {name: os.environ.get(name) for name in "
            "('DARWIN_TRIPLE', 'CROSS_CLANG', 'CROSS_EXTRA_FLAGS', 'UNIXNU_LOCAL_LD')},\n"
            "        'versions': {")
    start = text.index('    if stub_names:\n')
    end = text.index('    # Forced exports', start)
    text = (text[:start] + "    if stub_names:\n"
            "        raise RuntimeError('Reference is missing real source hooks: ' + repr(stub_names))\n" + text[end:])
    replace("    objects = linked_objects(output / f'{mode}-obj/RELEASE_ARM64_BCM2837', options.lto)",
            "    linked_dir = output / f'{mode}-obj/RELEASE_ARM64_BCM2837'\n"
            "    if options.lto and (not (linked_dir / 'nonltolink.filelist').is_file() or\n"
            "                        not (linked_dir / 'justlto.o').exists()):\n"
            "        raise RuntimeError(f'LTO did not emit its object; inspect {output / (mode + \"-build.log\") }')\n"
            "    objects = linked_objects(linked_dir, options.lto)")
    replace("        listed = subprocess.run(['xcrun', 'nm', '-gUj', *objects[i:i + 100]], capture_output=True, text=True, check=True)",
            "        listed = subprocess.run(['xcrun', 'nm', '-gUj', *objects[i:i + 100]], capture_output=True, text=True)\n"
            "        if listed.returncode:\n"
            "            raise RuntimeError('Reference symbol reader failed: ' + listed.stderr)")
    # The reference uses the same supported ISA for PAN objects; otherwise a
    # later per-object v8.1 flag contradicts the shim's DIT version macros.
    text = text.replace('-march=armv8.1-a', '-march=' + MARCH)
    ast.parse(text)
    return text


def run_checked(argv, *, env, cwd, timeout=120):
    result = subprocess.run(list(map(str, argv)), cwd=cwd, env=env,
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'exit {result.returncode}: {argv[0]}\n' + result.stderr[-5000:])
    return result


def macho_identity(path, expected_kind):
    data = path.read_bytes()
    if len(data) < 32:
        raise ValueError('Truncated Mach-O: ' + str(path))
    magic, cpu, subtype, kind, count, command_bytes = struct.unpack_from('<6I', data)
    if (magic, cpu, subtype & 0xff, kind) != (0xfeedfacf, 0x100000c, 2, expected_kind):
        raise ValueError('Not the expected arm64e Mach-O: ' + str(path))
    end = 32 + command_bytes
    if end > len(data):
        raise ValueError('Truncated Mach-O commands')
    at = 32
    platforms = []
    for _ in range(count):
        if at + 8 > end:
            raise ValueError('Truncated load command')
        command, size = struct.unpack_from('<2I', data, at)
        if size < 8 or at + size > end:
            raise ValueError('Invalid load command size')
        if command == 0x32 and size >= 24:  # LC_BUILD_VERSION
            platforms.append(struct.unpack_from('<I', data, at + 8)[0])
        elif command == 0x25:  # LC_VERSION_MIN_IPHONEOS
            platforms.append(2)
        elif command == 0x24:  # LC_VERSION_MIN_MACOSX
            platforms.append(1)
        at += size
    if platforms != [2]:
        raise ValueError('Mach-O platform is not uniquely iOS: ' + repr(platforms))
    return dict(cpu=cpu, subtype=subtype, kind=kind, platforms=platforms)


def preflight(out, tree, env):
    """Test the actual shim and linker path, not just a direct clang invocation."""
    audit = {}
    for tool in ('clang', 'clang++', 'nm'):
        selected = run_checked(['xcrun', '-find', tool], env=env, cwd=tree).stdout.strip()
        audit[tool] = dict(path=selected, resolved=str(Path(selected).resolve()))
    if Path(audit['nm']['path']).resolve() != NM.resolve():
        raise ValueError('xcrun selected an unqualified symbol reader')
    install = shutil.which('install', path=env['PATH'])
    expected_install = TOOLCHAIN / 'CommandLineTools/usr/bin/install'
    if install is None or Path(install).resolve() != expected_install.resolve():
        raise ValueError('PATH did not select the Linux BSD-install adapter')
    audit['install'] = dict(path=install, resolved=str(Path(install).resolve()))
    source = out / 'lto-smoke.c'
    source.write_text('int sony_reference_lto_smoke(int x) { return x + 1; }\n'
                      'void sony_reference_dit(unsigned long v) { __asm__ volatile("msr DIT, %0" :: "r"(v)); }\n'
                      'unsigned long sony_reference_cas(unsigned long *p, unsigned long old, unsigned long v) '
                      '{ __asm__ volatile("cas %0, %2, [%1]" : "+r"(old) : "r"(p), "r"(v) : "memory"); return old; }\n')
    anchor = out / 'lto-smoke-anchor.c'
    anchor.write_text('int sony_reference_nonlto_anchor;\n')
    bitcode = out / 'lto-smoke.bc'
    anchor_obj = out / 'lto-smoke-anchor.o'
    mach = out / 'lto-smoke.o'
    compile_cmd = [audit['clang']['path'], '-arch', 'arm64e', '-flto',
                   '-ffreestanding', '-fno-stack-protector', '-c', str(source), '-o', str(bitcode)]
    anchor_cmd = [audit['clang']['path'], '-arch', 'arm64e', '-ffreestanding',
                  '-c', str(anchor), '-o', str(anchor_obj)]
    link_cmd = ['bash', str(WRAPPER), '-arch', 'arm64e', '-r', str(anchor_obj),
                '-filelist', str(out / 'smoke.filelist'), '-miphoneos-version-min=27.0',
                '-Wl,-mllvm,-inline-threshold=100', '-Wl,-object_path_lto,' + str(mach),
                '-o', str(out / 'lto-smoke.linked.o')]
    run_checked(compile_cmd, env=env, cwd=out)
    run_checked(anchor_cmd, env=env, cwd=out)
    (out / 'smoke.filelist').write_text(str(bitcode) + '\n')
    linked = run_checked(link_cmd, env=env, cwd=out)
    (out / 'lto-smoke.log').write_text(linked.stdout + linked.stderr)
    if 'ignoring file' in linked.stderr:
        raise ValueError('LTO linker ignored an input')
    if bitcode.read_bytes()[:4] != bytes.fromhex('dec0170b'):
        raise ValueError('Compiler did not emit LLVM bitcode')
    identity = macho_identity(mach, 1)
    symbols = run_checked(['xcrun', 'nm', '-gUj', str(mach)], env=env, cwd=out).stdout.split()
    for required in ('_sony_reference_lto_smoke', '_sony_reference_dit', '_sony_reference_cas'):
        if required not in symbols:
            raise ValueError('LTO result lost ' + required)
    audit.update(compile_command=compile_cmd, anchor_command=anchor_cmd,
                 link_command=link_cmd, lto_object_sha256=sha(mach), identity=identity, passed=True)
    write_json(out / 'toolchain-preflight.json', audit)
    return audit


def audit_compile_records(build):
    records = []
    wrong = []
    for path in sorted((build / 'lto-obj/RELEASE_ARM64_BCM2837').rglob('*.json')):
        if not path.name.endswith(('.o.json', '.cpo.json')):
            continue
        record = json.JSONDecoder().raw_decode(path.read_text())[0]
        args = record['arguments']
        targets = [a.split('=', 1)[1] for a in args if a.startswith('--target=')]
        row = dict(record=str(path), targets=targets, file=record['file'])
        records.append(row)
        if not targets or not targets[-1].startswith(TARGET):
            wrong.append(row)
    if not records or wrong:
        raise ValueError('Invalid iOS27 compile records: ' + repr(wrong[:5]))
    return dict(count=len(records), wrong_targets=wrong, records=records)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path, help='new evidence directory')
    parser.add_argument('--core', type=Path, default=Path('/root/unixnu-build/sheng27-control-001/UniXNU'))
    parser.add_argument('--preflight-only', action='store_true')
    parser.add_argument('--jobs', type=int, default=8)
    options = parser.parse_args()
    if options.jobs < 1:
        parser.error('--jobs must be positive')
    tree = options.tree.resolve()
    out = options.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    native = tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/mach.development.bcm2837.unstripped.noctf'
    storage = tree / 'build/sheng-ufs/libShengUfs.a'
    protected = [native, storage]
    sanitizer_runtime = tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/san/DEVELOPMENT/ubsan_minimal.o'
    protected.append(sanitizer_runtime)
    baseline = {str(p): sha(p) for p in protected}
    report = dict(native=str(native), native_sha256=baseline[str(native)],
                  storage_archive=str(storage), storage_archive_sha256=baseline[str(storage)],
                  sanitizer_runtime=str(sanitizer_runtime), sanitizer_runtime_sha256=baseline[str(sanitizer_runtime)],
                  mode='RELEASE/LTO naming reference only', built=False,
                  device_operations=False, native_replaced=False)
    write_json(out / 'report.json', report)
    try:
        recipe = subprocess.check_output(['git', '-C', str(options.core), 'show',
                                          CORE + ':scripts/build-fileset-release-reference.py']).decode()
        if hashlib.sha256(recipe.encode()).hexdigest() != RECIPE_SHA:
            raise ValueError('Pinned recipe digest changed')
        sdk = tree / '.cache/fakeroot'
        tools = out / 'host-tools'
        tools.mkdir()
        (tools / 'nm').symlink_to(NM)
        clt = TOOLCHAIN / 'CommandLineTools/usr/bin'
        env = dict(os.environ)
        env.update(CROSS_CLANG=str(CLANG), DARWIN_TRIPLE=TARGET, CROSS_EXTRA_FLAGS=FEATURE_FLAGS,
                   UNIXNU_LOCAL_CLANGXX=str(clt / 'clang++'), UNIXNU_LOCAL_LD=str(LINKER),
                   UNIXNU_XNU_ARCH='arm64e', UNIXNU_IOS_VERSION='27.0',
                   UNIXNU_XNU_DARWIN='25.5.0', UNIXNU_XNU_VERSION='12377.121.6',
                   UNIXNU_SDKROOT=str(sdk), UNIXNU_SDK_VERSION='27.0', UNIXNU_SDK_BUILD='24A446',
                   UNIXNU_PLATFORM_PATH=str(sdk / 'Platforms/iPhoneOS.platform'), PLATFORM='iPhoneOS',
                   KERNEL_SDKROOT=str(sdk), XNU_AVAILABILITY_PL=str(sdk / 'usr/local/libexec/availability.pl'),
                   XNU_TOOLCHAIN_BIN=f'{tools} {clt} {TOOLCHAIN}/XcodeDefault.xctoolchain/usr/bin',
                   PYTHONDONTWRITEBYTECODE='1', ZERO_AR_DATE='1',
                   LD_LIBRARY_PATH='/root/unixnu-build/pdx234-pac-clang-build/lib:' + env.get('LD_LIBRARY_PATH', ''))
        env.update(PATH=os.pathsep.join([str(clt), str(TOOLCHAIN / 'bin'), env.get('PATH', '')]),
                   LC_ALL='C', CLT_PREFIX=str(TOOLCHAIN / 'CommandLineTools/usr'),
                   XCTOOLCHAIN_PREFIX=str(TOOLCHAIN / 'XcodeDefault.xctoolchain/usr'),
                   CCC_OVERRIDE_OPTIONS='# +-Wno-missing-designated-field-initializers +-Wno-unused-but-set-global')
        host = ['TIGHTBEAMC=tightbeamc-not-supported', 'BUILD_DSYM=0',
                'MEMORY_SIZE=' + str(os.sysconf('SC_PHYS_PAGES') * os.sysconf('SC_PAGE_SIZE')),
                'SYSCTL_HW_PHYSICALCPU=' + str(os.cpu_count()), 'SYSCTL_HW_LOGICALCPU=' + str(os.cpu_count()),
                'PLATFORM=iPhoneOS', 'HOST_CC=' + str(clt / 'xnu-host-cc'),
                'MIGCOM=' + str(TOOLCHAIN / 'CommandLineTools/usr/libexec/migcom'),
                'LD=' + str(WRAPPER), 'LD_KERNEL_LIBS=' + str(sdk / 'usr/local/lib/kernel/libcc_kext.a'),
                'MAKEJOBS=-j' + str(options.jobs)]
        report.update(environment={k: env[k] for k in ('DARWIN_TRIPLE', 'CROSS_CLANG', 'CROSS_EXTRA_FLAGS',
                      'UNIXNU_LOCAL_LD', 'UNIXNU_LOCAL_CLANGXX', 'XNU_TOOLCHAIN_BIN', 'LD_LIBRARY_PATH', 'PATH')},
                      make_host_arguments=host, pinned_recipe_sha256=RECIPE_SHA)
        report['preflight'] = preflight(out, tree, env)
        if not options.preflight_only:
            # /root's sparse VHDX is backed by G:, so its Linux df is misleading.
            free = shutil.disk_usage(DEVICE).free
            report['backing_drive_free_bytes'] = free
            if free < 2 * 1024 ** 3:
                raise ValueError('Less than 2 GiB free on the VHDX backing drive')
            adapted = out / 'build-reference-adapted.py'
            adapted.write_text(adapt_recipe(recipe, host, storage, sanitizer_runtime))
            report.update(recipe=str(adapted), recipe_sha256=sha(adapted))
            command = [sys.executable, '-B', str(adapted), '--tree', str(tree), '--lto']
            report['command'] = command
            write_json(out / 'report.json', report)
            with (out / 'reference-build.log').open('w') as log:
                result = subprocess.run(command, cwd=tree, env=env, stdout=log, stderr=subprocess.STDOUT)
            report['exit'] = result.returncode
            if result.returncode:
                raise RuntimeError((out / 'reference-build.log').read_text()[-6000:])
            final = tree / 'build/xnu/fileset-reference/mach.release.bcm2837.unstripped.noctf'
            saved = json.loads(final.with_suffix('.json').read_text())
            if saved['inputs']['mode'] != 'lto' or saved['sha256'] != sha(final):
                raise ValueError('Invalid reference build receipt')
            build = Path(saved['build'])
            audit = audit_compile_records(build)
            write_json(out / 'compile-record-audit.json', audit)
            report.update(reference=str(final), reference_sha256=sha(final), build=str(build),
                          identity=macho_identity(final, 2), compile_record_count=audit['count'], built=True)
    except (Exception, KeyboardInterrupt) as error:
        report.update(error=repr(error), built=False)
    finally:
        after = {str(p): sha(p) for p in protected}
        report['protected_inputs_unchanged'] = baseline == after
        if baseline != after:
            report.update(built=False, error='Protected native/storage input changed during build')
        write_json(out / 'report.json', report)
    print(json.dumps(report, indent=2), flush=True)
    return 1 if 'error' in report else 0


if __name__ == '__main__':
    raise SystemExit(main())
