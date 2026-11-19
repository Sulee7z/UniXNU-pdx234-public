#!/usr/bin/env python3
"""Build the CURRENT sheng27 storage/diagnostic runtime with Sony-only UFS.

Use original verified D27 policies. Copy sources, never old runtime objects.
No device operation and no fake definitions for missing native hooks.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

DEVICE = Path(__file__).resolve().parents[2]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--work', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--reuse-dependencies', action='store_true', help='Verify and retain this build own source-only dependency staging')
    args = p.parse_args()
    work = args.work.resolve()
    tree = work / 'UniXNU/out/pdx234/ios-27.0.1-24A446-iphone14/pdx234_sheng27_bulk/tree'
    core = work / 'UniXNU'
    sony_ufs = work / 'sony-current-ufs'
    if not (tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json').is_file():
        raise ValueError('Need full native27 compile records')
    args.out.mkdir(parents=True, exist_ok=False)
    out = args.out.resolve()
    staged = out / 'device'
    staged.mkdir()
    shutil.copytree(work / 'sheng/package', staged / 'package')
    # Current upstream declares/defines16 swipe counters but the logger reads
    # counter16. The producer has no such metric. Report its absence rather
    # than disabling array bounds diagnostics or inventing a zero-valued stat.
    # Sony runs without the GPU/display/touch/Data-IO diagnostic exporter.
    # Remove its only definition from this staged copy; BootLog's guard skips it.
    diag_export = staged / 'package/BootDiagExport.c'
    diag_removed = diag_export.exists()
    if diag_removed:
        (out / 'removed-diagnostics').mkdir(exist_ok=True)
        shutil.move(str(diag_export), str(out / 'removed-diagnostics' / 'BootDiagExport.c'))
    boot_log = staged / 'package/BootLog.c'
    before_log = boot_log.read_text()
    if before_log.count('[swipe2] heavy=%u.%03us') != 1:
        raise ValueError('Unexpected current swipe diagnostic')
    after_log = before_log.replace('[swipe2] heavy=%u.%03us', '[swipe2] heavy=n/a')
    after_log, count = re.subn(r'native_swipe_stats\[16\] / 1000,\s*native_swipe_stats\[16\] % 1000,\s*', '', after_log)
    if count != 1:
        raise ValueError('Unsupported swipe metric read was not uniquely identified')
    # Guard the export thread so it runs only when all of its probes exist.
    export_old = '  if (half && &native_ufs_export_write && (k.stage = (uint8_t *)IOMallocAligned(LogExportStage * LogBlock, LogBlock))) {'
    export_new = '  if (half && &native_ufs_export_write && &boot_diag_scan && &boot_diag_stream && (k.stage = (uint8_t *)IOMallocAligned(LogExportStage * LogBlock, LogBlock))) {'
    if after_log.count(export_new) == 1:
        pass  # already guarded (upstream copy was edited in place earlier); idempotent
    elif after_log.count(export_old) == 1:
        after_log = after_log.replace(export_old, export_new)
    else:
        raise ValueError('Unexpected export thread guard')
    boot_log.write_text(after_log)
    ignore = shutil.ignore_patterns('.git', 'build', 'out', '__pycache__')
    shutil.copytree(sony_ufs, staged / 'drivers/ShengUfs', ignore=ignore)
    spec = importlib.util.spec_from_file_location('sony_macho_asm', DEVICE / 'scripts/ci/macho-inline-asm.py')
    asm = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(asm)
    # Build source-only dependencies of the official archive in the target tree.
    additions = [('drivers/RamBlock', False), ('drivers/VirtioMmioBlock', True), ('kits/VerifiedRoot', True)]
    for relative, link in additions:
        destination, source = tree / relative, core / relative
        if destination.exists():
            if not args.reuse_dependencies:
                raise ValueError('Preserve existing dependency staging: ' + str(destination))
            if link:
                if not destination.is_symlink() or destination.resolve() != source.resolve():
                    raise ValueError('Dependency symlink changed')
            else:
                for path in source.rglob('*'):
                    if path.suffix not in ('.c', '.cpp', '.h') or '.git' in path.parts:
                        continue
                    expected, _ = asm.normalize(path.read_text())
                    actual = destination / path.relative_to(source)
                    if not actual.is_file() or actual.read_text() != expected:
                        raise ValueError('Existing dependency source changed: ' + str(actual))
            continue
        destination.parent.mkdir(exist_ok=True, parents=True)
        if link:
            destination.symlink_to(source, target_is_directory=True)
        else:
            shutil.copytree(source, destination, ignore=ignore)
    transformed = []
    for directory in [staged / 'package', staged / 'drivers/ShengUfs', tree / 'drivers/RamBlock']:
        for path in sorted(directory.rglob('*')):
            if path.suffix not in ('.c', '.cpp', '.h'):
                continue
            original = path.read_text()
            result, count = asm.normalize(original)
            if count:
                path.write_text(result)
                transformed.append(dict(path=str(path), before_sha256=hashlib.sha256(original.encode()).hexdigest(),
                                        after_sha256=sha(path), asm_separators_fixed=count))
    helper = out / 'build-current-storage.py'
    text = (tree / 'scripts/build-sheng-source-storage.py').read_text()
    text = text.replace('ROOT = Path(__file__).resolve().parents[1]', 'ROOT = Path(' + repr(str(tree)) + ')', 1)
    marker = "flags = ['-DNATIVE_UFS_SOURCE_API=1',"
    if text.count(marker) != 1:
        raise ValueError('Current official source-storage recipe changed')
    text = text.replace(marker, "flags = ['-DSONY_UFS_HEAP_SCRATCH=1', '-DNATIVE_UFS_SOURCE_API=1',", 1)
    # Sony has no GPU/display/touch/Data-IO diagnostic exporter, so the
    # diagnostic file export source is not compiled at all. Drop its
    # record-selection entry and make the source append conditional on the
    # producer actually existing; never register a stub or empty definition.
    bsd_old = "    bsd_sources = {'BootWatchdogPolicy.c', 'BootDiagExport.c', 'WifiFirmware.c'}\n"
    bsd_new = "    bsd_sources = {'BootWatchdogPolicy.c', 'WifiFirmware.c', 'SonyWeakDefaults.c'}\n"
    if text.count(bsd_old) != 1:
        raise ValueError('Unexpected official bsd_sources record selection: BootDiagExport.c is no longer a single entry')
    text = text.replace(bsd_old, bsd_new, 1)
    export_old = "        sources.append(device_source('BootDiagExport.c'))\n"
    export_new = ("        diag_export_source = device / 'package/BootDiagExport.c'\n"
                  "        if diag_export_source.is_file():\n"
                  "            sources.append(diag_export_source)\n")
    if text.count(export_old) != 1:
        raise ValueError('Unexpected official diagnostic export append: BootDiagExport.c is no longer a single entry')
    text = text.replace(export_old, export_new, 1)
    # Upstream weak_defaults() only sees declarations that start with 'extern '
    # and end with '__attribute__((weak_import));', so it silently skips the
    # multi-declarator weak imports in BootLog.c and every weak import of a
    # source that never gets a defaults file. Those are exactly the symbols the
    # kernel link left undefined after the diagnostic exporter was dropped, so
    # give them the same documented default the official mechanism gives the
    # rest: zero data, function reports absence. A real producer still wins.
    sony_weak = (
        ('Data IO', 'package/BootLog.c', 'native_data_io_reads', 'volatile uint64_t native_data_io_reads'),
        ('Data IO', 'package/BootLog.c', 'native_data_io_read_bytes', 'volatile uint64_t native_data_io_read_bytes'),
        ('Data IO', 'package/BootLog.c', 'native_data_io_read_ticks', 'volatile uint64_t native_data_io_read_ticks'),
        ('Data IO', 'package/BootLog.c', 'native_data_io_writes', 'volatile uint64_t native_data_io_writes'),
        ('Data IO', 'package/BootLog.c', 'native_data_io_write_bytes', 'volatile uint64_t native_data_io_write_bytes'),
        ('Data IO', 'package/BootLog.c', 'native_data_io_write_ticks', 'volatile uint64_t native_data_io_write_ticks'),
        ('Data IO', 'package/BootLog.c', 'native_data_io_gate_ticks', 'volatile uint64_t native_data_io_gate_ticks'),
        ('Data IO', 'package/BootLog.c', 'native_data_io_max_ticks', 'volatile uint64_t native_data_io_max_ticks'),
        ('Data IO', 'package/BootLog.c', 'native_data_flushes', 'volatile uint64_t native_data_flushes'),
        ('Data IO', 'package/BootLog.c', 'native_data_flush_ticks', 'volatile uint64_t native_data_flush_ticks'),
        ('Data IO', 'package/BootLog.c', 'native_data_flush_blocks', 'volatile uint64_t native_data_flush_blocks'),
        ('Data IO', 'package/BootLog.c', 'native_data_timer_flushes', 'volatile uint64_t native_data_timer_flushes'),
        ('4K signature', 'package/BootLog.c', 'cs_native4k_digest_wall', 'uint64_t cs_native4k_digest_wall[2]'),
        ('4K signature', 'package/BootLog.c', 'cs_native4k_digest_cpu', 'uint64_t cs_native4k_digest_cpu[2]'),
        ('4K signature', 'package/BootLog.c', 'cs_native4k_digest_bytes', 'uint64_t cs_native4k_digest_bytes[2]'),
        ('4K signature', 'package/BootLog.c', 'cs_native4k_chunk_ticks', 'uint64_t cs_native4k_chunk_ticks'),
        ('4K signature', 'package/BootLog.c', 'cs_native4k_record_ticks', 'uint64_t cs_native4k_record_ticks'),
        ('GPU', 'package/BootUiTraceProbe.c', 'native_gpu_role_thread', 'uint64_t native_gpu_role_thread(uint32_t,uint32_t)'),
        ('backtrace capture', 'osfmk/kern/exception.c', 'boot_cache_input_capture', 'void boot_cache_input_capture(user_addr_t, uint64_t)'),
    )
    exception_source = tree / '.cache/xnu-work/osfmk/kern/exception.c'
    if not exception_source.is_file():
        raise ValueError('Missing patched osfmk exception source')
    # The patched kernel source calls the removed exporter's capture only behind
    # an address guard, so a zero default is skipped at run time.
    exception_guard = 'if (&boot_cache_input_capture) boot_cache_input_capture((user_addr_t)data[4], data[5]);'
    exception_text = exception_source.read_text()
    if exception_text.count(exception_guard) != 1:
        raise ValueError('Patched exception source no longer guards the boot cache input capture call')
    weak_sources = {'package/BootLog.c': boot_log,
                    'package/BootUiTraceProbe.c': staged / 'package/BootUiTraceProbe.c',
                    'osfmk/kern/exception.c': exception_source}
    for _, relative, name, decl in sony_weak:
        source_text = weak_sources[relative].read_text()
        # A multi-declarator line carries the base type only on its first
        # declarator, so anchor on the declarator tail and then confirm the
        # statement really opens with the declared type.
        anchor = decl[decl.index(name):] + ' __attribute__((weak_import))'
        if source_text.count(anchor) != 1:
            raise ValueError('Weak import declaration changed: ' + decl)
        start = source_text.rfind('extern ', 0, source_text.index(anchor))
        end = source_text.index(';', source_text.index(anchor))
        statement = ' '.join(source_text[start:end].split())
        if not statement.startswith('extern ' + decl[:decl.index(name)].strip() + ' '):
            raise ValueError('Weak import type changed: ' + decl)
    # Never duplicate what the official generator already defaults.
    spec = importlib.util.spec_from_file_location('sheng_source_storage', tree / 'scripts/build-sheng-source-storage.py')
    upstream_storage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(upstream_storage)
    official_defaults = upstream_storage.weak_defaults(boot_log)
    for _, _, name, _ in sony_weak:
        if re.search(r'\b' + name + r'\s*(\[|;|\()', official_defaults):
            raise ValueError('Official weak defaults already define: ' + name)
    weak_path = out / 'SonyWeakDefaults.c'
    weak_lines = ['/* Sony: the documented weak-import defaults for the imports the official',
                  ' * weak_defaults() cannot see: multi-declarator extern lines in BootLog.c',
                  ' * and weak imports of sources that never get a defaults file',
                  ' * (BootUiTraceProbe.c, osfmk exception.c). Zero data, functions report',
                  ' * absence, hidden visibility, and a real producer still wins.',
                  ' * Generated by scripts/ci/build-sheng27-sony-source-storage.py. */',
                  '#include <kern/startup.h>',
                  '#include <machine/types.h>',
                  '',
                  '#pragma clang diagnostic ignored "-Wc23-extensions"',
                  '']
    for _, _, _, decl in sony_weak:
        if '(' in decl:
            body = ' { }' if decl.startswith('void ') else ' { return 0; }'
            weak_lines.append(f'__attribute__((weak, visibility("hidden"))) {decl}{body}')
        else:
            weak_lines.append(f'__attribute__((weak, visibility("hidden"))) {decl};')
    weak_path.write_text('\n'.join(weak_lines) + '\n')
    weak_append_old = "        sources.append(device_source('WifiFirmware.c'))\n"
    weak_append_new = weak_append_old + '        sources.append(Path(' + repr(str(weak_path)) + '))\n'
    if text.count(weak_append_old) != 1:
        raise ValueError('Unexpected official Wifi firmware append')
    text = text.replace(weak_append_old, weak_append_new, 1)
    helper.write_text(text)
    toolchain = Path('/root/unixnu-build/pdx234-pac-toolchain')
    clt = toolchain / 'CommandLineTools/usr'
    env = dict(os.environ, PATH='/root/unixnu-build/pdx234-pac-clang-build/bin:' + str(clt / 'bin') + ':' + str(toolchain / 'bin') + ':' + os.environ['PATH'],
               UNIXNU_XNU_ARCH='arm64e', UNIXNU_IOS_VERSION='27.0', UNIXNU_IPSW_BUILD='24A446',
               DARWIN_TRIPLE='arm64e-apple-ios27.0', CROSS_CLANG=str(toolchain / 'llvm/bin/clang-24'),
               CROSS_EXTRA_FLAGS='-mllvm -disable-atexit-based-global-dtor-lowering',
               CLT_PREFIX=str(clt), XCTOOLCHAIN_PREFIX=str(toolchain / 'XcodeDefault.xctoolchain/usr'),
               XNU_TOOLCHAIN_BIN=f'{clt / "bin"} {toolchain / "XcodeDefault.xctoolchain/usr/bin"}',
               CCC_OVERRIDE_OPTIONS='# +-Wno-missing-designated-field-initializers +-Wno-unused-but-set-global',
               UNIXNU_SDKROOT=str(tree / '.cache/fakeroot'), UNIXNU_SDK_VERSION='27.0', UNIXNU_SDK_BUILD='24A446',
               UNIXNU_IOSTORAGEFAMILY_COMMIT='7edb88fbae296fb7c8ce2f64e115e116e566d51c',
               UNIXNU_ROOT_OS_UUID='CA0FF65B-3E73-4D62-9000-EC719E1B6DB1',
               UNIXNU_ROOT_SYSTEMOS_UUID='79A22534-CAB8-4277-A9A7-C5B9656E6C0A',
               UNIXNU_ROOT_OS_SHA256='5371e392912dbc5f6f9677d4987c726e15fd7afc519b3644d8d6694777182ad5',
               UNIXNU_ROOT_SYSTEMOS_SHA256='34b6010eb6329ca1c942c374df1b157c40cfc36b1120b0c2ec811ea69ed3b686',
               XNU_SOURCE_STORAGE_TABLES='userdata', PYTHONDONTWRITEBYTECODE='1', TMPDIR=str(out))
    command = [sys.executable, '-B', str(helper), '--tree', str(tree), '--device', str(staged),
               '--policy-dir', str(DEVICE / 'out/d27-owner-policies-001')]
    plan = dict(command=command, tree=str(tree), source_device=str(staged), asm_normalizations=transformed,
                diagnostic_bounds_fix=dict(source='BootLog.c', producer_elements=16,
                                           unavailable_metric_index=16, displayed='heavy=n/a',
                                           before_sha256=hashlib.sha256(before_log.encode()).hexdigest(),
                                           after_sha256=sha(boot_log), bounds_warning_disabled=False),
                sony_weak_defaults=dict(
                    mechanism='upstream weak_defaults() convention, extended to multi-declarator weak imports',
                    source=str(weak_path), sha256=sha(weak_path),
                    symbols=[dict(name=name, category=category, declared_in=relative, declaration=decl)
                             for category, relative, name, decl in sony_weak],
                    exception_reference=dict(source=str(exception_source),
                                             sha256=hashlib.sha256(exception_text.encode()).hexdigest(),
                                             guarded=True, guard=exception_guard)),
                upstream_sheng='abfc15a6e05d36b616ad2d8a3b52fef960999a0e',
                upstream_ufs='57f031c99d7f69ffa611626bebaeab0731e93254', root_partition='unixnu',
                source_objects_reused=False, source_policy_tables_in_unixnu_required=True,
                device_operations=False, compiled=False)
    try:
        with (out / 'compile.log').open('w') as log:
            result = subprocess.run(command, cwd=tree, env=env, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError((out / 'compile.log').read_text(errors='replace')[-5500:])
        archive = tree / 'build/sheng-source-storage/libShengSourceStorage.a'
        report = json.loads((archive.parent / 'report.json').read_text())
        shutil.copyfile(archive, out / archive.name)
        shutil.copyfile(archive.parent / 'root-policies.bin', out / 'root-policies.headers.bin')
        plan.update(compiled=True, archive=str(out / archive.name), archive_sha256=sha(out / archive.name),
                    upstream_build_report=report, header_bundle_bytes=(out / 'root-policies.headers.bin').stat().st_size)
    except BaseException as error:
        plan['error'] = repr(error)
        raise
    finally:
        (out / 'report.json').write_text(json.dumps(plan, indent=2) + '\n')
    print(json.dumps(plan, indent=2), flush=True)


if __name__ == '__main__':
    main()
