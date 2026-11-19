#!/usr/bin/env python3
"""Resolve the complete pinned sheng iPadOS27 series into a fresh D27 Sony build.

No handset access, image writes, source-cache mutation, iPad OS assets or 17/26
overrides. Native build success alone is not a handset-ready prelinked kernel.
"""
import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import sys
import tomllib

DEVICE = Path(__file__).resolve().parents[2]
SHENG = 'abfc15a6e05d36b616ad2d8a3b52fef960999a0e'
CORE = '82b847c4ac3f68a57024b3082ffa3a03442defd9'
SOC = 'a9f45dc60c035084b95463781538380f4c3606c9'
PROFILE = 'ios-27.0.1-24A446-iphone14'
CONFIG = 'pdx234_sheng27_bulk_defconfig'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(command, cwd, log, env=None):
    with log.open('w') as stream:
        result = subprocess.run(list(map(str, command)), cwd=cwd, env=env,
                                stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f'exit{result.returncode}; {log}\n' + log.read_text(errors='replace')[-4000:])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--work', type=Path, required=True, help='Existing fresh checkout container')
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--jobs', type=int, default=6)
    p.add_argument('--resume-preparation', action='store_true', help='Resume only this owned, unbuilt staging tree')
    p.add_argument('--source-storage-archive', type=Path,
                   help='Enable the real Sony current source-storage/owner runtime with this freshly compiled archive')
    args = p.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    work = args.work.resolve()
    sheng = work / 'sheng'
    if subprocess.check_output(['git', '-C', str(sheng), 'rev-parse', 'HEAD'], text=True).strip() != SHENG:
        p.error('Require the explicitly frozen current sheng snapshot')
    if subprocess.check_output(['git', '-C', str(sheng), 'status', '--porcelain'], text=True).strip():
        p.error('Upstream sheng checkout must remain clean')
    args.out.mkdir(exist_ok=args.resume_preparation, parents=True)
    out = args.out.resolve()
    core, sony = work / 'UniXNU', work / 'sony'
    if not core.exists():
        run(['git', 'clone', '--shared', '/root/unixnu-build/sheng27-control-001/UniXNU', core],
            work, out / 'clone-core.log')
        run(['git', '-C', core, 'checkout', '--detach', CORE], work, out / 'checkout-core.log')
    elif not args.resume_preparation or subprocess.check_output(['git', '-C', str(core), 'rev-parse', 'HEAD'], text=True).strip() != CORE:
        raise ValueError('Refuse an unqualified pre-existing build checkout')
    # No historical source objects/overlays are copied. Sony config and identity
    # stay separate from the read-only upstream library/patch snapshot.
    if not sony.exists():
        sony.mkdir()
        for name in ('configs', 'dts', 'profiles'):
            shutil.copytree(DEVICE / name, sony / name)
        shutil.copyfile(DEVICE / 'feeds.toml', sony / 'feeds.toml')
        shutil.copytree(sheng / 'patches/xnu-12377', sony / 'patches/sheng27')
        shutil.copytree(sheng / 'package', sony / 'package')
    elif not args.resume_preparation:
        raise ValueError('Preserve existing Sony staging')
    profile_destination = core / 'profiles/os' / PROFILE
    if not profile_destination.exists():
        shutil.copytree(sony / 'profiles' / PROFILE, profile_destination)
    # The sheng kit is a source-library name, not a hardware identity. Do not
    # import its board, peripheral publication, firmware or payload arguments.
    board = f'''schema_version = 2
[board]
name = "pdx234"
soc = "SM8550"
soc_source = "sm8550"
os_profile = "{PROFILE}"
kit = "sheng"
description = "Sony D27 bulk sheng27 integration; intermediate native build, not a flash image"
[components]
include = ["ArmDTPlatform", "ArmCpu", "XnuPrelink", "DarwinBoot"]
[kernel]
defconfig = "{CONFIG}"
config_fragments = ["arch:configs/common.config", "os:configs/ios.config"]
patch_series = ["arch:patches/xnu/series", "soc:patches/xnu-12377/series", "os:patches/xnu/series", "device:patches/sheng27/series"]
archives = ["prepare-xnu-source.py", "build-corecrypto-14.py", "build-corecrypto-14.py --namespace", "component:ArmDTPlatform", "component:ArmCpu", "build-libpthread-kernel.py"]
[device_tree]
source = "device:dts/pdx234.dts"
include_dirs = ["soc:dts"]
[userdata]
first_lba = 45679360
last_lba = 62456575
lba_bytes = 4096
[payload]
volume = "PDX234XNU"
size_mib = 64
loader = "firmware"
title = "Sony D27 sheng27 integration candidate"
kernel_args = ["-v", "serial=3", "debug=0x14e", "native-ufs-root=0", "data-persist=0", "sheng-data-persist=0"]
[payload.adt]
root_match_volume_uuid = "CA0FF65B-3E73-4D62-9000-EC719E1B6DB1"
[adt.defaults.u32]
vmm-present = 1
[package]
unixnu = "../UniXNU"
[package.defconfig]
"{PROFILE}" = "{CONFIG}"
'''
    (sony / 'board.toml').write_text(board)
    config_text = (DEVICE / 'configs/pdx234_native27_probe_defconfig').read_text()
    if args.source_storage_archive:
        archive = args.source_storage_archive.resolve()
        if not archive.is_file():
            raise ValueError('Source storage archive is missing')
        receipt = json.loads((archive.parent / 'report.json').read_text())
        if not receipt.get('compiled') or receipt.get('archive_sha256') != sha(archive):
            raise ValueError('Need the actual current-source archive receipt')
        seed = json.loads((DEVICE / 'out/d27-data-linux-seed-002/seed.json').read_text())
        if seed.get('os_sha256') != '5371e392912dbc5f6f9677d4987c726e15fd7afc519b3644d8d6694777182ad5' or not seed.get('populated'):
            raise ValueError('D27 populated Data seed identity differs')
        owner_keys = ['XNU_SOURCE_STORAGE', 'XNU_OWNER_ROOT_AUDIT', 'XNU_OWNER_ROOT_TRUST',
                      'XNU_NATIVE_UFS', 'XNU_NATIVE_RAM_BLOCK', 'XNU_OWNER_CACHE_MOUNT',
                      'XNU_OWNER_CACHE_STARTUP', 'XNU_OWNER_BOOT_MANIFEST', 'XNU_OWNER_DATA_MOUNT',
                      'XNU_OWNER_UNION_SYSTEMOS']
        config_text = '\n'.join(line for line in config_text.splitlines()
                                if not any(line.startswith(('CONFIG_' + key + '=', '# CONFIG_' + key + ' is not set')) for key in owner_keys)) + '\n'
        config_text += ''.join('CONFIG_' + key + '=y\n' for key in owner_keys)
        config_text += 'CONFIG_XNU_OWNER_DATA_VOLUME_UUID="' + seed['volume_uuid'] + '"\n'
        config_text += 'CONFIG_XNU_SOURCE_STORAGE_TABLES="userdata"\n'
        # build-xnu-4k-baseline.sh already force-loads ROOT/build/sheng-ufs/libShengUfs.a
        # when XNU_NATIVE_UFS=1 (~line 639). Adding the same archive again would
        # duplicate every symbol, so the catalog path is verified after the tree
        # is assembled instead of adding CONFIG_XNU_EXTRA_LD_ARCHIVES.
    (sony / 'configs' / CONFIG).write_text(config_text)
    profile = tomllib.loads((sony / 'profiles' / PROFILE / 'profile.toml').read_text())
    if (profile['ipsw']['product'], profile['ipsw']['device_class'], profile['ipsw']['build']) != ('iPhone14,7', 'd27ap', '24A446'):
        raise ValueError('D27 original identity changed')
    old = json.loads((DEVICE / 'out/d27-official-ios27-control-001/experiment-plan.json').read_text())
    local_args = []
    for entry in old['immutable_source_cache']:
        source = Path(entry['path'])
        actual = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
        if actual != entry['revision']:
            raise ValueError('Reference source changed: ' + entry['name'])
        local_args += ['--local-module', f'refer:{entry["name"]}={source}']
    # Reuse only the clean pinned SoC repository, not any former build objects.
    status = json.loads((DEVICE / 'out/d27-official-ios27-control-001/official-status.json').read_text())
    soc = Path(status['profiles']['soc'])
    if subprocess.check_output(['git', '-C', str(soc), 'rev-parse', 'HEAD'], text=True).strip() != SOC:
        raise ValueError('SM8550 source pin differs')
    local_args += ['--local-module', f'soc:sm8550={soc}']
    common = ['-D', str(sony), '--os', PROFILE, '-j', str(args.jobs), *local_args]
    env = dict(os.environ, UNIXNU_TOOLCHAIN='/root/unixnu-build/pdx234-pac-toolchain',
               PYTHONDONTWRITEBYTECODE='1', TMPDIR=str(work), ZERO_AR_DATE='1')
    # A local-module path overrides transport, not the selected source version.
    # Preserve ALL verified reference pins so no legacy default is selected by
    # an archive recipe after resolution of a local source cache.
    prefixes = {'xnu': 'XNU', 'libplatform': 'LIBPLATFORM', 'libdispatch': 'LIBDISPATCH',
                'AvailabilityVersions': 'AVAILABILITYVERSIONS', 'libpthread': 'LIBPTHREAD',
                'IOStorageFamily': 'IOSTORAGEFAMILY', 'IOHIDFamily': 'IOHIDFAMILY',
                'corecrypto-2023': 'CORECRYPTO'}
    for entry in old['immutable_source_cache']:
        if entry['name'] in prefixes:
            env['UNIXNU_' + prefixes[entry['name']] + '_COMMIT'] = entry['revision']
    warnings = '-Wno-reserved-identifier -Wno-pre-c11-compat -Wno-missing-designated-field-initializers -Wno-suggest-override -Wno-unnecessary-virtual-specifier -Wno-suggest-destructor-override -Wno-ms-bitfield-padding'
    # LSE is supported across Sony SM8550's A510/A715/X3 cores. Keep Apple's
    # legacy ARM8.2 spelling consistent with the compiler's actual instruction set.
    env['XNU_EXTRA_CFLAGS'] = warnings + ' -march=armv8.2-a+lse -D__ARM_ARCH_8_2__=1'
    run(['./unixnu', 'defconfig', CONFIG, *common], core, out / 'defconfig.log', env)
    os.chdir(core)
    os.environ.update(env)
    sys.path.insert(0, str(core / 'scripts'))
    cli = importlib.import_module('unixnu.cli')
    kernel = importlib.import_module('unixnu.kernel')
    patches = importlib.import_module('unixnu.patches')
    original_linux_env = kernel.linux_env
    def d27_linux_env(ctx):
        values = original_linux_env(ctx)
        values.update(DARWIN_TRIPLE='arm64e-apple-ios27.0', UNIXNU_SDK_VERSION='27.0',
                      UNIXNU_SDK_BUILD='24A446')
        return values
    kernel.linux_env = d27_linux_env
    # Local-module overrides retain exact checked commits but may lack feed
    # metadata. Keep the storage header verifier pinned to D27's actual source.
    os.environ['UNIXNU_IOSTORAGEFAMILY_COMMIT'] = '7edb88fbae296fb7c8ce2f64e115e116e566d51c'
    context = cli.Context(cli.parser().parse_args(['tree', *common]))
    modules = cli.prepare(context, ['kernel'])
    patch_list = patches.prepare(context, modules)
    patch_paths = [Path(line) for line in patch_list.read_text().splitlines() if line.strip()]
    resolved = []
    for i, path in enumerate(patch_paths):
        resolved.append(dict(index=i, path=str(path), sha256=sha(path)))
    audited = json.loads((DEVICE / 'out/d27-official-ios27-control-001/resolved-patches.json').read_text())
    if [row['sha256'] for row in resolved] != [row['sha256'] for row in audited]:
        raise ValueError('Resolved patches differ from the complete audited89-patch iPadOS27 sequence')
    (out / 'resolved-patches.json').write_text(json.dumps(resolved, indent=2) + '\n')
    native_source = context.tree / '.cache/xnu-work'
    sony_overlays = []
    for name in ('ios27-strict5-native-kpi.patch', 'ios27-d27-sanitizer-state.patch', 'ios27-sheng-stack-alignment.patch'):
        path = DEVICE / 'patches/xnu' / name
        checked = subprocess.run(['git', '-C', str(native_source), 'apply', '--check', str(path)], capture_output=True)
        sony_overlays.append(dict(name=name, sha256=sha(path), cleanly_applicable=checked.returncode == 0,
                                  diagnostic=checked.stderr.decode(errors='replace'), applied=False))
    (out / 'd27-overlay-review.json').write_text(json.dumps(sony_overlays, indent=2) + '\n')
    overlay_receipt = work / 'd27-bulk-overlays'
    if not overlay_receipt.exists():
        run([sys.executable, '-B', DEVICE / 'scripts/ci/rebase-d27-sheng27-overlays.py',
             '--source', native_source, '--out', overlay_receipt, '--apply'],
            work, out / 'apply-d27-overlays.log', dict(os.environ))
    elif not json.loads((overlay_receipt / 'report.json').read_text()).get('applied'):
        raise ValueError('Existing D27 overlay receipt is not applied')
    # Upstream's Linux compiler-rt helper hardcodes arm64/iOS17. Parameterize
    # that host-only recipe in this OWNED staging checkout; never use an arm64
    # archive whose arm64e objects the linker ignores.
    rt_helper = core / 'scripts/linux/prepare-xnu.py'
    rt_text = rt_helper.read_text()
    rt_old = "['xcrun', 'clang', '-target', 'arm64-apple-ios17.0', '-arch', 'arm64', '-isysroot', FAKEROOT,"
    rt_new = "['xcrun', 'clang', '-target', os.environ['DARWIN_TRIPLE'], '-arch', os.environ['UNIXNU_XNU_ARCH'], '-isysroot', FAKEROOT,"
    if rt_old in rt_text:
        if rt_text.count(rt_old) != 1:
            raise ValueError('Linux compiler-rt recipe is ambiguous')
        rt_text = rt_text.replace('import shutil\n', 'import shutil\nimport os\n', 1).replace(rt_old, rt_new)
        rt_helper.write_text(rt_text)
        rt_archive = context.tree / '.cache/fakeroot/usr/local/lib/kernel/libcc_kext.a'
        if rt_archive.exists():
            rt_archive.rename(rt_archive.with_name('libcc_kext.bootstrap-arm64.a'))
    elif rt_new not in rt_text:
        raise ValueError('Unexpected Linux compiler-rt source recipe')
    (out / 'linux-compiler-rt-helper.py').write_text(rt_text)
    catalog_archive = context.tree / 'build/sheng-ufs/libShengUfs.a'
    if args.source_storage_archive:
        if not catalog_archive.is_file():
            raise ValueError('Storage archive was not published to the catalog path; run the storage build first')
        if sha(catalog_archive) != sha(args.source_storage_archive.resolve()):
            raise ValueError('Catalog storage archive differs from the reviewed archive')
    plan = dict(sheng=SHENG, UniXNU=CORE, sm8550=SOC, profile=PROFILE,
                source_route='complete sheng iPadOS27 resolved series', patch_count=len(resolved),
                tree=str(context.tree), device=str(sony), kernelcache_sha256=profile['kernel']['prelink']['kernelcache_sha256'],
                original_target='D27 iPhone14,7 24A446', ipad_os_assets_used=False,
                legacy17_26_overrides_used=False, macos_overrides_used=False,
                package_sources_snapshot=SHENG, sony_hardware_inputs_retained=True,
                cpu_compiler_flags='-march=armv8.2-a+lse -D__ARM_ARCH_8_2__=1',
                historical_objects_imported=False, source_overlays_applied=True,
                compiler_rt_target='arm64e-apple-ios27.0', sdk_shim_version='27.0',
                d27_storage_header_commit='7edb88fbae296fb7c8ce2f64e115e116e566d51c',
                owner_runtime_enabled=bool(args.source_storage_archive),
                source_storage_archive=str(args.source_storage_archive) if args.source_storage_archive else None,
                root_policy_tables_in_unixnu_required=bool(args.source_storage_archive),
                catalog_storage_archive=str(catalog_archive) if args.source_storage_archive else None,
                duplicate_force_load_avoided=True,
                native_exit=None, handset_ready=False, device_operations=False)
    (out / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    print('FULL PATCH SERIES APPLIED:', len(resolved), 'D27 source build:', context.tree, flush=True)
    try:
        # Refresh compile records BEFORE replay-based archive builders. The
        # original Linux SDK17 shim's records otherwise override iOS27 flags.
        native_env = dict(os.environ)
        native_env.update(kernel.linux_env(context))
        native_env.update(kernel.xnu_env(context))
        native_env.update(kernel.version_env(modules, context))
        native_env.update(XNU_BOOTSTRAP='1', XNU_BOOT_PROGRESS='0', JOBS=str(args.jobs),
                          UNIXNU_PATCH_LIST=str(patch_list),
                          UNIXNU_GENERATED_DIR=str(context.tree / 'build/generated'))
        with (out / 'native-27-records.log').open('w') as log:
            first = subprocess.run(['bash', str(context.tree / 'scripts/build-xnu-4k-baseline.sh')],
                                   cwd=context.tree, env=native_env, stdout=log, stderr=subprocess.STDOUT)
        plan['bootstrap_27_records_exit'] = first.returncode
        recipe_path = context.tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json'
        recipe = json.JSONDecoder().raw_decode(recipe_path.read_text())[0]
        targets = [value for value in recipe['arguments'] if value.startswith('--target=')]
        if not targets or 'arm64e-apple-ios27.' not in targets[-1]:
            raise ValueError('Replay recipe still targets a legacy SDK: ' + repr(targets))
        plan['native_recipe_target'] = targets[-1]
        # Drive the real ordered shared build. Do not prelink or publish a native
        # executable as a bootable kernel; D27 overlays/driver binding follow.
        kernel.build(context, modules)
        native = context.tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/mach.development.bcm2837.unstripped.noctf'
        plan.update(native_exit=0, native=str(native), native_sha256=sha(native))
    except BaseException as error:
        plan.update(native_exit=1, error=repr(error))
        raise
    finally:
        (out / 'build-result.json').write_text(json.dumps(plan, indent=2) + '\n')
    print(json.dumps(plan, indent=2), flush=True)


if __name__ == '__main__':
    main()
