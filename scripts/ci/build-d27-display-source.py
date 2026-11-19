#!/usr/bin/env python3
"""Compile sheng27 GOP/KeyStore sources using verified D27 bindings and PAC recipes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import io
import tarfile
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'ci'))
import sony_display_overlay

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
TREE=BASE/'sources/UniXNU/out/pdx234/ios-27.0.1-24A446-iphone14/pdx234_sheng27_bulk/tree'
CORE=BASE/'sources/UniXNU'
SHENG=BASE/'sources/sheng'
MODULES=Path('/root/unixnu-build/sheng27-sony-bulk-20261111-001/UniXNU')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--bindings',type=Path,required=True)
    p.add_argument('--gop-revision',default='b0d812d578efa2acb005b66f73168891719af09a',help='Upstream GOP revision matching current sheng diagnostic fields')
    p.add_argument('--boot-screen',action='store_true',help='Link the actual upstream boot screen instead of no-animation support')
    p.add_argument('--matching-report',action='store_true',help='Retain upstream IOKit busy-service/matching-thread reporting')
    p.add_argument('--sony-cpufreq',action='store_true',help='Include sheng EPSS governor after Sony DT resource checks')
    a=p.parse_args()
    out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    cpufreq_inputs=None
    if a.sony_cpufreq:
        live=Path('/mnt/g/UniXNU-Port/evidence/Xperia-XQ-DQ72/20261110T051320Z/live.dtb')
        if sha(live)!='90c943fdb63ace5b5421f3ad1eaa98d72681a1bd2f4c73a0fc10429360aa1290':raise ValueError('Sony DT changed')
        def cells(node,prop):
            return [int(x,16) for x in subprocess.check_output(['fdtget','-t','x',str(live),node,prop],text=True).split()]
        assert cells('/soc/qcom,cpufreq-hw','reg')==[0x17d91000,0x1000,0x17d92000,0x1000,0x17d93000,0x1000]
        assert cells('/soc/qcom,dcvs/l3','reg')==[0x17d90000,0x4000,0x17d90100,0xa0]
        assert cells('/soc/qcom,dcvs/l3/sp','qcom,shared-offset')==[0x90]
        phandle=cells('/soc/qcom,cpufreq-hw','phandle')[0]
        domains=[cells(f'/cpus/cpu@{i*256:x}','qcom,freq-domain') for i in range(8)]
        assert domains==[[phandle,d] for d in [0,0,0,1,1,1,1,2]]
        cpufreq_inputs=dict(live_dtb_sha256=sha(live),domains=domains,source='unchanged sheng CpuFreqProbe.cpp',runtime_verified=False)
    for directory in ('scripts','drivers','kits','build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT','host-bin'):
        (out/directory).mkdir(parents=True,exist_ok=True)
    (out/'.cache').symlink_to(TREE/'.cache',target_is_directory=True)
    (out/'kits/XnuPrelink').symlink_to(BASE/'strict-pac-abi-019/XnuPrelink',target_is_directory=True)
    (out/'kits/sheng').mkdir()
    pins={}
    for name in ('GopFramebuffer','AppleKeyStoreState'):
        rel='drivers/'+name;module=MODULES/rel
        pin=a.gop_revision if name=='GopFramebuffer' else subprocess.check_output(['git','-C',str(CORE),'ls-tree','HEAD',rel],text=True).split()[2]
        current=subprocess.check_output(['git','-C',str(module),'rev-parse','HEAD'],text=True).strip()
        resolved=subprocess.check_output(['git','-C',str(module),'rev-parse',pin+'^{commit}'],text=True).strip()
        if resolved!=pin:raise ValueError('Require full module commit')
        with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['git','-C',str(module),'archive',pin]))) as archive:
            archive.extractall(out/rel,filter='data')
        pins[name]=pin
    for name in ('build-arm-driver.py','kernel_target.py'):
        shutil.copyfile(CORE/'scripts'/name,out/'scripts'/name)
    dependencies=Path(__file__).resolve().parents[2]/'ci/compile_dependencies.py'
    shutil.copyfile(dependencies,out/'scripts/compile_dependencies.py')
    driver=out/'scripts/build-arm-driver.py'
    driver_text=driver.read_text()
    anchor='result = subprocess.run(command, cwd=record[\'directory\'],'
    if driver_text.count(anchor)!=1:raise ValueError('Driver compile anchor changed')
    driver.write_text(driver_text.replace(anchor,"from compile_dependencies import run_recorded\nresult = run_recorded(command, cwd=record['directory'],"))
    shutil.copyfile(CORE/'components.toml',out/'components.toml')
    receipt=json.loads((a.bindings/'result.json').read_text())
    for item in receipt['fixtures']:
        if sha(item['path'])!=item['sha256']:raise ValueError('Binding changed')
    shutil.copyfile(a.bindings/'legacy-display-24A446.json',out/'scripts/legacy-display-24A446.json')
    abi=json.loads((out/'scripts/legacy-display-24A446.json').read_text())
    cache=Path('/mnt/g/UniXNU-Port/ports/UniXNU-pdx234/.cache/iphone14-ios27/ipsw/24A446/kernelcache.decompressed')
    display_fields=sony_display_overlay.qualify(abi,cache.read_bytes())
    gop_source=out/'drivers/GopFramebuffer/NativeLegacyDisplay.cpp'
    gop_source.write_text(sony_display_overlay.apply_gop(gop_source.read_text()))
    shutil.copyfile(Path(sony_display_overlay.__file__),out/'scripts/sony_display_overlay.py')
    plan=json.loads((BASE/'pac-abi-native-019/plan.json').read_text())
    job=next(j for j in plan['jobs'] if Path(j['source']).name=='IOPlatformExpert.cpp')
    record=dict(arguments=job['command'],file=job['source'],directory=job['directory'])
    (out/'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json').write_text(json.dumps(record))
    source=(SHENG/'scripts/build-gop-legacy-display-27.py').read_text()
    end=source.index('# Keyboard, buttons and touch,')
    recipe=source[:end]+'''
layout = OUT / 'PdxLegacyRequestLayout.cpp'
layout.write_text('extern "C" const unsigned native_legacy_request_layout[6] = {' +
                 ','.join(str(R[key]) for key in ('rect0','rect1','masks','options','dims','surfaces')) + '};\\n')
compile_cpp(layout, OUT / 'PdxLegacyRequestLayout.o')
archive = OUT / 'libNativeLegacyDisplay.late.a'
run(['xcrun', 'ar', 'rcs', archive, late, OUT / 'original-bindings.o', OUT / 'original-addresses.o',
     OUT / 'LegacyDisplayProbe.o', OUT / 'LegacyDisplaySupport27.o', gop_late, OUT / 'KeyStoreProbe.o', keyevents_late,
     OUT / 'PdxLegacyRequestLayout.o'])
print('DISPLAY_KEYSTORE_ARCHIVE', archive)
'''
    if a.boot_screen:
        start=recipe.index('// The board diagnostic page is not drawn on iPadOS 27:')
        stop=recipe.index("''')",start)
        recipe=recipe[:start]+recipe[stop:]
    if a.sony_cpufreq:
        recipe=recipe.replace("archive = OUT / 'libNativeLegacyDisplay.late.a'", "compile_cpp(ROOT / 'kits/sheng/CpuFreqProbe.cpp', OUT / 'CpuFreqProbe.o')\narchive = OUT / 'libNativeLegacyDisplay.late.a'")
        recipe=recipe.replace("OUT / 'PdxLegacyRequestLayout.o'])", "OUT / 'PdxLegacyRequestLayout.o', OUT / 'CpuFreqProbe.o'])")
        shutil.copyfile(SHENG/'package/CpuFreqProbe.cpp',out/'kits/sheng/CpuFreqProbe.cpp')
    old='return subprocess.check_output([str(x) for x in cmd], timeout=300, **kw)'
    if recipe.count(old)!=1:raise ValueError('Display runner changed')
    recipe=recipe.replace(old,'''from compile_dependencies import run_recorded
    return run_recorded(cmd, timeout=300, stdout=subprocess.PIPE, check=True, **kw).stdout''')
    (out/'scripts/build-gop-legacy-display-27.py').write_text(recipe)
    # Keep the complete upstream display implementation. Board startup invokes
    # only the Sony integration units being supplied here; it does not call
    # tablet-specific peripheral probes or replace them with success stubs.
    probe=sony_display_overlay.apply_probe((SHENG/'package/LegacyDisplayProbe.cpp').read_text(),display_fields)
    first=probe.index('    sheng_cpufreq_probe();',probe.index('void native_legacy_display_late_probe(void) {'))
    last=probe.index('    sheng_dpu_probe();',first)+len('    sheng_dpu_probe();')
    probe=probe[:first]+'    sheng_gpu_power_probe();\n'+probe[last:]
    if a.sony_cpufreq:
        probe=probe.replace('    sheng_gpu_power_probe();','    sheng_cpufreq_probe();\n    sheng_gpu_power_probe();')
    # This iOS build has neither the macOS-only SoftwareAES publication nor
    # the BootUiTrace worker. Retain their upstream implementations for a
    # later selected build instead of emitting fake successful providers.
    probe=probe.replace('    if (sheng_software_aes_probe) sheng_software_aes_probe();','')
    if not a.matching_report:
        probe=probe.replace('    {thread_t thread = nullptr; if (kernel_thread_start(busyReport, nullptr, &thread) == KERN_SUCCESS) thread_deallocate(thread);}','')
        start=probe.index('namespace {\n// IOKit\'s matching threads')
        end=probe.index('}  // namespace',start)+len('}  // namespace')
        probe=probe[:start]+probe[end:]
    # Publish the real D27 HID family/resource. Sony's physical input transport
    # is separate from the tablet's Novatek and keyboard-cover drivers.
    probe=probe.replace('    native_hid_input_probe();', '''    {
        kern_return_t hid = OSKextLoadKextWithIdentifier("com.apple.iokit.IOHIDFamily");
        IOLog("pdx234 HID family load: %d\\n", hid);
    }''')
    (out/'kits/sheng/LegacyDisplayProbe.cpp').write_text(probe)
    shutil.copyfile(SHENG/'package/KeyStoreProbe.cpp',out/'kits/sheng/KeyStoreProbe.cpp')
    # Host-only tools: exact target is explicitly supplied by upstream recipes.
    tools=out/'host-bin'
    xcrun='''#!/usr/bin/env python3
import os,sys
args=sys.argv[1:]
if args[:1]==['--sdk']:args=args[2:]
if args==['--show-sdk-path']:print(os.environ['UNIXNU_SDKROOT']);sys.exit(0)
tool=args.pop(0)
mapping={'clang':'/root/unixnu-build/pdx234-pac-toolchain/llvm/bin/clang-24',
         'ar':'/usr/bin/llvm-ar','nm':'/usr/bin/llvm-nm'}
exe=mapping.get(tool,tool);os.execvp(exe,[exe,*args])
'''
    (tools/'xcrun').write_text(xcrun);(tools/'xcrun').chmod(0o755)
    (tools/'brew').write_text('#!/bin/sh\n[ "$1" = "--prefix" ] && [ "$2" = "llvm" ] || exit 1\necho /usr/lib/llvm-23\n')
    (tools/'brew').chmod(0o755)
    env=dict(os.environ,PATH=str(tools)+':'+os.environ['PATH'],UNIXNU_XNU_ARCH='arm64e',UNIXNU_IOS_VERSION='27.0',
             UNIXNU_IPSW_BUILD='24A446',UNIXNU_SDKROOT=str(TREE/'.cache/fakeroot'),
             CCC_OVERRIDE_OPTIONS='# +-Wno-missing-designated-field-initializers +-Wno-unused-but-set-global')
    with (out/'build.log').open('x') as log:
        result=subprocess.run(['python3','-B',str(out/'scripts/build-gop-legacy-display-27.py')],env=env,stdout=log,stderr=subprocess.STDOUT)
    if result.returncode:raise RuntimeError((out/'build.log').read_text()[-7000:])
    archive=out/'build/native-legacy-display/libNativeLegacyDisplay.late.a'
    result=dict(archive=str(archive),sha256=sha(archive),pins=pins,bindings_sha256=sha(a.bindings/'result.json'),
                upstream_builder_sha256=sha(SHENG/'scripts/build-gop-legacy-display-27.py'),
                staged_builder_sha256=sha(out/'scripts/build-gop-legacy-display-27.py'),
                upstream_probe_sha256=sha(SHENG/'package/LegacyDisplayProbe.cpp'),
                 staged_probe_sha256=sha(out/'kits/sheng/LegacyDisplayProbe.cpp'),
                 source_overlay=dict(helper_sha256=sha(out/'scripts/sony_display_overlay.py'),
                     upstream_gop_sha256=sony_display_overlay.GOP_SHA256,
                     staged_gop_sha256=sha(gop_source),diagnostic_fields=display_fields,
                     one_layer_before_family_start=True,early_retire_default=0,
                     explicit_early_retire_compatibility=True,pac_client_interposition=False),
                boot_screen=a.boot_screen,
                matching_report=a.matching_report,
                cpufreq_inputs=cpufreq_inputs,
                pac_flag='-fptrauth-function-pointer-type-discrimination',runtime_verified=False,device_operations=False)
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
