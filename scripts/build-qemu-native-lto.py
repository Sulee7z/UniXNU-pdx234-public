#!/usr/bin/env python3
"""Build an isolated native source/LTO variant; never overwrite prior kernels or claim iOS boot."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

DEVICE=Path(__file__).resolve().parents[1]
TREE=Path('/root/unixnu-build/pdx234-qemu27-out/qemu27-iphone14/ios-27.0.1-24A446-iphone14/qemu27_native_probe/tree')
sys.path.insert(0,'/root/unixnu-build/pdx234-qemu27-mainline/scripts')
from unixnu.kernel import linux_env


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source,'sha256').hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--attempt',required=True)
    parser.add_argument('--configuration',choices=['DEVELOPMENT','RELEASE'],default='DEVELOPMENT')
    parser.add_argument('--no-lto',action='store_true',help='Documented DEVELOPMENT/non-LTO running-kernel variant')
    parser.add_argument('--pointer-format',choices=['chained','threaded'],default='chained',
                        help='chained: fileset-prelink input; threaded: official standalone arm64e entry format')
    parser.add_argument('--source-patch',action='append',default=[],type=Path,
                        help='Reviewed patch applied only to the isolated source copy')
    parser.add_argument('-j',type=int,default=8)
    args=parser.parse_args()
    if not args.attempt.isalnum() or not 1<=args.j<=32:
        parser.error('Fresh alphanumeric attempt and 1..32 jobs required')
    mode='threaded' if args.pointer_format=='threaded' else ('source' if args.no_lto else 'lto')
    out=DEVICE/'out'/('qemu-native-'+mode+'-'+args.attempt)
    work=Path('/root/unixnu-build')/('pdx234-qemu-native-'+mode+'-'+args.attempt)
    out.mkdir();work.mkdir()
    source=work/'source'
    shutil.copytree(TREE/'.cache/xnu-work',source,symlinks=True,ignore=shutil.ignore_patterns('.git'))
    source_patches=[]
    for patch in args.source_patch:
        patch=patch.resolve(strict=True)
        subprocess.run(['git','-C',str(source),'apply','--check',str(patch)],check=True)
        subprocess.run(['git','-C',str(source),'apply',str(patch)],check=True)
        source_patches.append({'path':str(patch),'sha256':digest(patch)})
    archive_paths=[TREE/'build'/name for name in (
        'corecrypto-2023/libcorecrypto_kernel_noasm-namespaced.a',
        'armvirt-platform/libArmVirtPlatform.a','armcpu/libArmCpu.a',
        'libpthread-kernel/libpthread_kernel.a')]
    archive_hashes={str(p):digest(p) for p in archive_paths}
    sdk=TREE/'.cache/fakeroot'
    os.environ['UNIXNU_TOOLCHAIN']='/root/unixnu-build/pdx234-pac-toolchain'
    env=linux_env(SimpleNamespace(tree=TREE,board={'os':{'arch':'arm64e','ios_version':'27.0'}}))
    env['PATH']='/root/unixnu-build/pdx234-lto-linker/install/bin:'+env['PATH']
    env['LD_LIBRARY_PATH']='/root/unixnu-build/pdx234-pac-clang-build/lib:'+env.get('LD_LIBRARY_PATH','')
    env['PLATFORM']='iPhoneOS'
    env['HOST_CC']=env['CLT_PREFIX']+'/bin/xnu-host-cc'
    env['MIGCOM']=env['CLT_PREFIX']+'/libexec/migcom'
    env['KERNEL_SDKROOT']=str(sdk)
    env['XNU_AVAILABILITY_PL']=str(sdk/'usr/local/libexec/availability.pl')
    env['CCC_OVERRIDE_OPTIONS']='# +-Wno-missing-designated-field-initializers +-Wno-unused-but-set-global'
    flags='-Wno-reserved-identifier -Wno-pre-c11-compat -Wno-missing-designated-field-initializers -Wno-suggest-override -Wno-unnecessary-virtual-specifier -Wno-suggest-destructor-override -Wno-ms-bitfield-padding -DXNU_NATIVE_PAN=1 -DXNU_SOURCE_CORECRYPTO14=1 -DXNU_BOOT_PROGRESS=0'
    link=' '.join([f'-L{sdk}/usr/local/lib/kernel','-lfirehose_kernel',str(archive_paths[0]),
                   *(f'-Wl,-force_load,{p}' for p in archive_paths[1:])])
    command=['make','-C',str(source),'build','SDKROOT=iphoneos','ARCH_CONFIGS=ARM64',
        'MACHINE_CONFIGS=BCM2837','KERNEL_CONFIGS='+args.configuration,
        'ARCH_STRING_FOR_CURRENT_MACHINE_CONFIG=arm64e','LARGE_MEMORY_DEFINE=-UARM_LARGE_MEMORY',
        'ARM64_LINK_ADDR=0xfffffff007004000','ARM64_PLKSEG_ADDR=0xfffffff004004000',
        'DEPLOYMENT_TARGET_FLAGS=-miphoneos-version-min=27.0 -DXNU_TARGET_OS_IOS',
        'DEPLOYMENT_LINKER_FLAGS=-Wl,-ios_version_min,27.0','RC_DARWIN_KERNEL_VERSION=25.5.0',
        'RC_ProjectSourceVersion=12377.121.6','BUILD_LTO='+('0' if args.no_lto else '1'),
        'XNU_KERNEL_CHAINED_FIXUPS='+('1' if args.pointer_format=='chained' else '0'),
        'BOUND_CHECKS=0','BUILD_WERROR=0',f'MAKEJOBS=-j{args.j}',
        'TIGHTBEAMC=tightbeamc-not-supported','BUILD_DSYM=0',
        'MEMORY_SIZE='+str(os.sysconf('SC_PHYS_PAGES')*os.sysconf('SC_PAGE_SIZE')),
        'SYSCTL_HW_PHYSICALCPU='+str(os.cpu_count()),'SYSCTL_HW_LOGICALCPU='+str(os.cpu_count()),
        'LD_KERNEL_LIBS='+str(sdk/'usr/local/lib/kernel/libcc_kext.a'),
        'CFLAGS_EXTRA='+flags,'LDFLAGS_KERNEL_LTO=-miphoneos-version-min=27.0 -Wl,-mllvm,-inline-threshold=100',
        'copyio.o_CFLAGS_ADD=-march=armv8.1-a','pcb.o_CFLAGS_ADD=-march=armv8.1-a',
        'platform_tests.o_CFLAGS_ADD=-march=armv8.1-a','start.o_SFLAGS_ADD=-DXNU_NATIVE_ARCH_TIMER=1',
        'pe_init.o_CFLAGS_ADD=-DXNU_DT_PANIC_REGION=1','LD_KERNEL_ARCHIVES='+link,
        'XNU_EXTERNAL_KERNEL_ARCHIVES='+' '.join(map(str,archive_paths)),
        'OBJROOT='+str(work/'obj'),'SYMROOT='+str(work/'sym'),'DSTROOT='+str(work/'dst')]
    record={'command':command,'archives':archive_hashes,'configuration':args.configuration,
            'lto':not args.no_lto,'chained_fixups':args.pointer_format=='chained','pointer_format':args.pointer_format,
            'artifact_role':'fileset-prelink-input' if args.pointer_format=='chained' else 'standalone-entry-only',
            'source_snapshot':str(source),'source_patches':source_patches,
            'replaces_prior_native':False,'device_operations':False}
    (out/'inputs.json').write_text(json.dumps(record,indent=2)+'\n')
    print('Native '+args.configuration+'/'+mode+' build: '+str(work/'build.log'),flush=True)
    with (work/'build.log').open('x') as log:
        result=subprocess.run(command,cwd=TREE,env=env,stdout=log,stderr=subprocess.STDOUT)
    shutil.copyfile(work/'build.log',out/'build.log')
    if result.returncode:
        print('\n'.join((out/'build.log').read_text(errors='replace').splitlines()[-45:]))
        raise SystemExit(result.returncode)
    built=work/'obj'/(args.configuration+'_ARM64_BCM2837')/('mach.'+args.configuration.lower()+'.bcm2837.unstripped')
    target=out/('native-'+args.pointer_format+'-kernel.macho')
    shutil.copyfile(built,target)
    record.update(native_sha256=digest(target),native_bytes=target.stat().st_size,
                  prelinked=False,kernel_or_springboard_boot_verified=False)
    (out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))


if __name__=='__main__':
    main()
