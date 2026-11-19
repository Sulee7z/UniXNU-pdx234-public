#!/usr/bin/env python3
"""Build pinned sheng Adreno implementation with Sony input tables and D27 ABI."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import sys
from concurrent.futures import ThreadPoolExecutor

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
CORE=BASE/'sources/UniXNU'
SHENG=BASE/'sources/sheng'
MODULES=Path('/root/unixnu-build/sheng27-sony-bulk-20261111-001/UniXNU')
TREE=CORE/'out/pdx234/ios-27.0.1-24A446-iphone14/pdx234_sheng27_bulk/tree'
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'ci'))
from compile_dependencies import run_recorded


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--inputs',type=Path,required=True);p.add_argument('--bindings',type=Path,required=True)
    p.add_argument('--display',type=Path,required=True);p.add_argument('--jobs',type=int,default=20);a=p.parse_args()
    out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    for rel in ('drivers','kits','scripts/data','build/adreno740/include','build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT','host-bin'):
        (out/rel).mkdir(parents=True,exist_ok=True)
    (out/'.cache').symlink_to(a.inputs.resolve()/'.cache',target_is_directory=True)
    pins={}
    for rel in ('drivers/Adreno740','drivers/AdrenoMetal','kits/AdrenoFirmware','kits/AdrenoPM4','kits/ArmSmmu4K'):
        pin=subprocess.check_output(['git','-C',str(CORE),'ls-tree','HEAD',rel],text=True).split()[2]
        if rel=='drivers/Adreno740':
            pin='653e11c8392490b191fc163881005f756ecfd896'
        data=subprocess.check_output(['git','-C',str(MODULES/rel),'archive',pin])
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:archive.extractall(out/rel,filter='data')
        pins[rel]=pin
    shutil.copytree(BASE/'sources/sm8550/kits/Sm8550Platform',out/'kits/Sm8550Platform')
    shutil.copytree(SHENG/'package',out/'kits/sheng')
    (out/'kits/XnuPrelink').symlink_to(BASE/'strict-pac-abi-019/XnuPrelink',target_is_directory=True)
    for rel in ('build/sheng-gmu','build/sheng-gpu-smmu'):shutil.copytree(a.inputs/rel,out/rel)
    for name in ('derive-a740-pwrup.py','derive-a740-hwinit.py','build-adreno740-accelerator.py','kernel_target.py'):
        shutil.copyfile(CORE/'scripts'/name,out/'scripts'/name)
    shutil.copyfile(Path(__file__).resolve().parents[2]/'ci/compile_dependencies.py',out/'scripts/compile_dependencies.py')
    accelerator=out/'scripts/build-adreno740-accelerator.py'
    text=accelerator.read_text()
    anchor="subprocess.run(cmd, cwd=record['directory'], check=True)"
    if text.count(anchor)!=1:raise ValueError('Accelerator compile anchor changed')
    accelerator.write_text(text.replace(anchor,"from compile_dependencies import run_recorded\nrun_recorded(cmd, cwd=record['directory'], check=True)"))
    shutil.copyfile(a.inputs/'scripts/data/adreno-inputs.json',out/'scripts/data/adreno-inputs.json')
    shutil.copyfile(a.bindings/'ioaccelerator-base-abi-24A446.json',out/'scripts/data/ioaccelerator-base-abi-24A446.json')
    for name in ('xcrun','brew'):shutil.copyfile(a.display/'host-bin'/name,out/'host-bin'/name);(out/'host-bin'/name).chmod(0o755)
    env=dict(os.environ,PATH=str(out/'host-bin')+':'+os.environ['PATH'],UNIXNU_XNU_ARCH='arm64e',UNIXNU_IOS_VERSION='27.0',
             UNIXNU_IPSW_BUILD='24A446',UNIXNU_SDKROOT=str(TREE/'.cache/fakeroot'),
             CCC_OVERRIDE_OPTIONS='# +-Wno-missing-designated-field-initializers +-Wno-unused-but-set-global')
    for name in ('derive-a740-pwrup.py','derive-a740-hwinit.py'):
        subprocess.run(['python3','-B',str(out/'scripts'/name)],check=True,env=env)
    plan=json.loads((BASE/'pac-abi-native-019/plan.json').read_text())
    recipes={kind:next(j for j in plan['jobs'] if Path(j['source']).name==name) for kind,name in [('c','startup.c'),('cpp','IOPlatformExpert.cpp')]}
    cpp=recipes['cpp'];record=dict(arguments=cpp['command']+['-DNATIVE_ACCELERATOR_BASE=IOAcceleratorES'],file=cpp['source'],directory=cpp['directory'])
    (out/'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json').write_text(json.dumps(record))
    sources=[out/'kits/Sm8550Platform'/name for name in ('ShengGmu.c','ShengGmuCommandDb.c')]
    sources += [out/'kits/sheng/ShengGmuVotes.c']
    sources += [out/'kits/AdrenoFirmware'/name for name in ('AdrenoHfi.c','AdrenoHfiStartup.c','AdrenoHfiVotes.c','AdrenoFirmware.c')]
    sources += sorted((out/'kits/ArmSmmu4K').glob('ArmSmmu4K*.c'))
    sources += [out/'kits/AdrenoPM4/AdrenoPM4.c']
    sources += sorted(p for p in (out/'drivers/Adreno740').glob('NativeAdreno*.cpp') if p.name not in ('NativeAdrenoClient.cpp','NativeAdrenoAccelerator.cpp'))
    sources += [out/'kits/sheng/GpuPowerProbe.cpp']
    sources += [out/'kits/sheng/BootLatencyTrace.c']
    include=['kits/sheng','kits/Sm8550Platform','kits/AdrenoFirmware','kits/AdrenoPM4','kits/ArmSmmu4K','drivers/Adreno740','build/sheng-gmu','build/sheng-gpu-smmu','build/adreno740/include']
    def compile_source(source):
        job=recipes['c' if source.suffix=='.c' else 'cpp'];dest=out/'build/adreno740'/(source.stem+'.o')
        cmd=[];i=0;old=job['command']
        while i<len(old):
            v=old[i]
            if v==job['source']:cmd.append(str(source))
            elif v=='-o':cmd+=['-o',str(dest)];i+=1
            elif v in ('-MF','-MT','-MJ'):i+=1
            elif v in ('-MD','-MP'):pass
            elif v=='-Xclang' and old[i+1].startswith('-W'):i+=1
            elif not v.startswith('-W'):cmd.append(v)
            i+=1
        cmd+=['-I'+str(out/rel) for rel in include]+['-I'+str(TREE/'.cache/xnu-work/osfmk'),'-mgeneral-regs-only','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-c99-designator','-Wno-reorder-init-list','-Wno-deprecated-enum-enum-conversion','-Wno-unnecessary-virtual-specifier']
        r=run_recorded(cmd,cwd=job['directory'],env=env,capture_output=True,text=True)
        dest.with_suffix('.log').write_text(r.stdout+r.stderr)
        if r.returncode:raise RuntimeError(str(source)+'\n'+r.stderr[-3500:])
        dest.with_suffix('.json').write_text(json.dumps(dict(source=str(source),sha256=hashlib.sha256(source.read_bytes()).hexdigest(),command=cmd),indent=2))
        return dest
    with ThreadPoolExecutor(max_workers=a.jobs) as pool:objects=list(pool.map(compile_source,sources))
    pins_fw=json.loads((out/'scripts/data/adreno-inputs.json').read_text())['firmware']['files']
    # Firmware is DMA input data, not kernel pointer tables. Keep the blobs in
    # a data section so they do not consume the fixed readonly prefix before
    # Apple's retained family constants (same placement used by sheng firmware).
    assembly=['.section __DATA,__firmware']
    for label,key in [('_native_adreno_firmware_image','qcom/gmu_gen70200.bin'),('_native_adreno_sqe_firmware_image','qcom/a740_sqe.fw'),('_native_adreno_zap_image','qcom/sm8550/sheng/a740_zap.mbn')]:
        path=out/'.cache/firmware/sheng-gpu'/key;data=path.read_bytes();pin=pins_fw[key]
        if len(data)!=pin['bytes'] or hashlib.sha256(data).hexdigest()!=pin['sha256']:raise ValueError('Firmware pin')
        assembly += ['.p2align 12','.globl '+label,label+':','.incbin '+json.dumps(str(path)),label+'_end:','.p2align 3','.globl '+label+'_size',label+'_size:','.quad '+label+'_end-'+label]
    asm=out/'build/adreno740/firmware.S';asm.write_text('\n'.join(assembly)+'\n');fwobj=asm.with_suffix('.o')
    subprocess.run(['xcrun','clang','-target','arm64e-apple-ios27.0','-c',str(asm),'-o',str(fwobj)],env=env,check=True);objects.append(fwobj)
    archive=out/'build/adreno740/libAdreno740.a';subprocess.run(['llvm-ar','rcs',str(archive),*map(str,objects)],check=True)
    subprocess.run(['python3','-B',str(out/'scripts/build-adreno740-accelerator.py')],env=env,check=True)
    result=dict(archive=str(archive),sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),pins=pins,compiled_objects=len(objects),
                inputs_sha256=hashlib.sha256((a.inputs/'result.json').read_bytes()).hexdigest(),
                pac_flag='-fptrauth-function-pointer-type-discrimination',device_operations=False,runtime_verified=False)
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
