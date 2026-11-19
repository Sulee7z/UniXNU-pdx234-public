#!/usr/bin/env python3
"""Build executable069 display owner/DSI service and composable legacy hooks."""
import argparse,hashlib,importlib.util,json,shutil,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
DRIVER=ROOT/'drivers/SonyOledBacklight/platform069'
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
OLD=BASE/'sony-oled-driver-006'
NATIVE=Path('/mnt/f/UniXNU-Port-artifacts/platform067-20261118/native-platform067-full-002')
def sha(p):
    with Path(p).open('rb') as s:return hashlib.file_digest(s,'sha256').hexdigest()
def load(name,p):
    spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',required=True,type=Path);p.add_argument('--inputs',required=True,type=Path);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    generated=json.loads((a.inputs/'result.json').read_text())
    if sha(a.inputs/'SonyDisplay069.generated.h')!=generated['header_sha256']:raise ValueError('GeneratedSonyinputs changed')
    test=['clang++','-std=c++20','-O1','-g','-Wall','-Wextra','-Werror','-Wno-misleading-indentation',
          '-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(DRIVER),'-I',str(a.inputs),
          str(ROOT/'tests/sony_display069_host.cpp'),'-x','c++',str(DRIVER/'Display069.c'),str(DRIVER/'Resources069.c'),'-o',str(a.out/'host')]
    subprocess.run(test,check=True,timeout=90)
    run=subprocess.run([str(a.out/'host')],capture_output=True,text=True,timeout=30);(a.out/'host.log').write_text(run.stdout+run.stderr)
    if run.returncode:raise RuntimeError(run.stdout+run.stderr)
    builder=load('display069_cached',ROOT/'ci/qemu/display/input/build-input.py');includes=['-I',str(DRIVER),'-I',str(a.inputs),'-I',str(ROOT/'drivers/SonyWcn/platform069'),
        '-idirafter',str(builder.SDK/'System/Library/Frameworks/Kernel.framework/Versions/A/Headers')]
    (a.out/'objects').mkdir();commands={};members={}
    for name in ['Display069.c','Resources069.c','Native069.cpp','Backlight069.cpp']:
        obj=a.out/'objects'/(Path(name).stem+'.o')
        commands[name]=builder.compile_cpp(DRIVER/name,obj,includes,['-Xclang','-fptrauth-block-descriptor-pointers','-Wno-misleading-indentation'])
        members[obj.name]=obj
    back=a.out/'objects/SonyOledBacklight.late.o'
    subprocess.run(['llvm-objcopy-23','--remove-section=__DATA,__mod_init_func',
        '--globalize-symbol=__GLOBAL__sub_I_Backlight069.cpp',
        '--redefine-sym=__GLOBAL__sub_I_Backlight069.cpp=__GLOBAL__sub_I_SonyOledBacklight.cpp',
        str(members['Backlight069.o']),str(back)],check=True)
    initializer=subprocess.check_output(['llvm-nm','-g',str(back)],text=True)
    if ' T __GLOBAL__sub_I_SonyOledBacklight.cpp' not in initializer:
        raise ValueError('The retained backlight probe must reach the new class initializer')
    old=json.loads((OLD/'result.json').read_text());archive=a.out/'libSonyD27OledBacklight.a';shutil.copyfile(old['archive'],archive)
    subprocess.run(['llvm-ar','r',str(archive),str(back),str(members['Display069.o']),str(members['Resources069.o']),str(members['Native069.o'])],check=True)
    # Existingclass&168PACslots remainexactD27; ownerengine has no legacyApplepatch.
    table=builder.object_info(members['Backlight069.o'])['tables']['__ZTV17SonyOledBacklight']
    prior=json.loads((OLD/'abi.json').read_text())
    if len(table)!=168 or any(w>>32&65535!=int(row['diversity'],16) for (n,w),row in zip(table,prior['compiled_table'])):raise ValueError('D27backlightPACmismatch')
    result=dict(passed=True,archive=str(archive),sha256=sha(archive),baseline_native_sha256='734bb8fc84437371c34f4e2afc43ef4a0b4191d1bfbcd4b6cf1d52d5080c37dd',
         replaces=str(old['archive']),replaced_members=['SonyOledBacklight.late.o'],added_members=['Display069.o','Resources069.o','Native069.o'],
        commands=commands,sources={str(p):sha(p) for p in DRIVER.iterdir() if p.is_file()},tests_sha256=sha(ROOT/'tests/sony_display069_host.cpp'),
        generated_inputs=str(a.inputs/'result.json'),generated_inputs_sha256=sha(a.inputs/'result.json'),
        hardware_verified=False,prior_success_certificate_required=False,read52_required=False,current_verified=False,
        service_slots=168,startup='native_sony_display069_probe',hardware_engine_implemented=True,device_operations=False)
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k not in ['commands','sources']},indent=2))
if __name__=='__main__':main()
