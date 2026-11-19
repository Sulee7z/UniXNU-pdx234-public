#!/usr/bin/env python3
"""Stage immutable Sony069 radio/provider objects and composable owner adapters."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,re,shlex,shutil,subprocess,sys
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
FRESH=Path('/mnt/f/UniXNU-Port-artifacts/platform069-20261118')
OLD=BASE/'sony-wcn-067-002'
def sha(p):
    with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def run(cmd,cwd=None,log=None):
    r=subprocess.run(list(map(str,cmd)),cwd=cwd,capture_output=True,text=True,timeout=180)
    if log:Path(log).write_text(r.stdout+r.stderr)
    if r.returncode:raise RuntimeError((r.stdout+r.stderr)[-11000:])
    return r.stdout
def module(name,p):
    sp=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m
def compile_source(source,obj,record,extra):
    cmd=list(record['command']);cmd[cmd.index(record['source'])]=str(source);cmd[cmd.index('-o')+1]=str(obj)
    if '-MF' in cmd:cmd[cmd.index('-MF')+1]=str(obj.with_name(obj.name+'.d'))
    else:cmd+=['-MD','-MF',str(obj.with_name(obj.name+'.d'))]
    cmd=[('-Oz' if v=='-O2' else v) for v in cmd];cmd+=extra
    directory=record.get('cwd',record.get('directory'))
    if not directory:
        parents={str(Path(path).parent) for path in record.get('dependencies',{}) if Path(path).name=='meta_features.h'}
        if len(parents)!=1:raise ValueError('Exact compile directory required: '+str(source))
        directory=parents.pop()
    run(cmd,cwd=directory,log=obj.with_suffix('.log'))
    deps=shlex.split(obj.with_name(obj.name+'.d').read_text().replace('\\\n','').partition(':')[2])
    receipt={'dependency_schema':1,'dependency_compiler':cmd[0],'dependency_compiler_sha256':sha(cmd[0]),
             'source':str(source),'object':str(obj),'object_sha256':sha(obj),'command':cmd,'cwd':directory,
             'dependencies':{str((Path(directory)/p).absolute()):sha(Path(directory)/p) for p in deps}}
    obj.with_name(obj.name+'.dependencies.json').write_text(json.dumps(receipt,indent=2)+'\n');return receipt

def firmware_rows(inputs, destination):
    manifest=inputs/'firmware-manifest.json'
    fw=json.loads(manifest.read_text())
    if fw['device']!='Sony XQ-DQ72' or fw['dtb_sha256']!='6ab06c177a7131338cd8cc374b304838738497bf0d709a48ed50f0282c03bb8a':
        raise ValueError('Exact Sony live DT/firmware capture required')
    wifi={};bt={};root=inputs.resolve()/'runtime/firmware'
    for row in fw['files']:
        path=Path(row['staged']).resolve();parent=path.parent.relative_to(root).as_posix()
        if not row['phone_hash_matches'] or sha(row['path'])!=row['sha256'] or sha(path)!=row['sha256'] or path.stat().st_size!=row['bytes']:
            raise ValueError('Staged Sony firmware changed: '+str(path))
        if parent=='ath12k/WCN7850/hw2.0':
            target,name=wifi,path.name
        elif parent=='qca' and re.fullmatch(r'hmtbtfw20\.(?:tlv|ver)|hmtnv20\.(?:bin|b[0-9a-f]{2,4})',path.name):
            target,name=bt,'qca/'+path.name
        else:raise ValueError('Unexpected Sony firmware path: '+str(path))
        if name in target:raise ValueError('Duplicate Sony firmware path: '+name)
        target[name]=(row['bytes'],row['sha256'])
    if set(wifi)!={'amss.bin','m3.bin','sony-board.elf','sony-regdb.bin'} or len(bt)!=49 or not {'qca/hmtbtfw20.tlv','qca/hmtnv20.bin'}<=bt.keys():
        raise ValueError('Incomplete Sony firmware capture')
    with destination.open('w') as output:
        output.write('/* Generated from Sony phone/host hash-matched inputs. */\n')
        for key,files in (('wifi_files',wifi),('bt_files',bt)):
            output.write('static const struct SonyFirmwareFile '+key+'[]={\n')
            for name,(size,digest) in sorted(files.items()):
                output.write('{'+json.dumps(name)+','+str(size)+',{'+','.join(hex(b) for b in bytes.fromhex(digest))+'}},\n')
            output.write('};\n')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--inputs',type=Path,default=FRESH/'radio-inputs069-003');p.add_argument('--resume',action='store_true');a=p.parse_args()
    if a.out.exists() and not(a.resume and (a.out/'owner.json').exists()):raise ValueError('Preserve existing output')
    a.out.mkdir(parents=True,exist_ok=True);out=a.out.resolve();(out/'owner.json').write_text(json.dumps({'source':str(__file__)})+'\n')
    source=out/'source';source.mkdir(exist_ok=True);objects=out/'objects';objects.mkdir(exist_ok=True)
    adapt=module('sony069_adapt',HERE/'adapt069.py');r=json.loads((OLD/'result.json').read_text())
    address_adapter=module('sony069_address',ROOT/'ci/platform069/radio_address.py')
    old_commands=r['commands'];cxx=old_commands['WifiProbe.cpp'];c=old_commands['qbt_core.c']
    official=FRESH/'sheng/package';soc=OLD/'components/UniXNU-sm8550-common/kits/Sm8550Platform'
    smmu=BASE/'gpu-source-006/kits/ArmSmmu4K'
    for file in HERE.glob('*'):
        if file.suffix in ('.c','.h','.cpp'):shutil.copyfile(file,source/file.name)
    for name in ['QcomRpmh.c','QcomRpmh.h','QcomQmp.c','QcomQmp.h','BootResetCore.h']:
        shutil.copyfile(official/name,source/name)
    shutil.copyfile(OLD/'source/SmmuBypass.h',source/'SmmuBypass.h')
    shutil.copyfile(a.inputs/'SonyResources.generated.h',source/'SonyResources.generated.h')
    for name in ['SonyWcnPlatform.h','SonyWcnPower.h']:
        shutil.copyfile(HERE.parent/name,source/name)
    for name in ['WifiPcieTables.h','MhiBoot.h','WifiFirmware.h','BluetoothFirmware.h','SonyWcnBoard.h']:
        original=(OLD/name) if name=='SonyWcnBoard.h' else OLD/'source'/name
        shutil.copyfile(original,source/name)
    (source/'WifiProbe.cpp').write_text(address_adapter.wifi(adapt.wifi((OLD/'source/WifiProbe.cpp').read_text())))
    (source/'WifiFirmware.c').write_text(adapt.raw_firmware((OLD/'source/WifiFirmware.c').read_text()))
    (source/'BluetoothProbe.cpp').write_text(adapt.bluetooth((OLD/'source/BluetoothProbe.cpp').read_text()))
    (source/'BluetoothFirmware.c').write_text(adapt.bluetooth_firmware((OLD/'source/BluetoothFirmware.c').read_text()))
    firmware_rows(a.inputs, source/'SonyFirmware.generated.h')
    daemon=FRESH/'d27-radio-userland-original-003/files/os/usr/sbin/bluetoothd'
    if sha(daemon)!='cfd94854d0a2efd3ca4a2de6e55349f43fd0d274a4b8bfa9937f29d9f7208cb1':raise ValueError('D27 daemon ABI identity mismatch')
    include=[source,soc,smmu,*[OLD/'components/QcaBluetooth'/d for d in ['include','src','shim','out/linux']],OLD/'components/Ath12kWifi/include']
    extra=['-I'+str(x) for x in include]+['-Wno-unused-function','-Wno-unused-variable','-Wno-deprecated-volatile','-Wno-missing-field-initializers','-Wno-missing-braces','-Wno-sign-compare','-Wno-unused-but-set-global']
    receipts={};provider=[]
    for name in ['SonySharedResources.cpp','SonyDma.cpp','SonyWifiDma.cpp','SonyWifiDmaTables.c','SonyWifiAddress069.cpp','SonyIts.cpp','SonyRpmh.c','SonyVotes.c','SonyCommandDb.c','SonyIts.c','SonyBoard2.c','QcomRpmh.c','QcomQmp.c']:
        obj=objects/(Path(name).stem+('_encoding' if name=='SonyIts.c' else '')+'.o')
        receipts[name]=compile_source(source/name,obj,cxx if name.endswith('.cpp') else c,extra);provider.append(obj)
    picker=source/'Sm8550AppsSmmu.c'
    picker.write_text(adapt.apps_smmu((soc/'Sm8550AppsSmmu.c').read_text()))
    receipts['Sm8550AppsSmmu.c']=compile_source(picker,objects/'Sm8550AppsSmmu.o',c,extra)
    provider.append(objects/'Sm8550AppsSmmu.o')
    provider_archive=out/'libSonyRadioPlatform069.a';tmp=out/'libSonyRadioPlatform069.new.a'
    run(['llvm-ar','rcs',tmp,*provider]);tmp.replace(provider_archive)
    board=out/'libSonyWcn.a';shutil.copyfile(FRESH.parent/'platform067-20261118/radio-board-size-002/libSonyWcn.a',board)
    board_replaced=[]
    for name in ['WifiProbe.cpp','WifiFirmware.c','SonyWcnQualification.c','BluetoothProbe.cpp','BluetoothFirmware.c']:
        obj=objects/(Path(name).stem+'.o');receipts[name]=compile_source(source/name,obj,old_commands[name],extra)
        run(['llvm-ar','r',board,obj]);board_replaced.append(obj.name)
    # Only the QMI identity and native core board-name producer are rebuilt.
    core=out/'libSonyAth12kCore.a';core_old=FRESH.parent/'platform067-20261118/radio-core-size-002'
    shutil.copyfile(core_old/'libSonyAth12kCore.a',core)
    selected=json.loads((core_old/'result.json').read_text())
    core_changed=[]
    for filename,transform in [('qmi',adapt.qmi),('core',adapt.ath12k_core)]:
        name='ath12k_'+filename;obj=objects/(name+'.o')
        candidate=next((row for row in selected['replacements'] if Path(row['old_object']).name==obj.name),None)
        if candidate is None:raise ValueError('Actual locked Ath12k compile record needed: '+name)
        if sha(candidate['object'])!=candidate['object_sha256']:raise ValueError('Actual selected Ath12k object changed')
        rec=json.loads(Path(candidate['dependency_receipt']).read_text());rec['directory']=candidate['directory']
        file=source/(filename+'.c');file.write_text(transform(Path(rec['source']).read_text()))
        receipts[name]=compile_source(file,obj,rec,[])
        rename=OLD/'wifi-core/rename.txt';run(['llvm-objcopy-23','--redefine-syms='+str(rename),obj]);run(['llvm-ar','r',core,obj])
        receipts[name].update(compiled_object_sha256=receipts[name]['object_sha256'],object_sha256=sha(obj),
            namespace_map=str(rename),namespace_map_sha256=sha(rename))
        obj.with_name(obj.name+'.dependencies.json').write_text(json.dumps(receipts[name],indent=2)+'\n')
        core_changed.append(obj.name)
    # Composable parent-owned replacements: generated in private output, never
    # edit current ArmCpu/touch/UFS or their source references.
    arm_src=BASE/'sources/armcpu-spi/ArmCpu.cpp';(source/'ArmCpu069.cpp').write_text(adapt.armcpu(arm_src.read_text()))
    (out/'owner-adapters.json').write_text(json.dumps({'armcpu_source':str(source/'ArmCpu069.cpp'),
        'armcpu_original':str(arm_src),'touch_adapter':str(HERE/'adapt069.py')+':touch',
        'ufs_adapter':str(HERE/'adapt069.py')+':ufs','required_shared_lock':'sony_shared_config_lock/unlock',
        'native_early_int_call':'native_sony_radio_platform069_init (check returned errno before userland)',
        'provider_archive':str(provider_archive)},indent=2)+'\n')
    result={'passed':True,'provider_archive':str(provider_archive),'provider_sha256':sha(provider_archive),
        'board_archive':str(board),'board_sha256':sha(board),'core_archive':str(core),'core_sha256':sha(core),
        'board_replaced_members':board_replaced,'board_added_members':[],
         'core_replaced_members':core_changed,'core_added_members':[],
        'provider_members':[p.name for p in provider],'commands':receipts,
         'firmware_manifest':str(a.inputs.resolve()/'firmware-manifest.json'),
         'firmware_manifest_sha256':sha(a.inputs/'firmware-manifest.json'),
         'installed_firmware_verification':'vnode actual length and SHA256 before use, per Sony manifest; Bluetooth variants remain ROM/BID-selected',
        'hardware_verified':False,'device_operations':False,
        'requires_main_owner_integration':str(out/'owner-adapters.json'),
        'inputs':{str(p):sha(p) for p in source.glob('*') if p.is_file()}}
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k not in ['commands','inputs']},indent=2))
if __name__=='__main__':main()
