#!/usr/bin/env python3
"""Verify actual platform067 linked members, final PAC tables and source receipts."""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'ci'))
from platform067.integration import sha,validate
from native_source_overlays import validate_overlays


def members(path):
    names=subprocess.check_output(['llvm-ar','t',str(path)],text=True).splitlines()
    if len(names)!=len(set(names)):raise ValueError('Duplicate linked archive members')
    return {name:hashlib.sha256(subprocess.check_output(['llvm-ar','p',str(path),name])).hexdigest() for name in names}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('native','strict','out'):parser.add_argument('--'+key,type=Path,required=True)
    args=parser.parse_args()
    n=json.loads((args.native/'result.json').read_text());s=json.loads((args.strict/'result.json').read_text())
    if (sha(args.native/'native.macho')!=n['native_sha256'] or s['native_sha256']!=n['native_sha256'] or
            sha(args.strict/'kernel.macho')!=s['candidate_sha256'] or not s['pac_enabled'] or
            s['pac_metadata_adapters'] or s['auth_instruction_patches']):
        raise ValueError('Exact physical strict PAC identities required')
    validate_overlays(n,sha);validate(n['platform067'])
    args.out.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(args.strict/'XnuPrelink'));from kc_image import Image
    raw=(args.strict/'kernel.macho').read_bytes();image=Image(raw);member=Image(raw,image.entries['com.apple.kernel'][1])
    names={name:address for address,values in member.symbols().items() for name in values}
    fixups=image.fixups();starts=member.function_starts();implementations={}
    def implementation(name):
        if name not in names:raise ValueError('Selected function absent: '+name)
        at=names[name];index=bisect.bisect_right(starts,at)
        if index==len(starts):raise ValueError('Unbounded selected function: '+name)
        length=starts[index]-at;code=member.read(at,length)
        stream='\n'.join(' '.join(f'0x{b:02x}' for b in code[i:i+4]) for i in range(0,len(code),4))
        result=subprocess.run(['llvm-mc-23','--disassemble','--triple=aarch64','--mattr=+v8.3a,+pauth,+lse'],
            input=stream,capture_output=True,text=True,check=True,timeout=20)
        lines=[line.strip() for line in result.stdout.splitlines() if line.strip() and line.strip()!='.text']
        if len(lines)!=len(code)//4:raise ValueError('Incomplete final instruction decode: '+name)
        destination=args.out/(name+'.asm');destination.write_text('\n'.join(f'{at+4*i:#x} {line}' for i,line in enumerate(lines))+'\n')
        implementations[name]=dict(address=hex(at),bytes=length,sha256=hashlib.sha256(code).hexdigest(),
            disassembly=str(destination),disassembly_sha256=sha(destination))
        return '\n'.join(lines)
    command=json.loads((args.native/'native-link.command.json').read_text())
    filelist=Path(command[command.index('-filelist')+1]).read_text().splitlines()
    blocks=n['block_descriptor_abi']
    for row in blocks['replacements']:
        if filelist.count(row['new_object'])!=1:raise ValueError('Unlinked Blocks receipt: '+row['new_object'])
    if not n.get('official_addon_size_067'):raise ValueError('Missing audited official addon size repair')
    patch=next(row for row in n['native_source_patches'] if row['native_source_patch']=='audit-d27-addon-reference')
    if 'VATTR_SET(&va, va_data_size, size);' not in Path(patch['source']).read_text():
        raise ValueError('Official vnode length assignment absent')
    implementation('_native_gpu_addon_write')
    perf=n['platform067_performance'];performance_checks={}
    for key in ('display_source','gpu_source'):
        baseline=perf['archives'][key];actual=members(n[key]['archive'])
        for name,digest in baseline['unchanged_members'].items():
            if actual.get(name)!=digest:raise ValueError('Preserved performance member changed: '+name)
        required=['CpuFreqProbe','SonyPerformanceProbe'] if key=='display_source' else ['GpuPowerProbe']
        for name in required:
            row=perf['compiled'][name]
            if actual.get(name+'.o')!=row['object_sha256'] or sha(row['object'])!=row['object_sha256']:
                raise ValueError('Qualified performance object not selected: '+name)
        performance_checks[key]=dict(unchanged_members=len(baseline['unchanged_members']),
            required_members=required,actual_member_count=len(actual))
        if key=='display_source':
            startup_object=args.native/'LegacyDisplayProbe.o'
            if actual.get('LegacyDisplayProbe.o')!=sha(startup_object):
                raise ValueError('Actual display startup archive member differs')
    startup_names=[name for name in names if name.startswith('_native_legacy_display_late_probe')]
    if len(startup_names)!=1:raise ValueError('Unique actual display late entry required')
    implementation(startup_names[0])
    startup_address=names[startup_names[0]]
    startup_length=implementations[startup_names[0]]['bytes']
    startup_code=member.read(startup_address,startup_length)
    branch_targets=set()
    for offset in range(0,len(startup_code)-3,4):
        instruction=int.from_bytes(startup_code[offset:offset+4],'little')
        if instruction&0xfc000000==0x94000000:
            displacement=instruction&0x03ffffff
            if displacement&(1<<25):displacement-=1<<26
            branch_targets.add(startup_address+offset+displacement*4)
    for name in ('native_sony_touch_start',*n['platform067']['startup_calls']):
        if '_'+name not in names or names['_'+name] not in branch_targets:
            raise ValueError('Peripheral/performance entry present but not called by actual startup: '+name)
    for name in ('_sheng_cpufreq_probe','_native_sony_performance_start'):
        implementation(name)
    for marker in (b'[sony-perf]',b'[sony-present-rate]',b'[sony-dpu-rate]',b'panel-hz=unmeasured'):
        if marker not in raw:raise ValueError('Bounded performance recorder absent')
    buttons=n.get('platform067_buttons');buttons_check=None
    if buttons:
        if sha(buttons['archive'])!=buttons['sha256']:raise ValueError('Buttons archive changed')
        abi_path=Path(buttons['archive']).with_name('buttons-hid-abi.json')
        if sha(abi_path)!=buttons['hid_abi_sha256']:raise ValueError('Buttons ABI receipt changed')
        abi=json.loads(abi_path.read_text());table=names['__ZTV14SonyButtonsHid']+16
        if len(abi['compiled_vtable'])!=207 or abi['base_bytes']!=208:
            raise ValueError('Wrong button HID extent')
        for row in abi['compiled_vtable']:
            value=fixups[table+8*row['slot']]
            if value[1:]!=(1,0,int(row['diversity'],16),1):raise ValueError('Final buttons HID PAC mismatch')
        for name in ('_native_sony_buttons_start','_native_sony_buttons_allocate'):
            implementation(name)
        if not buttons['neutral_hid_registration_without_mmio'] or buttons['synthetic_home']:
            raise ValueError('Unqualified or synthetic button input')
        buttons_check=dict(final_hid_pac_slots=207,base_bytes=208,
            neutral_registration_without_mmio=True,physical_reads_qualified=False,
            source_qualified_experimental_power_volume_up=buttons.get('source_qualified_experimental_power_volume_up',False),
            hardware_working=False)
    oled=n.get('platform067_oled');oled_check=None
    if oled:
        if sha(oled['archive'])!=oled['sha256']:raise ValueError('OLED archive changed')
        abi_path=Path(oled['archive']).with_name('abi.json')
        if sha(abi_path)!=oled['abi_sha256']:raise ValueError('OLED ABI receipt changed')
        abi=json.loads(abi_path.read_text());table=names['__ZTV17SonyOledBacklight']+16
        if len(abi['compiled_table'])!=168 or not abi['all_service_pac_slots_match']:
            raise ValueError('Wrong Sony OLED service extent')
        for row in abi['compiled_table']:
            value=fixups[table+8*row['slot']]
            if value[1:]!=(1,0,int(row['diversity'],16),1):raise ValueError('Final OLED IOService PAC mismatch')
        implementation('_native_sony_oled_backlight_probe')
        implementation('_native_sony_oled_bind_mapped')
        oled_check=dict(staged=True,physical_owner_installed=oled['physical_mmio_provider_installed'],
            hardware_enabled=oled['hardware_enabled'],final_service_pac_slots=168,runtime_verified=False)
    radio=n.get('platform067_radio');radio_check=None
    if radio:
        radio_archives={radio['archive']:radio['sha256'],radio['wifi_core']['archive']:radio['wifi_core']['sha256']}
        for path,digest in radio_archives.items():
            if command.count('-Wl,-force_load,'+path)!=1 or sha(path)!=digest:
                raise ValueError('Actual selected radio archive differs')
        for section in (radio['objects'],radio['wifi_core']['objects']):
            for path,digest in section.items():
                if sha(path)!=digest:raise ValueError('Radio object changed: '+path)
        for name in ('_native_sony_wifi_start','_native_sony_bluetooth_start','_native_sony_bluetooth_publish',
                     '_sony_wcn_platform_install'):
            implementation(name)
        if radio['firmware']['wifi_ready'] or radio['firmware']['bluetooth_ready']:
            raise ValueError('This candidate has no qualified radio firmware/runtime')
        radio_check=dict(board_members=len(radio['objects']),core_members=len(radio['wifi_core']['objects']),
            firmware_present=False,runtime_enabled=False,hardware_working=False,
            source_size_optimization=radio['wifi_core'].get('optimization','-O2'))
    logging=n.get('platform067_logging');logging_check=None
    if logging:
        storage=[value.split('-Wl,-force_load,',1)[1] for value in command
                 if value.startswith('-Wl,-force_load,') and Path(value.split(',')[-1]).name=='libShengUfs.a']
        if len(storage)!=1:raise ValueError('Unique final Sony storage archive required')
        old=members(logging['storage_archive']);new=members(storage[0])
        if old.keys()!=new.keys() or {key for key in old if old[key]!=new[key]}!={'BootLog.o'}:
            raise ValueError('Log provider must not change the Sony disk/window drivers')
        if new['BootLog.o']!=logging['new_provider_sha256']:
            raise ValueError('Qualified log provider not actually selected')
        for name in ('_boot_log_startup_stage','_boot_log_startup_result','_boot_log_process_exit','_boot_log_panic_record'):
            implementation(name)
        if b'unixnu-exit:' not in raw:raise ValueError('Official process exit text absent')
        logging_check=dict(official_consumer_patches=5,only_storage_member_changed='BootLog.o',
            platform_sleep_enabled=False,device_writes_by_agent=False)
    record=dict(passed=True,native_sha256=n['native_sha256'],strict_sha256=s['candidate_sha256'],
        implementations=implementations,official_addon_size_repair_selected=True,
        actual_startup_branch_targets_verified=True,
        actual_signed_blocks_inputs_verified=len(blocks['replacements']),performance=performance_checks,
        buttons=buttons_check,oled=oled_check,radio=radio_check,logging=logging_check,
        hardware_features_verified=False,device_operations=False)
    (args.out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({k:v for k,v in record.items() if k!='implementations'},indent=2))


if __name__=='__main__':main()
