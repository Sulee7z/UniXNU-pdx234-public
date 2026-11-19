#!/usr/bin/env python3
"""Independent Windows/Linux069 transport, every menu request, signature and PAC readback."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import struct
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'ci'))
from pdx_boot_transport import BootTransport
from platform069.addon import decode,trust_modules
from platform069.integration import BASELINE_SHA,sha
from platform069.menu import BASELINE_IMAGE_SHA,PROTECTED,validate_choices
from platform069.launchd_cache import inspect_detached_signature
from sony_menu068 import loader_guard
import tomllib


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def require(condition,message):
    if not condition:raise ValueError(message)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release',type=Path,required=True)
    parser.add_argument('--baseline',type=Path,default=ROOT/'out/d27-pac-abi-release-20261118-068')
    parser.add_argument('--version',choices=('069','070','071'),default='069')
    parser.add_argument('--out',type=Path,required=True)
    options=parser.parse_args();j=json.loads((options.release/'release.json').read_text())
    previous=json.loads((options.baseline/'release.json').read_text())
    tag='PDX'+options.version
    require(j['label']=='PAC-ABI-'+options.version and j['screen_build_tag']==tag and
        previous['sha256']==BASELINE_IMAGE_SHA,'Wrong release or exact068 baseline identity')
    original=BootTransport(options.baseline/Path(previous['image']).name,BASELINE_IMAGE_SHA)
    delivered=BootTransport(options.release/Path(j['image']).name,j['sha256'])
    require(len(delivered.raw)==j['bytes'] and len(delivered.raw)<=96*1024**2,'Sony boot capacity/size differs')
    require(delivered.fd==original.fd and delivered.android==original.android,'Retained Android or firmware changed')
    require(hashlib.sha256(delivered.fd).hexdigest()==j['firmware_sha256'] and
        hashlib.sha256(delivered.android).hexdigest()==j['original_android_sha256'],'Firmware or Android receipt differs')
    checks=dict(passed=True,image_sha256=j['sha256'],bytes=len(delivered.raw),android_identical=True,
        firmware_identical=True,raw_lzma_crc_verified=True,independent_fat_readback=True,
        hardware_verified=False,device_operations=False)
    firmware=load('radio069_firmware',ROOT/'scripts/check-firmware-services.py');volumes=firmware.volume_files(delivered.fd)
    require('9eb02581-63fc-44ee-a820-49ced6493f12' not in volumes,'UEFI CDC driver present')
    import uuid
    service=uuid.UUID('765f0768-b70e-43cc-917d-8f213169dc42').bytes_le
    require(not any(service in data for sections in volumes.values() for kind,data in sections if kind==0x10),'UEFI CDC consumer present')
    pe=next(data for kind,data in volumes['1b64af87-8415-4b57-9b16-680d70913b9f'] if kind==0x10)
    checks['actual_loader_guard']=loader_guard(pe)
    config=tomllib.loads(delivered.get('EFI/UniXNU/unixnu.toml').decode())
    require(config['ui']['title']==j['menu_title'] and 'iOS 27' in j['menu_title'] and j['label'] in j['menu_title'],'Wrong menu identity')
    checks['menu_requests']=validate_choices(config,j['kernel_args'])
    tokens=j['kernel_args'].split();keys=[token.split('=',1)[0] for token in tokens]
    require(len(keys)==len(set(keys)),'Duplicate final boot arguments')
    for name,value in {**PROTECTED,'build-tag':tag}.items():require(tokens.count(name+'='+value)==1,'Protected final argument differs: '+name)
    require(j['gpu_enabled'] and j['cdc_disabled'] and j.get('xnu_cdc_enabled') is False,'CDC-off/GPU-on policy differs')
    checks.update(uefi_cdc_absent=True,xnu_cdc_disabled=True,gpu_arguments_enabled=True)
    files={}
    for name,digest in [('kernel.macho',j['payload_kernel_sha256']),('kernel.macho.adt',j['adt_sha256']),
        ('kernel.macho.gpuaddon',j['metal_runtime']['addon_sha256']),('kernel.macho.trustcache',j['metal_runtime']['trust_sha256']),
        ('scratch-data.img',j['volatile_seed']['seed_sha256']),('scratch-data-skip-setup.img',j['skip_setup']['sha256'])]:
        data=delivered.get('EFI/UniXNU/Payloads/'+name);require(hashlib.sha256(data).hexdigest()==digest,'Final FAT identity differs: '+name);files[name]=data
    require(files['scratch-data.img']==original.get('EFI/UniXNU/Payloads/scratch-data.img'),'Normal pristine seed changed')
    for name in ('scratch-data.img','scratch-data-skip-setup.img'):
        data=files[name];require(data[:8]==b'DBRDISK1' and struct.unpack_from('<Q',data,16)[0]==2147483648,'2GiB volatile seed required')
    require(j['volatile_seed']['persistence_mode']==0 and j['skip_setup']['skip_setup'] and j['skip_setup']['build']=='24A446' and
        j['skip_setup']['no_auto_dim'] is False and j['skip_setup']['uuid_preserved'] and j['skip_setup']['apfsck_passed'],'Skip Setup/pristine seed policy differs')
    checks.update(volatile_data_seed_mib=2048,persistence_disabled=True,normal_seed_preserved=True,optional_skip_setup_seed_verified=True)
    adt=load('radio069_adt',ROOT/'scripts/apple-device-tree.py');tree=adt.parse(files['kernel.macho.adt'])
    chosen=tree['children']['chosen']['properties']
    for name,value in [('dram-base',0x980000000),('dram-size',0x180000000),('darwinboot-memory-size',0x130000000)]:
        require(struct.unpack('<Q',chosen[name])[0]==value,'High memory ADT differs')
    require(len(tree['children']['cpus']['children'])==8 and struct.unpack('<I',tree['children']['defaults']['properties']['kern.maxvnodes'])[0]==78848,
        'Eight-core/high-memory ADT policy differs')
    from platform069.radio_adt import overlay_adt
    expected_adt,radio_delta=overlay_adt(original.get('EFI/UniXNU/Payloads/kernel.macho.adt'))
    require(files['kernel.macho.adt']==expected_adt,'Final radio ADT differs from the bounded original068 overlay')
    checks['radio_adt']=dict(exact_bounded_overlay_verified=True,delta=radio_delta,
        static_hardware_addresses_invented=False)
    addon=decode(files['kernel.macho.gpuaddon']);old_addon=decode(original.get('EFI/UniXNU/Payloads/kernel.macho.gpuaddon'))
    expected={row['path']:row for row in j['metal_runtime']['files']}
    require(set(addon)==set(expected) and len(expected)==len(j['metal_runtime']['files']),'Addon member selection differs')
    for name,row in addon.items():
        require((len(row['data']),hashlib.sha256(row['data']).hexdigest(),row['mode'])==
            (expected[name]['bytes'],expected[name]['sha256'],expected[name]['mode']),'Addon file bytes/mode differ: '+name)
    allowed=set(j['metal_runtime'].get('changed_or_added_files',[]))
    for name,row in old_addon.items():require(name in addon and (name in allowed or addon[name]==row),'Unrelated068 addon member changed')
    old_modules=trust_modules(original.get('EFI/UniXNU/Payloads/kernel.macho.trustcache'));modules=trust_modules(files['kernel.macho.trustcache'])
    require(modules[:len(old_modules)]==old_modules,'An original068 trust module changed')
    trusted={module[at:at+20].hex() for module in modules for at in range(24,len(module),24)}
    signature_checks={**j['metal_runtime']['signature_checks'],**j['metal_runtime'].get('extra_signature_checks',{})}
    for name,row in signature_checks.items():require(row['verified_code_pages']>0 and row['cdhash'] in trusted,'Signed runtime identity missing from trust: '+name)
    # Independently recompute every executable code-page digest from final FAT
    # bytes, rather than trusting the signing-side boolean.
    for name,row in addon.items():
        if row['data'][:4]!=b'\xcf\xfa\xed\xfe':continue
        data=row['data'];at=32;signature=None
        for _ in range(struct.unpack_from('<I',data,16)[0]):
            command,length=struct.unpack_from('<II',data,at)
            if command==0x1d:
                offset,size=struct.unpack_from('<II',data,at+8);signature=data[offset:offset+size]
            at+=length
        require(signature is not None,'Unsigned Mach-O member: '+name)
        magic,size,count=struct.unpack_from('>III',signature);require(magic==0xfade0cc0 and size<=len(signature),'Malformed signature')
        code_directory=None
        for i in range(count):
            kind,offset=struct.unpack_from('>II',signature,12+8*i)
            if kind==0:
                magic,length=struct.unpack_from('>II',signature,offset);require(magic==0xfade0c02 and offset+length<=size,'Invalid CodeDirectory');code_directory=signature[offset:offset+length]
        require(code_directory is not None,'CodeDirectory absent')
        cd=code_directory;hash_offset,_,_,slots,limit=struct.unpack_from('>IIIII',cd,16)
        hash_size,hash_type,_,page=struct.unpack_from('>BBBB',cd,36)
        require(hash_size==32 and hash_type==2 and page==12 and slots==(limit+4095)//4096,'Signature hash/page ABI differs')
        for i in range(slots):require(cd[hash_offset+32*i:hash_offset+32*(i+1)]==hashlib.sha256(data[i*4096:min(limit,(i+1)*4096)]).digest(),'Final code-page digest mismatch: '+name)
        require(hashlib.sha256(cd).hexdigest()[:40] in trusted,'Final Mach-O signature not trusted: '+name)
    detached=j['metal_runtime'].get('detached_signature_checks',{})
    require(set(detached)=={'xpc/launchd.plist'},'Missing source-qualified signed launchd cache')
    for name,expected in detached.items():
        require(name in addon and expected['signature_path'] in addon,'Missing detached-signature runtime member')
        raw=addon[name]['data'];signature=addon[expected['signature_path']]['data']
        identity=inspect_detached_signature(raw,signature,'launchd-'+hashlib.sha1(raw).hexdigest())
        require(identity['cdhash']==expected['cdhash'] and identity['cdhash'] in trusted and
            hashlib.sha256(raw).hexdigest()==expected['data_sha256'] and
            hashlib.sha256(signature).hexdigest()==expected['signature_sha256'],
            'Final launchd detached signature identity differs from trust/readback')
        require(identity['identification_wrapper']['matches_raw_plist_sha1'],
            'Final launchd raw-file identification is stale')
    firmware=j['metal_runtime'].get('radio_firmware')
    require(firmware and len(firmware['files'])==53 and firmware['phone_hashes_matched'],
        'Complete Sony phone/host firmware manifest required')
    for name,expected in firmware['files'].items():
        require(name in addon and len(addon[name]['data'])==expected['bytes'] and
            hashlib.sha256(addon[name]['data']).hexdigest()==expected['sha256'] and addon[name]['mode']==0o644,
            'Final captured Sony firmware differs: '+name)
    checks.update(detached_cache_signature_pages_verified=True,raw_cache_identification_verified=True,
        captured_sony_firmware_files_verified=53,apple_loader_runtime_verified=False)
    checks.update(runtime_addon_members=len(addon),all_original_trust_modules_preserved=len(old_modules),signature_pages_verified=True)
    sys.path.insert(0,str(ROOT/'ci/XnuPrelink'));from kc_image import Image
    kernel=files['kernel.macho'];collection=Image(kernel);member=Image(kernel,collection.entries['com.apple.kernel'][1])
    symbols={name:at for at,names in member.symbols().items() for name in names};fixups=collection.fixups()
    for name in ('_native_qemu_storage_start','_native_qemu_input_start','_native_virtio_cache_hits'):
        require(name not in symbols,'Virtual backend selected')
    for name in ('_native_source_storage_start','_native_legacy_pm_callbacks','_native_gpu_power_stage','_native_sony_touch_start'):
        require(name in symbols,'Physical backend missing')
    for key in ('handset_instruction_verification','platform069_linked_verification'):
        verification=j[key];require(verification['passed'] and verification['native_sha256']==j['native_sha256'] and
            verification['strict_sha256']==j['strict_kernel_sha256'],'Wrong final strict verification')
        for name,row in verification['implementations'].items():
            at=int(row['address'],16);require(symbols.get(name)==at and hashlib.sha256(member.read(at,row['bytes'])).hexdigest()==row['sha256'],
                'Actual final instruction body differs: '+name)
    metadata_segment=next(s for s in collection.segments if s['name']=='__PRELINK_INFO')
    metadata=plistlib.loads(kernel[metadata_segment['fileoff']:metadata_segment['fileoff']+metadata_segment['filesize']].split(b'\0',1)[0])
    rows=metadata['_PrelinkInfoDictionary'];require(len(rows)==38 and sum(len(row.get('IOKitPersonalities') or {}) for row in rows)==32,
        'Full driver closure/personalities were reduced')
    require(len(j['selected_profile']['roots'])==19,'Full profile roots changed')
    block=j['block_descriptor_abi'];globals=[]
    for address,names in member.symbols().items():
        if any('block_literal_global' in name for name in names):
            require(fixups[address+24][1:]==(1,2,0xc0bb,1),'Unsigned global Block descriptor')
            globals.append(dict(block=hex(address),descriptor_slot=hex(address+24),target=hex(fixups[address+24][0])))
    require(globals==block['global_descriptors'] and block['recompiled_objects']==66 and block['tamper_rejected'] and
        block['authenticated_copy_and_resign'] and block['old_runtime_data_abort_reproduced'],'Signed Blocks closure changed')
    touch=j['sony_touch_verification'];address=int(touch['firmware_address'],16)
    require(symbols['_native_sony_geni_firmware']==address and hashlib.sha256(member.read(address,touch['firmware_bytes'])).hexdigest()==touch['firmware_sha256'],
        'Embedded Sony GENI firmware changed')
    tables=[('touch','__ZTV14NativeHidInput',j['sony_touch_hid_abi']['compiled_vtable'],207)]
    for key,table_name,rows_key,count in [('buttons','__ZTV14SonyButtonsHid','compiled_vtable',207),('oled','__ZTV17SonyOledBacklight','compiled_table',168)]:
        if key in j['platform069_abi']:tables.append((key,table_name,j['platform069_abi'][key][rows_key],count))
    for name,table_name,rows,count in tables:
        require(len(rows)==count,'Wrong final '+name+' PAC table extent');table=symbols[table_name]+16
        for row in rows:require(fixups[table+8*row['slot']][1:]==(1,0,int(row['diversity'],16),1),'Final '+name+' PAC slot mismatch')
        checks[name+'_pac_slots']=count
    radio=j['platform069_linked_verification']['pac_tables']
    radio_slots=0
    for name,record in radio.items():
        if not name.startswith('radio:'):continue
        table=symbols[record['symbol']]+16
        for row in record['rows']:
            value=fixups.get(table+8*row['slot'])
            require(value is not None and value[1:]==(1,0,row['diversity'],1) and value[0]==int(row['target'],16),
                'Final radio PAC slot/target differs: '+name)
            radio_slots+=1
    require(radio_slots==928,'Full928 final radio PAC slots required')
    init=next(section for section in member.sections if (section['segment'],section['name'])==('__BOOTDATA','__init_entry_set'))
    startup=j['platform069_linked_verification']['radio_startup']['strict']
    require(len(startup['radio_records'])==5 and startup['actual_sort_stride']==24 and startup['actual_sort_compares_subsystem_rank'],
        'Actual Qca startup consumer qualification missing')
    for row in startup['radio_records']:
        at=symbols[row['name']]
        require(init['va']<=at<init['va']+init['size'] and (at-init['va'])%24==0 and
            member.read(at,8).hex()==row['order_fields_hex'] and
            fixups[at+8]==(symbols[row['function_symbol']],1,0,0x2abe,0) and
            fixups[at+16][0]==symbols[row['argument_symbol']], 'Final Qca startup record changed')
    checks.update(radio_pac_slots=928,qca_startup_records=5)
    data=next(s for s in collection.segments if s['name']=='__PDX_DATA')
    require(struct.unpack_from('<II',kernel,data['command_offset']+56)==(3,3),'Native data mapping is not RW/NX')
    old_kernel=Image(original.get('EFI/UniXNU/Payloads/kernel.macho'));old_fixups=old_kernel.fixups()
    for text in j['platform069_original_kmod_sites']:
        site=int(text,16);require(fixups[site]==old_fixups[site] and fixups[site][3]==0xe4fe,'Original Apple kmod PAC changed')
    require(len(j['platform069_original_kmod_sites'])==36,'Incomplete original kmod audit')
    statuses=j['platform069_feature_status']
    require(set(statuses)=={'heat','refresh','app_exits','wifi','bluetooth','brightness','power_key','touch'},'Missing feature-specific state')
    for name,row in statuses.items():require(isinstance(row['implemented'],bool) and row['hardware_verified'] is False and bool(row['limits']),'Unqualified new hardware claim: '+name)
    require(j['platform069']['baseline_native_sha256']==BASELINE_SHA and j['platform069']['all_baseline_archive_members_retained'],
        '069 baseline/driver provenance differs')
    checks.update(full_roots=19,closure_entries=38,matching_personalities=32,original_kmod_pac_fields=36,
        signed_blocks_inputs=66,global_block_descriptors=len(globals),actual_qualified_instruction_bodies_verified=True,
        native_rw_nx=True,temporary_touch_probes_removed=j['sony_touch']['temporary_probes_removed'],
        physical_068_baseline_inherited=True,all_menu_arguments_within1023=True)
    options.out.parent.mkdir(parents=True,exist_ok=True)
    with options.out.open('x') as stream:stream.write(json.dumps(checks,indent=2)+'\n')
    print(json.dumps(checks,indent=2))


if __name__=='__main__':main()
