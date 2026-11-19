"""Independently decode final boot transport and FAT on Windows."""
from pathlib import Path
import hashlib, importlib.util, json, lzma, struct, tomllib, zlib, argparse, plistlib
import sys

ROOT=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--release',type=Path,default=ROOT/'out/d27-pac-abi-release-20261115-030')
r=parser.parse_args().release
j=json.loads((r/'release.json').read_text())
raw=(r/Path(j['image']).name).read_bytes()
assert hashlib.sha256(raw).hexdigest()==j['sha256']
c=raw[4096:4096+struct.unpack_from('<I',raw,8)[0]]
off,length=struct.unpack('<8sIIQQQIIQQQQ',c[-80:])[-2:]
blob=c[off:off+length]
magic,header,packed,size,crc,res=struct.unpack_from('<8s4IQ',blob)
assert (magic,header,packed,res)==(b'PDXFAT02',32,len(blob)-32,0)
props,dictionary=blob[32],struct.unpack_from('<I',blob,33)[0]
lc=props%9;rest=props//9;lp=rest%5;pb=rest//5
decoder=lzma.LZMADecompressor(format=lzma.FORMAT_RAW,filters=[dict(id=lzma.FILTER_LZMA1,dict_size=dictionary,lc=lc,lp=lp,pb=pb)])
fat=decoder.decompress(blob[45:],max_length=size+1)
assert len(fat)==size and decoder.eof and not decoder.unused_data and zlib.crc32(fat)==crc
bps=struct.unpack_from('<H',fat,11)[0];spc=fat[13];reserved=struct.unpack_from('<H',fat,14)[0]
nf=fat[16];roots=struct.unpack_from('<H',fat,17)[0];fs=struct.unpack_from('<H',fat,22)[0]
total=struct.unpack_from('<H',fat,19)[0] or struct.unpack_from('<I',fat,32)[0]
rootsecs=(roots*32+bps-1)//bps
if not fs:fs=struct.unpack_from('<I',fat,36)[0]
data_sec=reserved+nf*fs+rootsecs;clusters=(total-data_sec)//spc;bits=16 if clusters<65525 else 32
assert clusters>=4085
def chain(cluster):
    out=bytearray();seen=set()
    while 2<=cluster<(0xfff8 if bits==16 else 0xffffff8):
        assert cluster not in seen;seen.add(cluster)
        at=(data_sec+(cluster-2)*spc)*bps;assert at+spc*bps<=len(fat)
        out+=fat[at:at+spc*bps]
        cluster=struct.unpack_from('<H' if bits==16 else '<I',fat,reserved*bps+cluster*(bits//8))[0] & (0xffff if bits==16 else 0xfffffff)
    return bytes(out)
root=fat[(reserved+nf*fs)*bps:(reserved+nf*fs+rootsecs)*bps] if bits==16 else chain(struct.unpack_from('<I',fat,44)[0])
def get(path):
    data=root
    for part in path.split('/'):
        long={};found=None
        for at in range(0,len(data),32):
            e=data[at:at+32]
            if not e or e[0]==0:break
            if e[0]==0xe5:long={};continue
            if e[11]==15:
                long[e[0]&31]=(e[1:11]+e[14:26]+e[28:32]).decode('utf-16-le');continue
            short=e[:8].decode().strip()+('.'+e[8:11].decode().strip() if e[8:11].strip() else '')
            name=''.join(long[k] for k in sorted(long)).split('\0')[0].rstrip('\uffff') if long else short
            long={}
            if name.lower()==part.lower():found=e;break
        assert found is not None,part
        cluster=struct.unpack_from('<H',found,26)[0]+(struct.unpack_from('<H',found,20)[0]<<16)
        data=chain(cluster)
        if not found[11]&16:data=data[:struct.unpack_from('<I',found,28)[0]]
    return data
checks={}
platform_labels=('PAC-ABI-067','PAC-ABI-068')
for name,expected in [('kernel.macho',j['payload_kernel_sha256']),('kernel.macho.adt',j['adt_sha256']),('kernel.macho.gpuaddon',j['metal_runtime']['addon_sha256']),('kernel.macho.trustcache',j['metal_runtime']['trust_sha256'])]:
    data=get('EFI/UniXNU/Payloads/'+name);assert hashlib.sha256(data).hexdigest()==expected,name
    checks[name]=expected
spec=importlib.util.spec_from_file_location('adt',ROOT/'scripts/apple-device-tree.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
t=m.parse(get('EFI/UniXNU/Payloads/kernel.macho.adt'));chosen=t['children']['chosen']['properties']
for key,value in [('dram-base',0x980000000),('dram-size',0x180000000),('darwinboot-memory-size',0x130000000)]:
    assert struct.unpack('<Q',chosen[key])[0]==value
assert struct.unpack('<I',t['children']['defaults']['properties']['kern.maxvnodes'])[0]==78848
assert len(t['children']['cpus']['children'])==8
config=tomllib.loads(get('EFI/UniXNU/unixnu.toml').decode())
if 'menu_title' in j:assert config['ui']['title']==j['menu_title']
if 'menu_default' in j:assert config['boot']['default']==j['menu_default']
assert next(e for e in config['entry'] if e['id']=='xnu')['args']==j['kernel_args']
sys.path.insert(0,str(ROOT/'ci'))
from darwin_boot_args import validate as validate_darwin_boot_args
command_line=validate_darwin_boot_args(j['kernel_args'])
checks.update(darwinboot_command_line_fits=True,darwinboot_command_line_bytes=command_line['ascii_bytes'],
              darwinboot_command_line_capacity=command_line['capacity_bytes'])
android_bytes=struct.unpack('<8sIIQQQIIQQQQ',c[-80:])[4]
android=c[0x200000:0x200000+android_bytes];assert hashlib.sha256(android).hexdigest()==j['original_android_sha256']
mem=struct.unpack_from('<Q',android,16)[0];fd=c[0x200000+mem:0x200000+mem+0x300000]
assert hashlib.sha256(fd).hexdigest()==j['firmware_sha256']
if j.get('cdc_disabled'):
    import uuid
    spec=importlib.util.spec_from_file_location('fv',ROOT/'scripts/check-firmware-services.py')
    fv=importlib.util.module_from_spec(spec);spec.loader.exec_module(fv)
    files=fv.volume_files(fd)
    assert '9eb02581-63fc-44ee-a820-49ced6493f12' not in files
    service=uuid.UUID('765f0768-b70e-43cc-917d-8f213169dc42').bytes_le
    assert not any(service in data for sections in files.values() for kind,data in sections if kind==0x10)
    args=next(e for e in config['entry'] if e['id']=='xnu')['args'].split()
    assert [arg for arg in args if arg.startswith('qcom-usb-debug=')]==['qcom-usb-debug=0']
    assert config['boot']['default']=='xnu' and 'iOS 27' in config['ui']['title']
    checks.update(uefi_cdc_absent=True,xnu_cdc_disabled=True)
if j.get('gpu_enabled'):
    args=next(e for e in config['entry'] if e['id']=='xnu')['args'].split()
    for key,value in [('gpu-power','9'),('gpu-metal','1'),('sheng-gpu-addon','1'),('fb-gpu','1'),('qcom-usb-debug','0' if j.get('cdc_disabled') else '1'),('dpu-scanout','0')]:
        assert [arg for arg in args if arg.startswith(key+'=')]==[key+'='+value]
    if j.get('usb_core_errors_fixed'):
        spec=importlib.util.spec_from_file_location('fv',ROOT/'scripts/check-firmware-services.py')
        fv=importlib.util.module_from_spec(spec);spec.loader.exec_module(fv)
        spec=importlib.util.spec_from_file_location('core_errors',ROOT/'ci/sony_usb_core_errors.py')
        fix=importlib.util.module_from_spec(spec);spec.loader.exec_module(fix)
        original=ROOT.parent/'uefi-pdx234/Binaries/pdx234/QcomPkg/Drivers/UsbfnDwc3Dxe/UsbfnDwc3Dxe.efi'
        pe=next(data for kind,data in fv.volume_files(fd)['94f8a6a7-dc34-4101-88c1-99179cceae83'] if kind==0x10)
        if j.get('usb_core_trace'):
            assert j['usb_core_errors_tests'].get('trace_wrappers')
            base=fix.adapt_pe(original.read_bytes())
            import sys
            sys.path.insert(0,str(ROOT/'ci'))
            from sony_usb_poll_errors import adapt_pe as fix_poll
            base=fix_poll(base)
            sites=[item['site'] for item in j['usb_core_errors_tests']['trace_sites']]
            allowed=set(range(0x16600,0x16f00))|set(range(0xec0c,0xec10))|{i for site in sites for i in range(site,site+4)}
            assert len(pe)==len(base)
            assert all(a==b or i in allowed for i,(a,b) in enumerate(zip(pe,base)))
            assert hashlib.sha256(pe[0x16600:0x16f00]).hexdigest()==j['usb_core_errors_tests']['trace_region_sha256']
            assert pe[0xec0c:0xec10].hex()==j['usb_core_errors_tests']['qscratch_entry_bytes']
            for item in j['usb_core_errors_tests']['trace_sites']:
                site=item['site'];opcode=0x14000000 if item['tail'] else 0x94000000
                assert struct.unpack_from('<I',pe,site)[0]==opcode|(((item['wrapper']-site)//4)&0x3ffffff)
            checks['usb_core_trace_pe_verified']=True
        else:
            assert pe==fix.adapt_pe(original.read_bytes())
        assert j['usb_core_errors_tests']['tested_pe_sha256']==hashlib.sha256(pe).hexdigest()
        checks['usb_core_error_pe_verified']=True
        if j.get('usb_prepare_errors'):
            cfg=next(data for kind,data in fv.volume_files(fd)['cd823a4d-7dec-4531-ae5d-4134fa4127b8'] if kind==0x10)
            assert j['usb_prepare_errors_tests']['passed']
            assert hashlib.sha256(cfg).hexdigest()==j['usb_prepare_errors_tests']['traced_sha256']
            checks['usb_prepare_error_pe_verified']=True
    elif not j.get('cdc_disabled'):
        assert j['firmware_sha256']=='ec2ce4d8cbc05c4c56aa869e3de8958253c5143223501b7cab00a47eae2c8b3a'
        checks['cdc049_firmware_preserved']=True
    checks.update(gpu_arguments_enabled=True,tablet_direct_scanout_disabled=True)
if j.get('label') in ('PAC-ABI-055','PAC-ABI-056','PAC-ABI-057','PAC-ABI-058','PAC-ABI-059','PAC-ABI-060','PAC-ABI-061','PAC-ABI-062','PAC-ABI-063','PAC-ABI-064','PAC-ABI-065','PAC-ABI-066',*platform_labels):
    assert j.get('cdc_disabled') and j.get('gpu_enabled')
    assert ('build-tag=PDX'+j['label'][-3:]) in j['kernel_args'].split()
    trust=get('EFI/UniXNU/Payloads/kernel.macho.trustcache')
    count=struct.unpack_from('<I',trust)[0]
    assert 1<count<32
    starts=list(struct.unpack_from('<'+'I'*count,trust,4))+[len(trust)]
    assert starts[0]>=4+4*count and all(a<b for a,b in zip(starts,starts[1:]))
    modules=[trust[a:b] for a,b in zip(starts,starts[1:])]
    for module in modules:
        assert len(module)>=24 and struct.unpack_from('<I',module)[0]==2
        assert len(module)==24+24*struct.unpack_from('<I',module,20)[0]
    entries={modules[-1][at:at+20].hex() for at in range(24,len(modules[-1]),24)}
    for name in ['plugin','turnip']:
        assert j['metal_runtime']['signature_checks'][name]['cdhash'] in entries
    checks['metal_signed_identities_in_trust']=True
    addon=get('EFI/UniXNU/Payloads/kernel.macho.gpuaddon')
    assert addon[:8]==b'NGPUADD2'
    count,_,length=struct.unpack_from('<IIQ',addon,8)
    assert length==len(addon) and 0<count<=1024
    expected={item['path']:item for item in j['metal_runtime']['files']}
    assert len(expected)==len(j['metal_runtime']['files'])==count
    seen=set();at=24
    for _ in range(count):
        plen,mode,size,packed=struct.unpack_from('<IIQQ',addon,at);at+=24
        assert 1<plen<=4096 and at+plen<=len(addon)
        name=addon[at:at+plen];assert name[-1]==0;name=name[:-1].decode();at+=(plen+7)&-8
        assert name not in seen and name in expected and at+packed<=len(addon)
        seen.add(name);entry=expected[name];assert entry['bytes']==size and entry['mode']==mode
        decompressor=zlib.decompressobj()
        data=decompressor.decompress(addon[at:at+packed],size+1)
        assert decompressor.eof and not decompressor.unused_data and not decompressor.unconsumed_tail
        assert len(data)==size and hashlib.sha256(data).hexdigest()==entry['sha256']
        if j['label'] in ('PAC-ABI-056','PAC-ABI-057','PAC-ABI-058','PAC-ABI-059','PAC-ABI-060','PAC-ABI-061','PAC-ABI-062','PAC-ABI-063','PAC-ABI-064','PAC-ABI-065','PAC-ABI-066',*platform_labels) and name.endswith('/libvulkan_freedreno.dylib'):
            assert hashlib.sha256(data).hexdigest()=='540cef9e278693dc8562f36e596ae4632214671ad3a0e57a95ed4ee48d4b360f'
            command_at=32;aligned=False
            for _ in range(struct.unpack_from('<I',data,16)[0]):
                command,command_size=struct.unpack_from('<II',data,command_at)
                if command==2:
                    assert struct.unpack_from('<I',data,command_at+16)[0]%8==0
                    aligned=True
                command_at+=command_size
            assert aligned
            checks['turnip_matches_qemu_loading_candidate']=True
        at+=(packed+7)&-8
    assert at==len(addon)
    checks['metal_addon_members_verified']=count
if j.get('menu_confirmation_removed'):
    assert config['boot']['default']=='xnu' and config['boot']['timeout']==-1
    assert 'confirm' not in next(e for e in config['entry'] if e['id']=='xnu')
    checks['manual_ios_default_without_confirmation_conflict']=True
if j.get('first_frame_diagnostics'):
    args=next(e for e in config['entry'] if e['id']=='xnu')['args'].split()
    for item in ('first-frame-diag=1','gpu-trace=1','sheng-gpu-trace=1'):
        assert [arg for arg in args if arg.split('=')[0]==item.split('=')[0]]==[item]
    assert j['boot_screen']['first_frame_diagnostics'] and j['functional_first_frame_fix_claimed'] is False
    assert j['framebuffer_call_trace']['verified']
    assert j['swift_trap_diagnostic']['verified']
    kernel=get('EFI/UniXNU/Payloads/kernel.macho')
    for marker in (b'FIRSTFRAME %us trace=%d',b'FB hex calls=',b'GP no worker sample yet',b'PROC %.23s pid=%u'):
        assert marker in kernel,marker
    checks['complete_first_frame_diagnostic_switches']=True
if j.get('label') in platform_labels:
    args=next(e for e in config['entry'] if e['id']=='xnu')['args'].split()
    for item in ('first-frame-diag=0','gpu-trace=0','sheng-gpu-trace=0'):
        assert [arg for arg in args if arg.split('=')[0]==item.split('=')[0]]==[item]
    assert not j['first_frame_diagnostics'] and j['temporary_probe_cleanup']
    assert j['boot_screen']['thirty_ms_touch_worker_removed']
    kernel=get('EFI/UniXNU/Payloads/kernel.macho')
    for marker in (b'FIRSTFRAME %us trace=%d',b'FB hex calls=',b'GP no worker sample yet',b'PROC %.23s pid=%u'):
        assert marker not in kernel,marker
    checks['completed_first_frame_painters_and_trace_switches_disabled']=True
if j.get('minimal_driver_control'):
    args=next(e for e in config['entry'] if e['id']=='xnu')['args'].split()
    assert [arg for arg in args if arg.startswith('cpufreq=')]==['cpufreq=0']
    assert j['baseline_kernel_byte_identity'] is False and j['native_kernel_byte_identity']
    assert j['retained_executable_bytes_unchanged'] and j['gpu_enabled'] and j['cdc_disabled']
    assert j['strict_kernel_sha256']=='a57854987d193a6f647dd41065f808879728e7c2ba381f362e8f208be4ce951f'
    profile=ROOT/'profiles/ios-27.0.1-24A446-iphone14/minimal-graphics-prelink.toml'
    assert hashlib.sha256(profile.read_bytes()).hexdigest()==j['minimal_prelink_profile_sha256']
    assert len(j['minimal_prelink_roots'])==10 and 'com.apple.iokit.IOGPUFamily' in j['minimal_prelink_roots']
    assert len(j['suppressed_matching_personalities'])==7
    kernel=get('EFI/UniXNU/Payloads/kernel.macho');at=32;metadata=None
    for _ in range(struct.unpack_from('<I',kernel,16)[0]):
        cmd,size=struct.unpack_from('<II',kernel,at);assert size>=8 and at+size<=len(kernel)
        if cmd==0x19 and kernel[at+8:at+24].rstrip(b'\0')==b'__PRELINK_INFO':
            start,length=struct.unpack_from('<QQ',kernel,at+40);assert start+length<=len(kernel)
            metadata=plistlib.loads(kernel[start:start+length].split(b'\0',1)[0])
        at+=size
    assert metadata is not None
    personalities={row['CFBundleIdentifier']:row.get('IOKitPersonalities') or {} for row in metadata['_PrelinkInfoDictionary']}
    assert len(personalities)==38 and sum(len(v) for v in personalities.values())==25
    for bundle in ('com.apple.driver.AppleM2ScalerCSCDriver','com.apple.driver.IODARTFamily','com.apple.iokit.IOAVFamily'):
        assert not personalities[bundle]
    assert 'AppleImage4' in personalities['com.apple.security.AppleImage4']
    assert 'FirstPersonality' in personalities['com.apple.iokit.IOSurface']
    assert personalities['com.apple.iokit.IOHIDFamily']
    assert hashlib.sha256(plistlib.dumps(personalities,sort_keys=True)).hexdigest()==j['matching_selection']['metadata_sha256']
    checks['optional_matching_personalities_suppressed']=7
    checks['required_matching_personalities_retained']=25
    checks['minimal_driver_control_gpu_on_cpufreq_off']=True
if j.get('label') in ('PAC-ABI-060','PAC-ABI-061','PAC-ABI-062','PAC-ABI-063','PAC-ABI-064','PAC-ABI-065','PAC-ABI-066',*platform_labels):
    assert j['physical_058_derived'] and j['virtual_backends_selected'] is False
    assert not j.get('minimal_driver_control') and not j.get('minimal_drivers')
    kernel=get('EFI/UniXNU/Payloads/kernel.macho')
    import sys
    sys.path.insert(0,str(ROOT/'ci/XnuPrelink'))
    from kc_image import Image
    collection=Image(kernel);member=Image(kernel,collection.entries['com.apple.kernel'][1])
    symbols={name:address for address,names in member.symbols().items() for name in names}
    verification=j['handset_instruction_verification']
    assert verification['passed'] and verification['virtual_backends_selected'] is False
    assert verification['native_sha256']==j['native_sha256']
    assert verification['strict_sha256']==j['strict_kernel_sha256']
    for name,row in verification['implementations'].items():
        address=int(row['address'],16)
        assert symbols[name]==address
        assert hashlib.sha256(member.read(address,row['bytes'])).hexdigest()==row['sha256'],name
    for name in ('_native_qemu_storage_start','_native_qemu_input_start','_native_virtio_cache_hits'):
        assert name not in symbols
    for name in ('_native_source_storage_start','_native_gpu_power_stage','_native_legacy_pm_callbacks'):
        assert name in symbols
    metadata=None;command_at=32
    for _ in range(struct.unpack_from('<I',kernel,16)[0]):
        command,size=struct.unpack_from('<II',kernel,command_at)
        if command==0x19 and kernel[command_at+8:command_at+24].rstrip(b'\0')==b'__PRELINK_INFO':
            start,length=struct.unpack_from('<QQ',kernel,command_at+40)
            metadata=plistlib.loads(kernel[start:start+length].split(b'\0',1)[0])
        command_at+=size
    personalities={row['CFBundleIdentifier']:row.get('IOKitPersonalities') or {} for row in metadata['_PrelinkInfoDictionary']}
    assert len(personalities)==38 and sum(len(v) for v in personalities.values())==32
    for bundle in ('com.apple.driver.AppleM2ScalerCSCDriver','com.apple.driver.IODARTFamily','com.apple.iokit.IOAVFamily'):
        assert personalities[bundle]
    assert len(j['selected_profile']['roots'])==19
    checks.update(physical_storage_display_selected=True,full058_roots=19,full058_closure_entries=38,
        full058_matching_personalities=32,pm_and_three_upstream_instruction_bodies_verified=True)
    if j['label'] in ('PAC-ABI-061','PAC-ABI-062','PAC-ABI-063','PAC-ABI-064','PAC-ABI-065','PAC-ABI-066',*platform_labels):
        expected_source=('929e240b9a9910e2496eaa736794a2b74030b06d4a9b4202d2cb8825bd59e901' if j['label']=='PAC-ABI-068' else
            '4f5984cce75fbf59f22628cb3025739bc05fa52fe7b613d121fe724e4462e456' if j['label']=='PAC-ABI-067' else
            '618d2c3bf69e9aacb1d962c5e4f6fc00afb61fbf7c3ce52903501fa00515fb0c')
        assert j['source_image_sha256']==expected_source
        for expected in ('sony-touch=1','touch-hid=1'):
            assert [v for v in args if v.split('=')[0]==expected.split('=')[0]]==[expected]
        if j['label']=='PAC-ABI-061':assert j['sony_touch']['cold_boot_init_implemented']
        else:
            assert j['sony_touch']['inherited_engine_init_implemented'] and j['sony_touch']['se_dma_implemented']
            assert j['sony_touch']['protected_alias_access'] is False
        assert not j['sony_touch']['virtual_backend_included']
        for name in ('_native_sony_touch_start','_sony_geni_firmware_init','_sony_geni_poll','_sw82907_decode','_sony_hid_touch_plan'):
            assert name in symbols
        for name in ('_native_virtio_input_probe','_native_touch_probe'):
            assert name not in symbols
        value=j['sony_touch_verification'];firmware_address=int(value['firmware_address'],16)
        assert symbols['_native_sony_geni_firmware']==firmware_address
        firmware=member.read(firmware_address,value['firmware_bytes'])
        assert len(firmware)==1585 and hashlib.sha256(firmware).hexdigest()=='0840aa323be767f134050cf8ff365b9e4675063863a8a34adc18343b978224e4'
        assert hashlib.sha256(firmware).hexdigest()==j['sony_touch']['geni_firmware']['firmware_sha256']
        table=symbols['__ZTV14NativeHidInput']+16;fixups=collection.fixups()
        rows=j['sony_touch_hid_abi']['compiled_vtable'];assert len(rows)==207
        for row in rows:
            assert fixups[table+8*row['slot']][1:]==(1,0,int(row['diversity'],16),1),row['slot']
        assert j['display_source']['sony_touch_start_connected']
        gpu_marker=b'[pdx061-gpu] sample=' if j['label']=='PAC-ABI-061' else b'[pdx062-gpu] sample='
        if j['label'] in platform_labels:
            assert j['sony_touch']['temporary_probes_removed'] and not j['boot_screen']['sony_touch_rows_enabled']
            assert j['boot_screen']['touch_test_painter_removed'] and j['boot_screen']['thirty_ms_touch_worker_removed']
            assert gpu_marker not in kernel and b'TOUCH s%u e%d' not in kernel and b'[sony-touch-registry]' not in kernel
            assert '_native_sony_cpu_snapshot' not in symbols and not j['sony_touch']['per_cpu_runtime_recorder']
            checks['temporary_touch_probes_and_painters_removed']=True
        else:
            assert j['boot_screen']['sony_touch_rows_enabled']
            assert gpu_marker in kernel and b'TOUCH s%u e%d' in kernel
        if j['label'] in ('PAC-ABI-062','PAC-ABI-063','PAC-ABI-064','PAC-ABI-065','PAC-ABI-066',*platform_labels):
            assert '_sony_geni_prepare_dma' in symbols
            if j['label'] not in platform_labels:assert b'[sony-touch-bus]' in kernel
            checks.update(sony_fifo_or_se_dma_selected=True,protected_geni_alias_access_disabled=True)
        checks.update(sony_sw82907_touch_selected=True,sony_geni_firmware_verified=True,
            sony_d27_hid_pac_slots=207,touch_and_gpu_progress_recorder_present=j['label'] not in platform_labels,
            virtual_or_novatek_input_absent=True)
        if j['label'] in ('PAC-ABI-063','PAC-ABI-064','PAC-ABI-065','PAC-ABI-066',*platform_labels):
            block=j['block_descriptor_abi']
            assert block['passed'] and block['authenticated_copy_and_resign'] and block['tamper_rejected']
            assert block['old_runtime_data_abort_reproduced']
            assert block['recompiled_objects']==66 and block['producer_objects']==63
            assert block['audited_link_inputs']==1083 and block['global_descriptor_count']>0
            actual_globals=[]
            for address,names in member.symbols().items():
                if any('block_literal_global' in name for name in names):
                    value=fixups[address+24]
                    assert value[1:]==(1,2,0xc0bb,1)
                    actual_globals.append(dict(block=hex(address),descriptor_slot=hex(address+24),target=hex(value[0])))
            assert actual_globals==block['global_descriptors'] and len(actual_globals)==block['global_descriptor_count']
            for name in ('__Block_copy','_Block_size','__Block_release','__Block_signature','__Block_extended_layout'):
                assert name in verification['implementations']
            checks.update(block_descriptor_authenticated_consumers_verified=True,
                block_descriptor_global_pac_slots=len(actual_globals),block_descriptor_recompiled_objects=66)
        if j['label'] in ('PAC-ABI-064','PAC-ABI-065','PAC-ABI-066',*platform_labels):
            for expected in ('banner=0','boot-diag-resume=0'):
                assert [v for v in args if v.split('=')[0]==expected.split('=')[0]]==[expected]
            assert j['ui_overlay_disabled'] and j['ui_timed_takeover_disabled']
            assert j['sony_touch']['engine_irq_registered_before_mask']
            for name in (('_sony_touch_irq_prepare',) if j['label'] in platform_labels else ('_sony_touch_irq_prepare','_native_sony_cpu_snapshot')):
                assert name in symbols and name in verification['implementations']
            if j['label'] not in platform_labels:
                assert j['sony_touch']['per_cpu_runtime_recorder']
                for text in (b'[pdx-cpu-summary]',b'[pdx-cpu] core=',b'[sony-touch-path]'):
                    assert text in kernel
            checks.update(ui_live_overlay_disabled=True,ui_timed_takeover_disabled=True,
                touch_route_attached_before_mask_verified=True,per_cpu_state_recorder_present=j['label'] not in platform_labels,
                all_eight_cpus_runtime_verified=False)
        if j['label'] in ('PAC-ABI-065','PAC-ABI-066',*platform_labels):
            assert j['sony_touch']['dma_done_is_completion'] and j['sony_touch']['late_hid_match_retried']
            expected_regressions={'chain','hid_parser','hid_delivery'}
            if j['label'] in ('PAC-ABI-066',*platform_labels):expected_regressions.add('boot_policy')
            assert set(j['sony_touch']['chain_regressions'])==expected_regressions
            for text in ((b'[sony-touch-sensor]',b'[sony-touch-engine]') if j['label'] in platform_labels else (b'[sony-touch-sensor]',b'[sony-touch-engine]',b'[sony-touch-chain]',b'[sony-touch-registry]')):
                assert text in kernel
            checks.update(vendor_dma_completion_and_hid_retry_receipts_present=True,full_touch_chain_diagnostics_present=j['label'] not in platform_labels)
        if j['label'] in ('PAC-ABI-066',*platform_labels):
            assert j['sony_touch']['sw82907_vendor_boot_policy'] and j['sony_touch']['boot_skip_requires_version_and_scan_status']
            assert [v for v in args if v.startswith('build-tag=')]==['build-tag=PDX'+j['label'][-3:]]
            assert 'com.apple.iokit.IOHIDEventDriver' not in j['selected_profile']['roots']
            for name in ('_sw82907_boot_result','_sw82907_code_crc_result','_sw82907_version_supported'):
                assert name in symbols and name in verification['implementations']
            assert b'[sony-touch-boot]' in kernel and b'[sony-touch-drive]' in kernel
            checks.update(sony_vendor_boot_policy_present=True,independent_sensor_version_and_scan_gates_present=True)
        if j['label'] in platform_labels:
            assert j['physical_066_derived'] and j['platform067']['baseline_native_sha256']=='80b2b18120eafde479aa2eaebd4017a677a67405b0ba0fe33e8d00ad6b6bc3dc'
            platform=j['platform067_linked_verification']
            assert platform['passed'] and platform['native_sha256']==j['native_sha256'] and platform['strict_sha256']==j['strict_kernel_sha256']
            assert platform['actual_signed_blocks_inputs_verified']==66
            for name,row in platform['implementations'].items():
                address=int(row['address'],16)
                assert symbols[name]==address
                assert hashlib.sha256(member.read(address,row['bytes'])).hexdigest()==row['sha256'],name
            extra_abi=j.get('platform067_abi',{})
            for key,table_name,rows_key,expected_slots in (
                ('buttons','__ZTV14SonyButtonsHid','compiled_vtable',207),
                ('oled','__ZTV17SonyOledBacklight','compiled_table',168)):
                if key not in extra_abi:continue
                rows=extra_abi[key][rows_key]
                assert len(rows)==expected_slots
                table=symbols[table_name]+16
                for row in rows:
                    assert fixups[table+8*row['slot']][1:]==(1,0,int(row['diversity'],16),1)
                checks['sony_'+key+'_final_pac_slots']=expected_slots
            statuses=j.get('platform067_feature_status',{})
            assert set(statuses)=={'heat','refresh','app_exits','wifi','bluetooth','brightness','power_key','touch'}
            assert all(v['hardware_verified'] is False and v['limits'] for v in statuses.values())
            assert statuses['refresh']['implemented'] is False
            assert statuses['wifi']['implemented'] is False and statuses['bluetooth']['implemented'] is False
            assert statuses['brightness']['implemented'] is False
            seed=get('EFI/UniXNU/Payloads/scratch-data.img')
            assert hashlib.sha256(seed).hexdigest()==j['volatile_seed']['seed_sha256']
            assert seed[:8]==b'DBRDISK1' and struct.unpack_from('<Q',seed,16)[0]==j['volatile_seed']['logical_bytes']==2147483648
            assert j['volatile_seed']['persistence_mode']==0 and 'data-persist=0' in args
            for name in j['platform067'].get('startup_calls',[]):
                assert '_'+name in symbols
            if j.get('platform067_radio'):
                for item in ('wifi=0','bluetooth=0'):
                    assert [v for v in args if v.split('=')[0]==item.split('=')[0]]==[item]
                checks['radio_sources_linked_but_missing_firmware_and_provider_disabled']=True
            if (j.get('platform067_buttons') or {}).get('source_qualified_experimental_power_volume_up'):
                for item in ('sony-buttons=1','sony-buttons-read-qualified=1','sony-buttons-pon-apid=560'):
                    assert [v for v in args if v.split('=')[0]==item.split('=')[0]]==[item]
                assert not any(v.startswith('sony-buttons-gpio-apid=') for v in args)
                checks['power_volume_up_source_qualified_experimental_apid560']=True
            for item in ('cpufreq=4','gpu-dcvs=1','gpu-dcvs-min=4','vsync=120'):
                assert [v for v in args if v.split('=')[0]==item.split('=')[0]]==[item]
            checks['sony_governors_enabled_and_software_vsync120_requested']=True
            checks.update(physical066_and_blocks_inherited=True,volatile_data_seed_mib=2048,persistence_disabled=True)
            if j['label']=='PAC-ABI-068':
                assert j['payload_kernel_sha256']=='f204912a04e8a922e0b9f2897991252befe3fca35f4fc5919b6242859950ef0a'
                fix=j['darwinboot_args_fix']
                assert fix['prior_argument_bytes']==1041 and fix['argument_bytes']==1006
                assert fix['only_config_changed'] and fix['kernel_byte_identical_to067'] and fix['no_auth_or_abi_changes']
                assert fix['removed_explicit_defaults']==['gpu-fence-wake=1','gpu-pause-us=1000']
                assert command_line['ascii_bytes']==1006
                assert not any(v.split('=')[0] in ('gpu-fence-wake','gpu-pause-us') for v in args)
                checks.update(darwinboot_pre_kernel_overflow_fixed=True,all067_payload_bytes_except_config_retained=True)
owned=0x130000000
pages=2+sum(((a&((1<<30)-1))+owned+(1<<30)-1)//(1<<30) for a in [0x980004000,0xfffffff007004000])
assert pages<=16
checks.update(image_sha256=j['sha256'],firmware_sha256=j['firmware_sha256'],raw_lzma_crc_verified=True,
              owned_memory_mib=4864,maxvnodes=78848,cpu_count=8,bootstrap_pages_needed=pages,
              bootstrap_pages_available=16,windows_independent_fat_readback=True,hardware_verified=False)
(r/'final-readback.json').write_text(json.dumps(checks,indent=2)+'\n')
print(json.dumps(checks,indent=2))
