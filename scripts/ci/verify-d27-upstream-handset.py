#!/usr/bin/env python3
"""Verify the actual physical strict kernel contains the four reviewed repairs."""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--native',type=Path,required=True)
    p.add_argument('--strict',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--touch',type=Path)
    p.add_argument('--block-tests',type=Path)
    a=p.parse_args()
    if a.out.exists():raise ValueError('Preserve existing verification')
    n=json.loads((a.native/'result.json').read_text())
    s=json.loads((a.strict/'result.json').read_text())
    k=json.loads((a.strict/'kernel.json').read_text())
    if (sha(a.native/'native.macho')!=n['native_sha256'] or s['native_sha256']!=n['native_sha256'] or
            sha(a.strict/'kernel.macho')!=s['candidate_sha256'] or k['candidate_sha256']!=s['candidate_sha256'] or
            k['missing'] or k['stubbed'] or k['allow_missing'] or not k['candidate_written'] or
            s['pac_metadata_adapters'] or s['auth_instruction_patches'] or not s['pac_enabled'] or
            not n.get('physical_058_derived') or n.get('virtual_backends_selected') is not False):
        raise ValueError('Require the completed physical058-derived strict PAC collection')
    sys.path.insert(0,str(ROOT/'ci'))
    from native_source_overlays import validate_overlays
    validate_overlays(n,sha)
    sys.path.insert(0,str(a.strict/'XnuPrelink'))
    from kc_image import Image
    raw=(a.strict/'kernel.macho').read_bytes();image=Image(raw)
    member=Image(raw,image.entries['com.apple.kernel'][1])
    names={name:address for address,values in member.symbols().items() for name in values}
    starts=member.function_starts()
    for forbidden in ('_native_qemu_storage_start','_native_qemu_input_start','_native_virtio_cache_hits'):
        if forbidden in names:raise ValueError('Virtual transport leaked into handset kernel: '+forbidden)
    for required in ('_native_source_storage_start','_native_legacy_pm_callbacks','_native_gpu_power_stage'):
        if required not in names:raise ValueError('Physical implementation absent: '+required)
    a.out.mkdir(parents=True)
    bodies={}
    def disasm(name,length=None):
        address=names[name]
        if length is None:length=starts[bisect.bisect_right(starts,address)]-address
        code=member.read(address,length)
        data='\n'.join(' '.join(f'0x{byte:02x}' for byte in code[i:i+4]) for i in range(0,len(code),4))
        done=subprocess.run(['llvm-mc-23','--disassemble','--triple=aarch64','--mattr=+v8.3a,+pauth,+lse'],
            input=data,capture_output=True,text=True,check=True,timeout=20)
        lines=[line.strip() for line in done.stdout.splitlines() if line.strip() and line.strip()!='.text']
        if len(lines)!=len(code)//4:raise ValueError('Instruction decoder omitted bytes: '+name)
        result='\n'.join(lines)
        destination=a.out/(name.replace('/','_')+'.asm')
        destination.write_text('\n'.join(f'{address+4*i:#x} {line}' for i,line in enumerate(lines))+'\n')
        bodies[name]=dict(address=hex(address),bytes=length,sha256=hashlib.sha256(code).hexdigest(),
            disassembly=str(destination),disassembly_sha256=sha(destination))
        return result
    preflight=disasm('_mmu_kvtop_wpreflight')
    if not ('at\ts1e1w, x0\nisb\nmrs\tx1, PAR_EL1' in preflight):
        raise ValueError('PAR_EL1 read is not synchronized after AT S1E1W')
    pm=disasm('__ZN10IOWorkLoop23eventSourcePerformsWorkEP13IOEventSource')
    if (pm.count('autda')!=2 or pm.count('autia')!=2 or 'cmp\tx8, x16' not in pm or
            'movk\tx17, #9038, lsl #48' not in pm or 'autiza' in pm or 'pacia' in pm):
        raise ValueError('Actual PM comparison does not authenticate the qualified implementation slots')
    for vector in ('el0_synchronous_vector_64_long','el0_irq_vector_64_long'):
        entry=disasm(vector,100)
        if not ('mrs\tx0, SCTLR_EL1' in entry and 'msr\tSCTLR_EL1, x0\nisb' in entry and
                entry.index('msr\tSCTLR_EL1, x0')<entry.index('autda')):
            raise ValueError('EL0 entry does not enable kernel PAC before pointer authentication')
    returns=disasm('exception_return_unint_tpidr_x3_restore_x18',344)
    if not ('ldr\tw2, [x2, #268]' in returns and 'tbz\tw2, #0' in returns and
            'bic\tx2, x2, x3\nmsr\tSCTLR_EL1, x2' in returns and 'eret' in returns):
        raise ValueError('arm64 user PAC transition missing from actual return path')
    tail=returns.split('msr\tSCTLR_EL1, x2',1)[1].split('eret',1)[0]
    if any(op in tail for op in ('autia','autib','autda','autdb','pacia','pacib','bl\t','blr')):
        raise ValueError('PAC or function call occurs after disabling keys for arm64 EL0')
    statfs=disasm('_vfs_get_statfs64')
    if not ('str\tx8, [x20, #48]' in statfs and 'ldr\tx8, [x16, #192]' in statfs and
            statfs.count('str\tx8, [x20, #48]')==2):
        raise ValueError('Root-union statfs FSID branch absent')
    jop=disasm('_ml_default_jop_pid')
    if 'mov\tw0, #1' not in jop:raise ValueError('Shared-region JOP selector must remain nonzero')
    command_at=32;metadata=None
    for _ in range(struct.unpack_from('<I',raw,16)[0]):
        cmd,size=struct.unpack_from('<II',raw,command_at)
        if cmd==0x19 and raw[command_at+8:command_at+24].rstrip(b'\0')==b'__PRELINK_INFO':
            at,length=struct.unpack_from('<QQ',raw,command_at+40)
            metadata=plistlib.loads(raw[at:at+length].split(b'\0',1)[0])
        command_at+=size
    rows=metadata['_PrelinkInfoDictionary'] if metadata else []
    personalities={row['CFBundleIdentifier']:row.get('IOKitPersonalities') or {} for row in rows}
    if len(k['closure'])!=38 or len(rows)!=38 or sum(len(v) for v in personalities.values())!=32:
        raise ValueError('Full058 dependency/personality selection was not retained')
    for bundle in ('com.apple.driver.AppleM2ScalerCSCDriver','com.apple.driver.IODARTFamily','com.apple.iokit.IOAVFamily'):
        if not personalities[bundle]:raise ValueError('059 personality suppression was retained')
    if len(s['selected_profile']['roots'])!=19 or len(s['original_kmod_fields_verified'])!=36:
        raise ValueError('Full profile/original kmod PAC checks differ')
    record=dict(passed=True,native_sha256=n['native_sha256'],strict_sha256=s['candidate_sha256'],
        implementations=bodies,pm_authenticated_vptr_and_slot=True,par_translation_synchronized=True,
        kernel_pac_restored_on_el0_entry=True,arm64_user_pac_transition=True,root_union_statfs_identity=True,
        shared_region_jop_selector_nonzero=True,virtual_backends_selected=False,full_profile_roots=19,
        closure_entries=38,matching_personalities=32,original_kmod_pac_fields=36,
        native_fixups=s['expanded_native_data']['all_native_fixups_verified'],rw_nx=s['expanded_native_data']['rw_nx'],
        zero_fill_verified=s['expanded_native_data']['zero_fill_verified'],
        handset_runtime_verified=False,desktop_verified=False,device_operations=False)
    if n.get('block_descriptor_abi'):
        if not a.block_tests:raise ValueError('Real Blocks PAC regression receipt required')
        tests=json.loads(a.block_tests.read_text())
        if not tests['passed'] or not tests['tampered_or_wrong_slot_signature_rejected'] or not tests.get('old_runtime_data_abort_reproduced'):
            raise ValueError('Blocks runtime regression incomplete')
        runtime=next(row for row in n['block_descriptor_abi']['replacements'] if 'runtime' in row['reasons'])
        if runtime['source_sha256']!=tests['source_sha256']:
            raise ValueError('Tested Blocks runtime differs from the linked source')
        dependencies=json.loads(Path(runtime['dependency_receipt']).read_text())['dependencies']
        headers=[digest for path,digest in dependencies.items() if Path(path).name=='Block_private.h']
        if headers!=[tests['header_sha256']]:raise ValueError('Tested Block_private.h differs from linked runtime')
        copy_code=disasm('__Block_copy')
        if copy_code.count('autda')<3 or 'pacda' not in copy_code or '#49339' not in copy_code or 'brk\t#0xc472' not in copy_code:
            raise ValueError('Final Block copy lacks authenticated descriptor access/re-signing')
        if copy_code.index('autda')>copy_code.index('ldr\tx21, [x16, #8]'):
            raise ValueError('Descriptor size is read before PAC authentication')
        for name in ('_Block_size','__Block_release','__Block_signature','__Block_extended_layout'):
            code=disasm(name)
            if 'autda' not in code or '#49339' not in code or 'brk\t#0xc472' not in code:
                raise ValueError('Final Block consumer does not authenticate the descriptor: '+name)
        globals=[];fixups=image.fixups()
        # Local symbol names repeat between translation units; never collapse them
        # to a name->address dictionary while auditing ALL global Block literals.
        for address,symbol_names in member.symbols().items():
            if any('block_literal_global' in name for name in symbol_names):
                value=fixups.get(address+24)
                if not value or value[1:]!=(1,2,0xc0bb,1):
                    raise ValueError('Unsigned or wrong-schema global Block descriptor: '+hex(address))
                globals.append(dict(block=hex(address),descriptor_slot=hex(address+24),target=hex(value[0])))
        if not globals:raise ValueError('Global Block producer audit found no literals')
        record['block_descriptor_abi']=dict(passed=True,compiler_flags=n['block_descriptor_abi']['compiler_flags'],
            recompiled_objects=len(n['block_descriptor_abi']['replacements']),
            producer_objects=n['block_descriptor_abi']['producer_objects'],
            audited_link_inputs=n['block_descriptor_abi']['audited_link_inputs'],
            global_descriptors=globals,global_descriptor_count=len(globals),
            runtime_tests_receipt=str(a.block_tests),runtime_tests_sha256=sha(a.block_tests),
            descriptor_key='DA',diversity='0xc0bb',address_diversity=True,
            authenticated_copy_and_resign=True,tamper_rejected=True,old_runtime_data_abort_reproduced=True,
            phone_runtime_verified=False)
    if a.touch:
        touch=json.loads((a.touch/'result.json').read_text())
        if n.get('sony_touch')!=touch or not (touch.get('cold_boot_init_implemented') or touch.get('inherited_engine_init_implemented')) or touch['virtual_backend_included']:
            raise ValueError('Qualified physical touch implementation differs')
        for section in ('sources','objects'):
            for path,digest in touch[section].items():
                if sha(path)!=digest:raise ValueError('Qualified touch build changed: '+path)
        abi=json.loads((a.touch/'hid-abi.json').read_text())
        if sha(a.touch/'hid-abi.json')!=touch['hid_abi_sha256']:raise ValueError('HID ABI receipt differs')
        table=names['__ZTV14NativeHidInput']+16;fixups=image.fixups()
        for row in abi['compiled_vtable']:
            if fixups[table+8*row['slot']][1:]!=(1,0,int(row['diversity'],16),1):
                raise ValueError('Final D27 touch vtable PAC schema differs')
        firmware=member.read(names['_native_sony_geni_firmware'],touch['geni_firmware']['firmware_bytes'])
        if hashlib.sha256(firmware).hexdigest()!=touch['geni_firmware']['firmware_sha256']:
            raise ValueError('Embedded OEM GENI firmware differs')
        selected=['_native_sony_touch_start','_sony_geni_firmware_init','_sony_geni_poll','_sw82907_decode','_sony_hid_touch_plan']
        if touch.get('se_dma_implemented'):selected+=['_sony_geni_prepare_dma']
        if touch.get('engine_irq_registered_before_mask'):
            selected+=['_sony_touch_irq_prepare']
            irq=json.loads(Path(touch['irq_tests_receipt']).read_text())
            if sha(touch['irq_tests_receipt'])!=touch['irq_tests_sha256'] or not irq['attach_before_mask_passed']:
                raise ValueError('Actual mask-before-attach regression receipt changed')
            for symbol in ('_armcpu_spi_attach','_armcpu_spi_mask'):
                if symbol not in names:raise ValueError('Missing IRQ dependency: '+symbol)
            if touch.get('per_cpu_runtime_recorder'):
                selected+=['_native_sony_cpu_snapshot']
                for symbol in ('_processor_array','_CpuDataEntries','_armcpu_core_timer','_armcpu_core_sgi'):
                    if symbol not in names:raise ValueError('Missing runtime probe dependency: '+symbol)
            elif not touch.get('temporary_probes_removed'):
                raise ValueError('Missing CPU recorder without explicit cleanup provenance')
        if touch.get('dma_done_is_completion'):
            if not touch.get('late_hid_match_retried'):raise ValueError('Missing late HID matching retry')
            for test in touch['chain_regressions'].values():
                path=Path(test['receipt']);case=json.loads(path.read_text())
                if sha(path)!=test['sha256'] or not case['passed']:raise ValueError('Touch-chain regression receipt differs')
                for source,digest in case['sources'].items():
                    if sha(source)!=digest:raise ValueError('Touch-chain tested source changed: '+source)
            selected+=['_native_touch_published','_native_touch_set_sink','_native_hid_live_checkpoint',
                '__ZN14NativeHidInput11touchNotifyEPv','__ZN14NativeHidInput9touchSendEv',
                '__ZN14NativeHidInput11touchActionEP8OSObjectPvS2_S2_S2_']
        if touch.get('sw82907_vendor_boot_policy'):
            selected+=['_sw82907_boot_result','_sw82907_code_crc_result','_sw82907_version_supported']
            if not touch.get('boot_skip_requires_version_and_scan_status'):
                raise ValueError('Missing independent firmware/scan acceptance gates')
        for symbol in selected:
            disasm(symbol)
        for symbol in ('_native_virtio_input_probe','_native_touch_probe'):
            if symbol in names:raise ValueError('Foreign input transport leaked into image')
        gpu_marker=b'[pdx062-gpu] sample=' if touch.get('se_dma_implemented') else b'[pdx061-gpu] sample='
        if touch.get('temporary_probes_removed'):
            for text in (gpu_marker,b'TOUCH s%u e%d',b'[sony-touch-registry]'):
                if text in raw:raise ValueError('Removed touch diagnostic survived final link')
            if '_native_sony_cpu_snapshot' in names:raise ValueError('Removed touch CPU worker survived final link')
            if b'S2X65234' not in raw:raise ValueError('Sony sensor identity gate absent')
        else:
            for text in (gpu_marker,b'TOUCH s%u e%d',b'S2X65234'):
                if text not in raw:raise ValueError('Touch/GPU recorder marker absent')
        record['sony_touch']={'archive_sha256':touch['sha256'],'hid_pac_slots':len(abi['compiled_vtable']),
                             'firmware_sha256':touch['geni_firmware']['firmware_sha256'],
                             'firmware_address':hex(names['_native_sony_geni_firmware']),
                             'firmware_bytes':len(firmware),'cold_boot_init_implemented':touch.get('cold_boot_init_implemented',False),
                             'protected_alias_access':touch.get('protected_alias_access',True),
                              'se_dma_implemented':touch.get('se_dma_implemented',False),
                              'engine_irq_registered_before_mask':touch.get('engine_irq_registered_before_mask',False),
                               'per_cpu_runtime_recorder':touch.get('per_cpu_runtime_recorder',False),
                              'dma_done_is_completion':touch.get('dma_done_is_completion',False),
                                'late_hid_match_retried':touch.get('late_hid_match_retried',False),
                              'sw82907_vendor_boot_policy':touch.get('sw82907_vendor_boot_policy',False),
                              'gpu_progress_recorder_present':not touch.get('temporary_probes_removed',False),
                              'temporary_probes_removed':touch.get('temporary_probes_removed',False),
                              'runtime_verified':False}
    (a.out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    summary={key:value for key,value in record.items() if key!='implementations'}
    if 'block_descriptor_abi' in summary:
        summary['block_descriptor_abi']={key:value for key,value in summary['block_descriptor_abi'].items() if key!='global_descriptors'}
    print(json.dumps(summary,indent=2))


if __name__=='__main__':main()
