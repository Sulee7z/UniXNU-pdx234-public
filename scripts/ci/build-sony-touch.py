#!/usr/bin/env python3
"""Compile Sony SW82907 transport with the actual qualified D27 HID declarations."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def once(text,old,new):
    if text.count(old)!=1:raise ValueError('Qualified HID source anchor differs: '+old[:80])
    return text.replace(old,new)


def adapt_hid(text):
    text=once(text,'#include <IOKit/IOBufferMemoryDescriptor.h>',
              '#include "HidTouchReport.h"\n#include "Sw82907.h"\n#include <IOKit/IOBufferMemoryDescriptor.h>')
    first=text.index('    int prevIds[TOUCH_FINGERS]')
    last=text.index('    static unsigned transformCoordinate',first)
    text=text[:first]+'    SonyHidTouchState previous={};\n    bool reportRetry=false;\n'+text[last:]
    first=text.index('    void touchSend() {')
    last=text.index('    // The button driver',first)
    text=text[:first]+'''    void touchSend() {
        if(!hasEventDriverCached()){
            reportRetry=true;native_hid_input_observed(3,0);if(timer)timer->setTimeoutMS(100);return;
        }
        native_hid_input_observed(3,1);
        reportRetry=false;
        const uint32_t before=native_touch_seq;
        if(before&1u){reportRetry=true;if(timer)timer->setTimeoutMS(8);return;}
        if(before==lastSeq)return;
        __asm__ volatile("dmb ish":::"memory");
        const unsigned count=native_touch_count;if(count>TOUCH_FINGERS)return;
        SonyHidContact contacts[TOUCH_FINGERS]={};
        for(unsigned i=0;i<count;++i) {
            const int id=native_touch_ids[i],x=native_touch_xs[i],y=native_touch_ys[i];
            if(id<0 || id>=10 || x<0 || x>1644 || y<0 || y>3840)return;
            contacts[i]={(uint8_t)id,(uint16_t)((uint64_t)x*32767/1644),
                                    (uint16_t)((uint64_t)y*32767/3840)};
        }
        __asm__ volatile("dmb ish":::"memory");
        if(native_touch_seq!=before){reportRetry=true;if(timer)timer->setTimeoutMS(8);return;}
        SonyHidTouchPlan plan={};if(sony_hid_touch_plan(&previous,contacts,count,&plan))return;
        for(unsigned i=0;i<plan.count;++i) {
            IOBufferMemoryDescriptor *buffer=IOBufferMemoryDescriptor::withBytes(
                plan.reports[i],SONY_HID_REPORT_BYTES,kIODirectionNone);
            const IOReturn result=buffer?submitReport(buffer):kIOReturnNoMemory;
            OSSafeReleaseNULL(buffer);native_hid_input_observed(6,result);
            if(result!=kIOReturnSuccess){reportRetry=true;if(timer)timer->setTimeoutMS(8);return;}
            previous=plan.after[i];native_touch_hid_reports=native_touch_hid_reports+1;
        }
        lastSeq=before;
    }
''' + text[last:]
    text=once(text,'        native_hid_live_checkpoint(self);', '''        native_hid_live_checkpoint(self);
        if(self->reportRetry){self->touchSend();if(!self->reportRetry)source->setTimeoutMS(1000);return;}''')
    text=once(text,'static const int32_t kEdgeX=48*65536/3048,kEdgeY=48*65536/2032;',
              'static const int32_t kEdgeX=48*65536/1644,kEdgeY=48*65536/3840;')
    text=once(text,'touchOnly?"VirtIO":"Virtual"','"I2C"')
    text=once(text,'touchOnly?"Offline touch digitizer":"Offline HID input probe"','"Sony SW82907 Touch"')
    text=once(text,'setProperty("OfflineInputProbe",true);','setProperty("SonyLxsTouch",true);')
    return text


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--tests',type=Path,required=True)
    parser.add_argument('--firmware',type=Path,required=True)
    parser.add_argument('--irq-tests',type=Path,required=True)
    parser.add_argument('--chain-tests',type=Path,required=True)
    parser.add_argument('--hid-parser-tests',type=Path,required=True)
    parser.add_argument('--hid-delivery-tests',type=Path,required=True)
    parser.add_argument('--boot-tests',type=Path,required=True)
    args=parser.parse_args()
    if args.out.exists():raise ValueError('Preserve the existing driver build')
    if not str(args.out).startswith(str(BASE)+'/sony-touch-'):raise ValueError('Use an isolated Sony build under BASE')
    if shutil.disk_usage('/mnt/g').free<8*1024**3:raise ValueError('Workspace reserve below8GiB')
    tests=json.loads(args.tests.read_text())
    irq_tests=json.loads(args.irq_tests.read_text())
    if not irq_tests['passed'] or not irq_tests['old_mask_before_attach_reproduced']:
        raise ValueError('Actual ArmCpu attach/mask regression required')
    for path,digest in irq_tests['helper_sources'].items():
        if sha(path)!=digest:raise ValueError('Tested IRQ lifecycle helper changed')
    receipts={}
    for name,path in [('chain',args.chain_tests),('hid_parser',args.hid_parser_tests),
                      ('hid_delivery',args.hid_delivery_tests),('boot_policy',args.boot_tests)]:
        record=json.loads(path.read_text())
        if (not record['passed'] or record.get('old_dma_timeout_reproduced') or
            record.get('old_late_matching_report_loss_reproduced') or record.get('old_boot_zero_rejection_reproduced')):
            raise ValueError('Successful current chain regression required: '+name)
        if name=='chain' and not record.get('vendor_boot_policy_cases_executed'):
            raise ValueError('Real Session boot-status acceptance/failure cases required')
        if name=='boot_policy' and not record.get('verbatim_vendor_boot_check'):
            raise ValueError('Verbatim Sony boot-status comparison required')
        for source,digest in record['sources'].items():
            if sha(source)!=digest:raise ValueError('Chain-tested source changed: '+source)
        receipts[name]={'receipt':str(path),'sha256':sha(path)}
    firmware=json.loads((args.firmware/'result.json').read_text())
    if not firmware['passed'] or sha(firmware['generated'])!=firmware['generated_sha256']:
        raise ValueError('Qualified OEM firmware source changed')
    if not tests['passed']:raise ValueError('Host sanitizer tests required')
    for path,digest in tests['sources'].items():
        if sha(path)!=digest:raise ValueError('Tested source changed: '+path)
    reference=BASE/'qemu-input-002'
    qualified=json.loads((reference/'result.json').read_text())
    for path,digest in qualified['objects'].items():
        if sha(path)!=digest:raise ValueError('Qualified D27 HID input changed')
    args.out.mkdir(parents=True);out=args.out.resolve()
    for folder in ('source','objects'): (out/folder).mkdir()
    shutil.copytree(reference/'include',out/'include')
    spec=importlib.util.spec_from_file_location('sony_hid_builder',ROOT/'ci/qemu/display/input/build-input.py')
    builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
    sys.path.insert(0,str(ROOT/'ci'));from compile_dependencies import run_recorded
    commands={}
    hid=out/'source/NativeHidInput.cpp';hid.write_text(adapt_hid((reference/'source/NativeHidInput.cpp').read_text()))
    if sha(hid)!=json.loads(args.hid_delivery_tests.read_text())['adapted_hid_source_sha256']:
        raise ValueError('Compiled HID source differs from the executed delivery fixture')
    driver=ROOT/'drivers/SonyLxsTouch'
    includes=['-I',str(out/'include'),'-I',str(driver),'-idirafter',
              str(builder.SDK/'System/Library/Frameworks/Kernel.framework/Versions/A/Headers')]
    includes+=['-I',str(BASE/'sources/sheng/package')]
    sys.path.insert(0,str(ROOT/'ci'));from block_descriptor_abi import FLAGS as block_flags
    commands['NativeHidInput']=builder.compile_cpp(hid,out/'objects/NativeHidInput.o',includes,['-DNATIVE_HID_SOURCE_API=1',*block_flags])
    builder.audit_hid(out);builder.qualify_edge(out)
    for stem in ('SonyTouch','Sw82907','Sw82907Boot','GeniI2c','HidTouchReport','GeniInit','SonyTouchIrq','SonyGeniFirmware'):
        suffix='.cpp' if stem=='SonyTouch' else '.c'
        source=Path(firmware['generated']) if stem=='SonyGeniFirmware' else driver/(stem+suffix)
        obj=out/'objects'/(stem+'.o')
        commands[stem]=builder.compile_cpp(source,obj,includes,
            [*block_flags,*(['-Wno-missing-field-initializers','-Wno-missing-braces'] if suffix=='.c' else [])])
    late=out/'objects/NativeHidInput.late.o'
    subprocess.run(['llvm-objcopy-23','--remove-section=__DATA,__mod_init_func',
                    '--globalize-symbol=__GLOBAL__sub_I_NativeHidInput.cpp',str(out/'objects/NativeHidInput.o'),str(late)],check=True)
    members=[late,*(out/'objects'/(name+'.o') for name in ('hid-bindings','hid-addresses','SonyTouch','Sw82907','Sw82907Boot','GeniI2c','HidTouchReport','GeniInit','SonyTouchIrq','SonyGeniFirmware'))]
    archive=out/'libSonyD27Touch.a'
    subprocess.run(['llvm-ar','rcs',str(archive),*map(str,members)],check=True)
    result={'archive':str(archive),'sha256':sha(archive),'commands':commands,
            'sources':{str(p):sha(p) for p in [hid,*driver.glob('*.c'),*driver.glob('*.h'),driver/'SonyTouch.cpp',Path(firmware['generated'])]},
            'objects':{str(p):sha(p) for p in members},'tests_sha256':sha(args.tests),
            'irq_tests_receipt':str(args.irq_tests),'irq_tests_sha256':sha(args.irq_tests),
            'chain_regressions':receipts,'dma_done_is_completion':True,'late_hid_match_retried':True,
            'sw82907_vendor_boot_policy':True,'boot_skip_requires_version_and_scan_status':True,
            'hid_slots':207,'hid_base_bytes':208,'event_service_slots':220,
            'hid_abi_sha256':sha(out/'hid-abi.json'),'edge_abi_sha256':sha(out/'edge-abi.json'),
            'backend':'Sony SW82907 / GENI I2C FIFO or SE DMA','virtual_backend_included':False,
            'required_args':['sony-touch=1','touch-hid=1'],
            'geni_firmware':firmware,'cold_boot_init_implemented':False,'inherited_engine_init_implemented':True,
            'protected_alias_access':False,'se_dma_implemented':True,
             'engine_irq_registered_before_mask':True,'per_cpu_runtime_recorder':False,
             'temporary_probes_removed':True,'periodic_registry_dump':False,
             'periodic_gpu_cpu_logger':False,'touch_test_rows':False,
            'known_limits':['Requires OEM-preloaded I2C engine firmware; never accesses protected firmware/FIFO aliases',
                            'GPIO25 level polling and SE DMA/Sony SMMU route still require handset qualification; power/suspend remains'],
            'startup':'native_sony_touch_start','runtime_verified':False,'image_delivered':False}
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('commands','sources','objects')},indent=2))


if __name__=='__main__':main()
