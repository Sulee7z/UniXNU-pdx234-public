#!/usr/bin/env python3
"""Build Sony firmware for one high-bank contiguous iPadOS27 memory window."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import argparse
import sys
import importlib.util

DEVICE=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,default=BASE/'firmware-high-memory-002')
    parser.add_argument('--vendor-usb',action='store_true',help='Embed Sony USB DXE and dependency modules with original DEPEX')
    parser.add_argument('--vendor-dal-fix',action='store_true',help='Retain SPMI polling fix and require DAL before its four implicit consumers')
    parser.add_argument('--pmic-handoff',action='store_true',help='Preserve the XBOOT coin-cell state instead of reprogramming it after ABL')
    parser.add_argument('--power-dependencies',action='store_true',help='Order NPA/Clock/RPMh/PMIC using actual protocol prerequisites')
    parser.add_argument('--ulog-dependency',action='store_true',help='Require ULog before NPA logging initialization')
    parser.add_argument('--usb-scope',action='store_true',help='Omit unrelated camera/PCIe RscDxe startup from the USB chain')
    parser.add_argument('--post-abl-power',action='store_true',help='Preserve handed-off charger/PS_HOLD policy and require USB resource providers')
    parser.add_argument('--exit-handoff',action='store_true',help='Preserve inherited PMIC IRQ/lock/channel ownership at secondary UEFI exit')
    parser.add_argument('--cdc-application',action='store_true',help='Drive CDC from the UniXNU application menu instead of timer notifications')
    parser.add_argument('--disable-cdc',action='store_true',help='Omit CDC service driver and restore the original menu loop')
    parser.add_argument('--usb-core-errors',action='store_true',help='Propagate vendor DWC core initialization failures as EFI errors')
    parser.add_argument('--usb-core-trace',action='store_true',help='Trace actual vendor connect/reset/DMA setup call boundaries')
    parser.add_argument('--usb-prepare-errors',action='store_true',help='Propagate and trace qualified Sony preparation failures')
    args=parser.parse_args();out=args.out;out.mkdir(exist_ok=False)
    if args.vendor_dal_fix and not args.vendor_usb:parser.error('--vendor-dal-fix requires --vendor-usb')
    if args.pmic_handoff and not args.vendor_dal_fix:parser.error('--pmic-handoff requires --vendor-dal-fix')
    if args.power_dependencies and not args.pmic_handoff:parser.error('--power-dependencies requires --pmic-handoff')
    if args.ulog_dependency and not args.power_dependencies:parser.error('--ulog-dependency requires --power-dependencies')
    if args.usb_scope and not args.ulog_dependency:parser.error('--usb-scope requires --ulog-dependency')
    if args.post_abl_power and not args.usb_scope:parser.error('--post-abl-power requires --usb-scope')
    if args.exit_handoff and not args.post_abl_power:parser.error('--exit-handoff requires --post-abl-power')
    if args.cdc_application and not args.exit_handoff:parser.error('--cdc-application requires --exit-handoff')
    if args.disable_cdc and (args.cdc_application or not args.exit_handoff):parser.error('--disable-cdc requires --exit-handoff and excludes --cdc-application')
    if args.usb_core_errors and not args.cdc_application:parser.error('--usb-core-errors requires --cdc-application')
    if args.usb_core_trace and not args.usb_core_errors:parser.error('--usb-core-trace requires --usb-core-errors')
    if args.usb_prepare_errors and not args.usb_core_trace:parser.error('--usb-prepare-errors requires --usb-core-trace')
    uefi=Path('/root/unixnu-build/uefi-pdx234');source=DEVICE.parent/'uefi-pdx234'
    darwin=Path('/root/unixnu-build/pdx234-DarwinBoot')
    package=Path('/root/unixnu-build/pdx234-unixnu-package')
    if args.cdc_application or args.disable_cdc:
        sys.path.insert(0,str(DEVICE/'ci'))
        from sony_cdc_application import apply, ORIGINAL_SHA
        menu=package/'UniXNUPkg/Library/UniXNULib/Menu.c'
        baseline=BASE/'cdc-menu-original.c'
        if not baseline.exists():
            if hashlib.sha256(menu.read_bytes()).hexdigest()!=ORIGINAL_SHA:raise ValueError('Unknown original menu')
            shutil.copyfile(menu,baseline)
        if hashlib.sha256(baseline.read_bytes()).hexdigest()!=ORIGINAL_SHA:raise ValueError('Menu baseline changed')
        original=baseline.read_text();adapted=apply(original)
        if menu.read_text() not in (original,adapted):raise ValueError('Unrecognized user menu changes')
        menu.write_text(original if args.disable_cdc else adapted);shutil.copyfile(menu,out/'Menu.c')
    # Preserve the old Linux build inputs before synchronizing current Sony
    # sources; the known-good published FD is an immutable separate artifact.
    shutil.copytree(uefi/'Platforms/Sony',out/'previous-sony')
    shutil.copyfile(darwin/'DarwinBootPkg/Driver/DarwinBoot.c',out/'previous-DarwinBoot.c')
    subprocess.run(['rsync','-rlt',str(source/'Platforms/Sony')+'/',str(uefi/'Platforms/Sony')+'/'],check=True)
    if args.disable_cdc:
        for name in ['UsbComponents.inc','UsbFirmware.inc']:
            path=uefi/'Platforms/Sony/pdx234Pkg/Include'/name
            lines=path.read_text().splitlines(keepends=True)
            if sum('Drivers/PdxUsbPrepareDxe/PdxUsbPrepareDxe.inf' in line for line in lines)!=1:
                raise ValueError('Unexpected CDC include inventory')
            path.write_text(''.join(line for line in lines if 'Drivers/PdxUsbPrepareDxe/PdxUsbPrepareDxe.inf' not in line))
    vendor=None
    if args.vendor_usb:
        vendor=json.loads((source/'Binaries/pdx234/usb-import.json').read_text())
        for row in vendor['modules']:
            directory=source/'Binaries/pdx234/QcomPkg/Drivers'/row['name']
            for ext,key in [('efi','pe_sha256'),('depex','depex_sha256')]:
                if hashlib.sha256((directory/(row['name']+'.'+ext)).read_bytes()).hexdigest()!=row[key]:
                    raise ValueError('Vendor USB input changed: '+row['name'])
        subprocess.run(['rsync','-rlt',str(source/'Binaries/pdx234')+'/',str(uefi/'Binaries/pdx234')+'/'],check=True)
        if args.usb_scope:
            import uuid
            protocol=uuid.UUID('3806cdf0-c281-4345-9b1e-49dfb3126923').bytes_le
            for row in vendor['modules']:
                if row['name']=='RscDxe':continue
                directory=uefi/'Binaries/pdx234/QcomPkg/Drivers'/row['name']
                for ext in ['efi','depex']:
                    if protocol in (directory/(row['name']+'.'+ext)).read_bytes():
                        raise ValueError('Retained module references RSC '+row['name'])
            vendor['excluded_modules']=[r for r in vendor['modules'] if r['name']=='RscDxe']
            if len(vendor['excluded_modules'])!=1:raise ValueError('Unexpected RSC inventory')
            vendor['modules']=[r for r in vendor['modules'] if r['name']!='RscDxe']
            for name in ['UsbComponents.inc','UsbFirmware.inc']:
                path=uefi/'Platforms/Sony/pdx234Pkg/Include'/name
                lines=path.read_text().splitlines(keepends=True)
                if sum('Drivers/RscDxe/RscDxe.inf' in l for l in lines)!=1:raise ValueError('Unexpected RSC include')
                path.write_text(''.join(l for l in lines if 'Drivers/RscDxe/RscDxe.inf' not in l))
        if args.vendor_dal_fix:
            sys.path.insert(0,str(DEVICE/'ci'))
            from sony_dal_dependencies import CONSUMERS, require_dal
            spec=importlib.util.spec_from_file_location('spmi_fix',Path(__file__).with_name('fix-sony-spmi-polling.py'))
            spmi=importlib.util.module_from_spec(spec);spec.loader.exec_module(spmi)
            changes=[]
            for row in vendor['modules']:
                directory=uefi/'Binaries/pdx234/QcomPkg/Drivers'/row['name']
                if row['name']=='SPMI':
                    path=directory/'SPMI.efi';data=spmi.patch_pe(path.read_bytes());path.write_bytes(data)
                    row['original_pe_sha256']=row['pe_sha256'];row['pe_sha256']=hashlib.sha256(data).hexdigest()
                    changes.append(dict(module='SPMI',kind='polling-init',sha256=row['pe_sha256']))
                if row['name'] in CONSUMERS:
                    path=directory/(row['name']+'.depex');data=require_dal(path.read_bytes());path.write_bytes(data)
                    row['original_depex_sha256']=row['depex_sha256'];row['depex_sha256']=hashlib.sha256(data).hexdigest()
                    row['depex_requires'].append('ae37b942-457f-4c91-a196-d9669fd347a3')
                    changes.append(dict(module=row['name'],kind='additional-DAL-dependency',sha256=row['depex_sha256']))
            vendor['adaptations']=changes;vendor['vendor_bytes_modified']=True
            if args.pmic_handoff:
                from sony_pmic_handoff import adapt_pe
                row=next(r for r in vendor['modules'] if r['name']=='PmicDxe')
                path=uefi/'Binaries/pdx234/QcomPkg/Drivers/PmicDxe/PmicDxe.efi'
                data=adapt_pe(path.read_bytes());path.write_bytes(data)
                row['original_pe_sha256']=row['pe_sha256'];row['pe_sha256']=hashlib.sha256(data).hexdigest()
                changes.append(dict(module='PmicDxe',kind='post-ABL-preserve-XBOOT-coincell',sha256=row['pe_sha256']))
                if args.post_abl_power:
                    from sony_pmic_post_abl import adapt_pe as adapt_post
                    data=adapt_post(data);path.write_bytes(data);row['pe_sha256']=hashlib.sha256(data).hexdigest()
                    changes.append(dict(module='PmicDxe',kind='post-ABL-preserve-charger-pshold',sha256=row['pe_sha256']))
                    if args.exit_handoff:
                        from sony_pmic_exit_handoff import adapt_pe as adapt_exit
                        data=adapt_exit(data);path.write_bytes(data);row['pe_sha256']=hashlib.sha256(data).hexdigest()
                        changes.append(dict(module='PmicDxe',kind='post-ABL-preserve-exit-ownership',sha256=row['pe_sha256']))
            if args.power_dependencies:
                from sony_dal_dependencies import POWER_DEPENDENCIES, ULOG_DEPENDENCIES, USB_RESOURCE_DEPENDENCIES, require_protocols
                dependencies=dict(POWER_DEPENDENCIES)
                if args.ulog_dependency:dependencies.update(ULOG_DEPENDENCIES)
                if args.post_abl_power:
                    for name,required in USB_RESOURCE_DEPENDENCIES.items():
                        dependencies[name]=dependencies.get(name,())+required
                for row in vendor['modules']:
                    required=dependencies.get(row['name'])
                    if not required:continue
                    path=uefi/'Binaries/pdx234/QcomPkg/Drivers'/row['name']/(row['name']+'.depex')
                    data=require_protocols(path.read_bytes(),required);path.write_bytes(data)
                    row.setdefault('original_depex_sha256',row['depex_sha256'])
                    row['depex_sha256']=hashlib.sha256(data).hexdigest()
                    row['depex_requires']+=list(required)
                    kind='ulog-protocol-prerequisite' if row['name'] in ULOG_DEPENDENCIES else 'power-protocol-prerequisites'
                    changes.append(dict(module=row['name'],kind=kind,requires=list(required),sha256=row['depex_sha256']))
            (out/'vendor-adaptations.json').write_text(json.dumps(changes,indent=2)+'\n')
        vendor['post_abl_power']=args.post_abl_power
        vendor['exit_handoff']=args.exit_handoff
        if args.usb_core_errors:
            from sony_usb_core_errors import adapt_pe as adapt_core_errors
            row=next(r for r in vendor['modules'] if r['name']=='UsbfnDwc3Dxe')
            path=uefi/'Binaries/pdx234/QcomPkg/Drivers/UsbfnDwc3Dxe/UsbfnDwc3Dxe.efi'
            original=path.read_bytes()
            data=adapt_core_errors(original)
            if args.usb_core_trace:
                from sony_usb_core_trace import adapt_pe as trace_core
                data=trace_core(original)
                vendor['usb_core_trace']=True
                for name in ['sony_usb_core_trace.py','sony_usb_core_trace.S','sony_usb_core_errors.py','sony_usb_poll_errors.py','sony_usb_poll_errors.S']:
                    shutil.copyfile(DEVICE/'ci'/name,out/name)
            path.write_bytes(data)
            row['original_pe_sha256']=row['pe_sha256'];row['pe_sha256']=hashlib.sha256(data).hexdigest()
            vendor['adaptations'].append(dict(module=row['name'],kind='propagate-core-errors',sha256=row['pe_sha256']))
            if args.usb_core_trace:
                vendor['adaptations'].append(dict(module=row['name'],kind='poll-error-propagation-and-complete-core-trace',sha256=row['pe_sha256']))
            vendor['usb_core_errors']=True
        if args.usb_prepare_errors:
            from sony_usb_prepare_errors import adapt_pe as prepare_errors
            row=next(r for r in vendor['modules'] if r['name']=='UsbConfigDxe')
            path=uefi/'Binaries/pdx234/QcomPkg/Drivers/UsbConfigDxe/UsbConfigDxe.efi'
            original=path.read_bytes();data=prepare_errors(original,trace=True);path.write_bytes(data)
            row['original_pe_sha256']=row['pe_sha256'];row['pe_sha256']=hashlib.sha256(data).hexdigest()
            vendor['adaptations'].append(dict(module=row['name'],kind='propagate-and-trace-preparation-errors',sha256=row['pe_sha256']))
            vendor['usb_prepare_errors']=True
            for name in ['sony_usb_prepare_errors.py','sony_usb_prepare_errors.S']:shutil.copyfile(DEVICE/'ci'/name,out/name)
        if vendor.get('adaptations'):
            (out/'vendor-adaptations.json').write_text(json.dumps(vendor['adaptations'],indent=2)+'\n')
    for rel in ['Silicon/Silicium/SiliciumPkg/Sec/Sec.c','Silicon/Silicium/SiliciumPkg/Sec/AArch64/ModuleEntryPoint.S','Resources/Configs/pdx234.toml']:
        shutil.copyfile(source/rel,uefi/rel)
    subprocess.run(['rsync','-rlt','--exclude=.git',str(DEVICE/'.cache/firmware-components/DarwinBoot')+'/',str(darwin)+'/'],check=True)
    path=darwin/'DarwinBootPkg/Driver/DarwinBoot.c'
    path.write_text(path.read_text())
    subprocess.run(['git','apply',str(DEVICE/'patches/firmware/darwinboot-dxe-log.patch')],cwd=darwin,check=True)
    subprocess.run(['git','apply',str(DEVICE/'patches/firmware/darwinboot-sony-entry-bank.patch')],cwd=darwin,check=True)
    entry=path.read_text().split('DarwinBootEntry (',1)[1]
    assert 'Print (L"DARWINBOOT: loader v2 installed' not in entry
    assert 'DEBUG ((DEBUG_ERROR, "DARWINBOOT: loader v2 installed' in entry
    dsc=uefi/'Platforms/Sony/pdx234Pkg/pdx234.dsc';text=dsc.read_text()
    old='-DPDX234_ENTRY_DRAM_BASE=0x880000000ULL -DPDX234_ENTRY_DRAM_BYTES=0x39d00000ULL'
    assert text.count(old)==1
    text=text.replace(old,'-DPDX234_ENTRY_DRAM_BASE=0x980000000ULL -DPDX234_ENTRY_DRAM_BYTES=0x180000000ULL')
    if args.vendor_usb:
        assert text.count('DEFINE PDX234_VENDOR_USB = 0')==1
        text=text.replace('DEFINE PDX234_VENDOR_USB = 0','DEFINE PDX234_VENDOR_USB = 1')
    dsc.write_text(text);shutil.copyfile(dsc,out/'pdx234.dsc');shutil.copyfile(path,out/'DarwinBoot.c')
    edk=uefi/'Mu_Basecore'
    env=dict(os.environ,WORKSPACE=str(uefi),EDK_TOOLS_PATH=str(edk/'BaseTools'),CONF_PATH=str(uefi/'Conf'),
        PACKAGES_PATH=':'.join(map(str,[uefi,uefi/'Platforms/Sony',uefi/'Platforms/Xiaomi',uefi/'Common/Mu',uefi/'Common/Mu_OEM_Sample',edk,uefi/'Silicon/Qualcomm',uefi/'Silicon/Silicium',uefi/'Silicium-ACPI',uefi/'Silicium-ACPI/Silicon/Qualcomm',package,darwin])),
        CLANG_BIN='/usr/bin/',PYTHON_COMMAND='python3',PYTHONDONTWRITEBYTECODE='1',
        PATH='/root/unixnu-build/mu-venv/bin:'+str(edk/'BaseTools/BinWrappers/PosixLike')+':'+str(edk/'BaseTools/Source/C/bin')+':'+os.environ['PATH'])
    cmd=['build','-p','Platforms/Sony/pdx234Pkg/pdx234.dsc','-a','AARCH64','-b','DEBUG','-t','CLANGPDB','-n','20']
    for value in ['FD_BASE=0xA7100000','FD_SIZE=0x300000','FD_BLOCKS=768','ENABLE_SECUREBOOT=0','MEMORY_PROTECTION=TRUE','SHIP_MODE=FALSE','DEVICE_MODEL=pdx234','BUILDID_STRING=pdx234-research']:
        cmd+=['-D',value]
    with (out/'build.log').open('w') as log:
        q=subprocess.run(cmd,env=env,cwd=uefi,stdout=log,stderr=subprocess.STDOUT)
    if q.returncode:raise RuntimeError((out/'build.log').read_text()[-6000:])
    fd=out/'SILICIUM_UEFI.fd';shutil.copyfile(uefi/'Build/pdx234Pkg/DEBUG_CLANGPDB/FV/SILICIUM_UEFI.fd',fd)
    subprocess.run(['python3','-B',str(DEVICE/'scripts/check-firmware-services.py'),str(fd),'--report',str(out/'service-check.json')],check=True)
    result=dict(fd=str(fd),sha256=hashlib.sha256(fd.read_bytes()).hexdigest(),entry_base=0x980000000,entry_bytes=0x180000000,
                vendor_usb=vendor,
                 route='iPadOS27 contiguous allocation; no excluded/outside-memory patches',hardware_verified=False)
    cdc=uefi/'Platforms/Sony/pdx234Pkg/Drivers/PdxUsbPrepareDxe/PdxUsbCdc.c'
    if args.disable_cdc:
        app=uefi/'Build/pdx234Pkg/DEBUG_CLANGPDB/AARCH64/UniXNU.efi'
        shutil.copyfile(app,out/'UniXNU.efi')
        result['cdc_disabled']=dict(menu_sha256=hashlib.sha256((out/'Menu.c').read_bytes()).hexdigest(),
            app_sha256=hashlib.sha256(app.read_bytes()).hexdigest(),omitted_driver='9eb02581-63fc-44ee-a820-49ced6493f12')
    if args.vendor_usb and cdc.exists() and not args.disable_cdc:
        glue=uefi/'Build/pdx234Pkg/DEBUG_CLANGPDB/AARCH64/PdxUsbPrepareDxe.efi'
        shutil.copyfile(cdc,out/'PdxUsbCdc.c');shutil.copyfile(glue,out/'PdxUsbPrepareDxe.efi')
        result['cdc_frontend']=dict(source_sha256=hashlib.sha256(cdc.read_bytes()).hexdigest(),pe_sha256=hashlib.sha256(glue.read_bytes()).hexdigest())
        boundary=cdc.with_name('PdxUsbBoundary.c')
        if boundary.exists():
            shutil.copyfile(boundary,out/boundary.name)
            result['cdc_frontend']['boundary_sha256']=hashlib.sha256(boundary.read_bytes()).hexdigest()
        if args.cdc_application:
            service=cdc.with_name('PdxUsbPrepare.c')
            shutil.copyfile(service,out/'PdxUsbPrepare.c')
            app=uefi/'Build/pdx234Pkg/DEBUG_CLANGPDB/AARCH64/UniXNU.efi'
            shutil.copyfile(app,out/'UniXNU.efi')
            result['cdc_application']=dict(menu_sha256=hashlib.sha256((out/'Menu.c').read_bytes()).hexdigest(),
                app_sha256=hashlib.sha256(app.read_bytes()).hexdigest(),service_sha256=hashlib.sha256(service.read_bytes()).hexdigest())
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
