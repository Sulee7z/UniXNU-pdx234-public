#!/usr/bin/env python3
"""Verify actual FD modules, original vendor bytes and USB dispatch dependencies."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import uuid
import sys

DEVICE=Path(__file__).resolve().parents[2]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build',type=Path,required=True)
    args=parser.parse_args()
    spec=importlib.util.spec_from_file_location('fv',DEVICE/'scripts/check-firmware-services.py')
    fv=importlib.util.module_from_spec(spec);spec.loader.exec_module(fv)
    record=json.loads((args.build/'result.json').read_text())
    raw=Path(record['fd']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=record['sha256']:raise ValueError('FD hash mismatch')
    files=fv.volume_files(raw)
    excluded=record['vendor_usb'].get('excluded_modules',[])
    if excluded:
        if [r['name'] for r in excluded]!=['RscDxe']:raise ValueError('Unexpected excluded driver')
        if excluded[0]['guid'] in files:raise ValueError('Excluded RSC still in FD')
        rsc_protocol=uuid.UUID('3806cdf0-c281-4345-9b1e-49dfb3126923').bytes_le
        for guid,sections in files.items():
            if any(rsc_protocol in data for kind,data in sections if kind in (0x10,0x13)):
                raise ValueError('Retained firmware references excluded RSC '+guid)
    # PI 1.8 section10.3: APRIORI dispatch ignores a driver's DEPEX.
    apriori=set()
    for kind,data in files.get('fc510ee7-ffdc-11d4-bd41-0080c73c8881',[]):
        if kind==0x19:
            if len(data)%16:raise ValueError('Malformed APRIORI GUID list')
            apriori.update(str(uuid.UUID(bytes_le=data[i:i+16])) for i in range(0,len(data),16))
    for module in record['vendor_usb']['modules']:
        if module['guid'] in apriori:raise ValueError('Vendor DEPEX bypassed by APRIORI '+module['name'])
        sections=files[module['guid']]
        for kind,key in [(0x10,'pe_sha256'),(0x13,'depex_sha256')]:
            values=[data for k,data in sections if k==kind]
            if len(values)!=1 or hashlib.sha256(values[0]).hexdigest()!=module[key]:
                raise ValueError('Vendor bytes differ '+module['name'])
    # Actual generic SDT provider, not merely a protocol GUID reference.
    if '9622e42c-8e38-4a08-9e8f-54f784652f6b' not in files:raise ValueError('ACPI table driver absent')
    disabled=record.get('cdc_disabled')
    glue=files.get('9eb02581-63fc-44ee-a820-49ced6493f12',[])
    if disabled:
        if glue or record.get('cdc_frontend'):raise ValueError('Disabled CDC still embedded')
        sys.path.insert(0,str(DEVICE/'ci'))
        from sony_cdc_application import ORIGINAL_SHA
        app=(args.build/'UniXNU.efi').read_bytes()
        if disabled['menu_sha256']!=ORIGINAL_SHA or hashlib.sha256((args.build/'Menu.c').read_bytes()).hexdigest()!=ORIGINAL_SHA:
            raise ValueError('CDC-free menu differs from original')
        if hashlib.sha256(app).hexdigest()!=disabled['app_sha256'] or not any(k==0x10 and data==app for sections in files.values() for k,data in sections):
            raise ValueError('CDC-free application differs')
        service=uuid.UUID('765f0768-b70e-43cc-917d-8f213169dc42').bytes_le
        if any(service in data for sections in files.values() for k,data in sections if k==0x10):
            raise ValueError('CDC service producer or consumer retained')
    else:
        verify_glue(glue)
    pe=next((data for k,data in glue if k==0x10),b'')
    cdc_verified=False
    application_verified=False
    if record.get('cdc_frontend'):
        cdc=record['cdc_frontend'];test=json.loads((args.build/'cdc-host-tests.json').read_text())
        if cdc.get('boundary_sha256'):
            boundary=json.loads((args.build/'cdc-boundary-tests.json').read_text())
            if not boundary['passed'] or boundary['source_sha256']!=cdc['boundary_sha256'] or hashlib.sha256((args.build/'PdxUsbBoundary.c').read_bytes()).hexdigest()!=cdc['boundary_sha256']:
                raise ValueError('CDC boundary observer differs from tested source')
        if not test['passed'] or test['source_sha256']!=cdc['source_sha256']:raise ValueError('CDC tested source differs')
        if hashlib.sha256((args.build/'PdxUsbCdc.c').read_bytes()).hexdigest()!=cdc['source_sha256'] or hashlib.sha256(pe).hexdigest()!=cdc['pe_sha256']:
            raise ValueError('CDC source/PE differs')
        for marker in [b'PDX CDC: StartEx descriptors',b'PDX234 UEFI CDC active',b'PDX234 UEFI log']:
            # Product is UTF16; status/banner are ASCII.
            if marker not in pe and marker.decode().encode('utf-16le') not in pe:raise ValueError('CDC marker absent')
        cdc_verified=True
        if record.get('cdc_application'):
            app_record=record['cdc_application'];app=(args.build/'UniXNU.efi').read_bytes()
            if app_record.get('service_sha256'):
                service_test=json.loads((args.build/'cdc-service-tests.json').read_text())
                if not service_test['passed'] or service_test['source_sha256']!=app_record['service_sha256'] or hashlib.sha256((args.build/'PdxUsbPrepare.c').read_bytes()).hexdigest()!=app_record['service_sha256']:
                    raise ValueError('CDC service tested source differs')
            if hashlib.sha256(app).hexdigest()!=app_record['app_sha256'] or hashlib.sha256((args.build/'Menu.c').read_bytes()).hexdigest()!=app_record['menu_sha256']:
                raise ValueError('CDC menu/application identity differs')
            if not any(kind==0x10 and data==app for sections in files.values() for kind,data in sections):
                raise ValueError('USB-consuming application absent from FD')
            service_guid=uuid.UUID('765f0768-b70e-43cc-917d-8f213169dc42').bytes_le
            if service_guid not in app or service_guid not in pe:raise ValueError('USB service producer/consumer missing')
            if b'PDX USB: application CDC start' not in pe or b'USB application service stopped' not in app:
                raise ValueError('Application CDC implementation absent')
            application_verified=True
    if not disabled and uuid.UUID('1c0cffce-fc8d-4e44-8c78-9c9e5b530d36').bytes_le not in pe:
        raise ValueError('Sony vendor start event missing')
    adaptations=record['vendor_usb'].get('adaptations',[])
    dal_checked=[];power_checked={};original_conditions=[];pe_adaptations=[]
    if adaptations:
        sys.path.insert(0,str(DEVICE/'ci'))
        from sony_dal_dependencies import CONSUMERS, DAL, evaluate
        for name in CONSUMERS:
            if name in {r['name'] for r in excluded}:continue
            row=next(r for r in record['vendor_usb']['modules'] if r['name']==name)
            expression=next(data for kind,data in files[row['guid']] if kind==0x13)
            prerequisites=set(row['depex_requires'])
            if evaluate(expression,prerequisites-{DAL}) or not evaluate(expression,prerequisites):
                raise ValueError('Incorrect DAL dispatch gate '+name)
            dal_checked.append(name)
    if any(a['kind']=='power-protocol-prerequisites' for a in adaptations):
        from sony_dal_dependencies import POWER_DEPENDENCIES, ULOG_DEPENDENCIES, USB_RESOURCE_DEPENDENCIES, require_protocols, require_dal
        dependencies=dict(POWER_DEPENDENCIES)
        for row in excluded:dependencies.pop(row['name'],None)
        if any(a['kind']=='ulog-protocol-prerequisite' for a in adaptations):dependencies.update(ULOG_DEPENDENCIES)
        if record['vendor_usb'].get('post_abl_power'):
            for name,required in USB_RESOURCE_DEPENDENCIES.items():dependencies[name]=dependencies.get(name,())+required
        from sony_pmic_handoff import adapt_pe
        original_root=DEVICE.parent/'uefi-pdx234/Binaries/pdx234'
        originals=json.loads((original_root/'usb-import.json').read_text())
        spmi_spec=importlib.util.spec_from_file_location('spmi_fix',Path(__file__).with_name('fix-sony-spmi-polling.py'))
        spmi=importlib.util.module_from_spec(spmi_spec);spmi_spec.loader.exec_module(spmi)
        for row in record['vendor_usb']['modules']:
            name=row['name'];original=next(r for r in originals['modules'] if r['name']==name)
            directory=original_root/'QcomPkg/Drivers'/name
            expression=(directory/(name+'.depex')).read_bytes()
            original_pe=(directory/(name+'.efi')).read_bytes()
            if hashlib.sha256(expression).hexdigest()!=original['depex_sha256'] or hashlib.sha256(original_pe).hexdigest()!=original['pe_sha256']:
                raise ValueError('Original vendor input changed '+name)
            if name in CONSUMERS:expression=require_dal(expression)
            required=dependencies.get(name,())
            expression=require_protocols(expression,required)
            actual=next(data for kind,data in files[row['guid']] if kind==0x13)
            if actual!=expression:raise ValueError('Original conditions or added gates changed '+name)
            original_conditions.append(name)
            if required:
                prerequisites=set(original['depex_requires'])|set(required)
                if name in CONSUMERS:prerequisites.add(DAL)
                if not evaluate(actual,prerequisites):raise ValueError('Unsatisfied complete dependency set '+name)
                for guid in required:
                    if evaluate(actual,prerequisites-{guid}):raise ValueError('Missing required power gate '+name+' '+guid)
                power_checked[name]=list(required)
            expected_pe=spmi.patch_pe(original_pe) if name=='SPMI' else adapt_pe(original_pe) if name=='PmicDxe' else original_pe
            if name=='UsbConfigDxe' and record['vendor_usb'].get('usb_prepare_errors'):
                from sony_usb_prepare_errors import adapt_pe as prepare_errors
                expected_pe=prepare_errors(original_pe,trace=True)
                test=json.loads((args.build/'usb-prepare-errors-tests.json').read_text())
                if not test.get('passed') or test.get('traced_sha256')!=hashlib.sha256(expected_pe).hexdigest():
                    raise ValueError('USB preparation tests differ from embedded PE')
            if name=='UsbfnDwc3Dxe' and record['vendor_usb'].get('usb_core_errors'):
                from sony_usb_core_errors import adapt_pe as adapt_core_errors
                expected_pe=adapt_core_errors(original_pe)
                if record['vendor_usb'].get('usb_core_trace'):
                    from sony_usb_core_trace import adapt_pe as trace_core
                    expected_pe=trace_core(original_pe)
                test=json.loads((args.build/'usb-core-errors-tests.json').read_text())
                if not test.get('passed') or not test.get('core_errors_fixed') or not test.get('real_attach_caller') or test['tested_pe_sha256']!=hashlib.sha256(expected_pe).hexdigest():
                    raise ValueError('USB core error tests differ from embedded PE')
                if record['vendor_usb'].get('usb_core_trace') and not test.get('trace_wrappers'):raise ValueError('Core trace wrappers not tested')
                if record['vendor_usb'].get('usb_core_trace'):
                    poll=json.loads((args.build/'usb-poll-errors-tests.json').read_text())
                    if not poll.get('passed') or not poll.get('trace_core') or poll.get('patched_sha256')!=hashlib.sha256(expected_pe).hexdigest():
                        raise ValueError('Combined EventHandler error propagation receipt differs')
            if name=='PmicDxe' and record['vendor_usb'].get('post_abl_power'):
                from sony_pmic_post_abl import adapt_pe as adapt_post
                expected_pe=adapt_post(expected_pe)
                if record['vendor_usb'].get('exit_handoff'):
                    from sony_pmic_exit_handoff import adapt_pe as adapt_exit
                    expected_pe=adapt_exit(expected_pe)
            if next(data for kind,data in files[row['guid']] if kind==0x10)!=expected_pe:
                raise ValueError('Unexpected vendor executable change '+name)
            if expected_pe!=original_pe:pe_adaptations.append(name)
        if set(power_checked)!=set(dependencies):raise ValueError('Missing power consumer')
    result=dict(fd_sha256=record['sha256'],vendor_modules_verified=len(record['vendor_usb']['modules']),
        original_depex_preserved=not adaptations,adaptations=adaptations,dal_dispatch_gates=dal_checked,
        power_dispatch_gates=power_checked,original_conditions_verified=original_conditions,
        source_qualified_pe_adaptations_verified=pe_adaptations,
        vendor_apriori_bypass_absent=True,
        excluded_modules_verified=[r['name'] for r in excluded],
        cdc_frontend_verified=cdc_verified,
        cdc_application_verified=application_verified,
        cdc_disabled_verified=bool(disabled),
        acpi_sdt_provider_embedded=True,usb_prepare_driver_embedded=not bool(disabled),
        vendor_start_event_present=not bool(disabled),hardware_dispatch_verified=False,usb_enumeration_verified=False,
        runtime_protocol_installation_verified=False)
    (args.build/'usb-verification.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))


def verify_glue(glue):
    depex=next(data for k,data in glue if k==0x13)
    for guid in ['e722b03f-b250-42ce-8ebd-5bd51812d037','d9d9ce48-44b8-4f49-8e3e-2a3b927dc6c1']:
        if b'\x02'+uuid.UUID(guid).bytes_le not in depex:raise ValueError('Missing glue protocol dependency')

if __name__=='__main__':main()
