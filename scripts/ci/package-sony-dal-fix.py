#!/usr/bin/env python3
"""Replace036 firmware with the verified DAL-dependent vendor build."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[2]
def sha(data):return hashlib.sha256(data).hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firmware',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--pmic-handoff',action='store_true',help='Package038 over037 with the verified non-XBOOT coin-cell adaptation')
    parser.add_argument('--pmic-tests',type=Path)
    parser.add_argument('--power-dependencies',action='store_true',help='Package039 over038 with verified power protocol prerequisites')
    parser.add_argument('--ulog-dependency',action='store_true',help='Package040 over039 with ULog before NPA')
    parser.add_argument('--ulog-tests',type=Path)
    parser.add_argument('--usb-scope',action='store_true',help='Package041 over040 omitting unrelated camera/PCIe RSC startup')
    parser.add_argument('--post-abl-power',action='store_true',help='Package042 over041 preserving charger policy and gating USB resources')
    parser.add_argument('--post-abl-tests',type=Path)
    parser.add_argument('--exit-handoff',action='store_true',help='Package043 over042 preserving inherited PMIC exit ownership')
    parser.add_argument('--exit-tests',type=Path)
    parser.add_argument('--cdc',action='store_true',help='Package044 over043 with Sony UsbDevice StartEx CDC frontend')
    parser.add_argument('--cdc-review',action='store_true',help='Package045 over044 with reviewed CDC scheduling and buffer ownership')
    parser.add_argument('--cdc-application',action='store_true',help='Package046 over045 with application-context CDC service')
    parser.add_argument('--cdc-provider-wait',action='store_true',help='Package047 over046 with event broadcast and USBFN readiness wait')
    parser.add_argument('--cdc-boundary',action='store_true',help='Package048 startup-boundary diagnostic over corrected047 menu')
    parser.add_argument('--cdc-core-snapshot',action='store_true',help='Package049 with bounded read-only pre-core snapshots')
    parser.add_argument('--usb-core-errors',action='store_true',help='Package052 over051 with tested USB core error propagation')
    parser.add_argument('--usb-core-trace',action='store_true',help='Package053 over052 with vendor call-boundary diagnostics')
    parser.add_argument('--native-staging',type=Path,help='Use verified053 native/display staging with retained052 firmware')
    parser.add_argument('--usb-prepare-errors',action='store_true')
    args=parser.parse_args()
    if args.power_dependencies and not args.pmic_handoff:parser.error('--power-dependencies requires --pmic-handoff')
    if args.ulog_dependency and not args.power_dependencies:parser.error('--ulog-dependency requires --power-dependencies')
    if args.usb_scope and not args.ulog_dependency:parser.error('--usb-scope requires --ulog-dependency')
    if args.post_abl_power and not args.usb_scope:parser.error('--post-abl-power requires --usb-scope')
    if args.exit_handoff and not args.post_abl_power:parser.error('--exit-handoff requires --post-abl-power')
    if args.cdc and not args.exit_handoff:parser.error('--cdc requires --exit-handoff')
    if args.cdc_review and not args.cdc:parser.error('--cdc-review requires --cdc')
    if args.cdc_application and not args.cdc_review:parser.error('--cdc-application requires --cdc-review')
    if args.cdc_provider_wait and not args.cdc_application:parser.error('--cdc-provider-wait requires --cdc-application')
    previous='046' if args.cdc_provider_wait else '045' if args.cdc_application else '044' if args.cdc_review else '043' if args.cdc else '042' if args.exit_handoff else '041' if args.post_abl_power else '040' if args.usb_scope else '039' if args.ulog_dependency else '038' if args.power_dependencies else '037' if args.pmic_handoff else '036'
    baseline=ROOT/('out/d27-pac-abi-release-20261116-'+previous)
    if args.cdc_boundary:
        if not args.cdc_provider_wait:parser.error('--cdc-boundary requires --cdc-provider-wait')
        baseline=ROOT/'out/d27-pac-abi-release-20261116-047-menu'
    if args.cdc_core_snapshot:
        if not args.cdc_boundary:parser.error('--cdc-core-snapshot requires --cdc-boundary')
        baseline=ROOT/'out/d27-pac-abi-release-20261116-048'
    if args.usb_core_errors:
        if not args.cdc_core_snapshot:parser.error('--usb-core-errors requires --cdc-core-snapshot')
        baseline=ROOT/'out/d27-pac-abi-release-20261116-051'
    if args.usb_core_trace:
        if not args.usb_core_errors:parser.error('--usb-core-trace requires --usb-core-errors')
        baseline=ROOT/'out/d27-pac-abi-release-20261116-052'
    if args.native_staging:
        if not args.usb_core_trace:parser.error('--native-staging requires --usb-core-trace')
        baseline=args.native_staging
    if args.usb_prepare_errors and not args.usb_core_trace:parser.error('--usb-prepare-errors requires --usb-core-trace')
    record=json.loads((baseline/'release.json').read_text())
    if args.native_staging:
        if not record.get('staging_only') or 'build-tag=PDX053' not in record['kernel_args'].split():
            raise ValueError('Require reviewed native053 staging')
    raw=(baseline/Path(record['image']).name).read_bytes()
    if sha(raw)!=record['sha256']:raise ValueError('Baseline image changed')
    fw=json.loads((args.firmware/'result.json').read_text())
    checks=json.loads((args.firmware/'usb-verification.json').read_text())
    fd=Path(fw['fd']).read_bytes()
    if args.cdc_boundary and not fw.get('cdc_frontend',{}).get('boundary_sha256'):
        raise ValueError('Startup boundary observer not built')
    if sha(fd)!=fw['sha256'] or checks['fd_sha256']!=fw['sha256'] or len(fd)!=0x300000:
        raise ValueError('Firmware identity differs')
    if args.cdc and not checks.get('cdc_frontend_verified'):raise ValueError('CDC frontend verification missing')
    if args.cdc_application and not checks.get('cdc_application_verified'):raise ValueError('CDC application verification missing')
    dal_consumers={'NpaDxe','ULogDxe','RscDxe','UsbConfigDxe'}
    if args.usb_scope:
        dal_consumers.remove('RscDxe')
        if checks.get('excluded_modules_verified')!=['RscDxe']:raise ValueError('RSC exclusion not verified')
    if set(checks['dal_dispatch_gates'])!=dal_consumers:
        raise ValueError('Missing DAL consumer gate')
    if args.power_dependencies:
        sys.path.insert(0,str(ROOT/'ci'))
        from sony_dal_dependencies import POWER_DEPENDENCIES, ULOG_DEPENDENCIES, USB_RESOURCE_DEPENDENCIES
        dependencies=dict(POWER_DEPENDENCIES)
        if args.usb_scope:dependencies.pop('RscDxe')
        if args.ulog_dependency:dependencies.update(ULOG_DEPENDENCIES)
        if args.post_abl_power:
            for name,required in USB_RESOURCE_DEPENDENCIES.items():dependencies[name]=dependencies.get(name,())+required
        if checks.get('power_dispatch_gates')!={k:list(v) for k,v in dependencies.items()}:
            raise ValueError('Missing power consumer gate')
        if set(checks.get('original_conditions_verified',[]))!={r['name'] for r in fw['vendor_usb']['modules']}:
            raise ValueError('Original conditions not verified')
        expected_adaptations={'SPMI','PmicDxe'}|({'UsbfnDwc3Dxe'} if args.usb_core_errors else set())
        if args.usb_prepare_errors:expected_adaptations.add('UsbConfigDxe')
        if set(checks.get('source_qualified_pe_adaptations_verified',[]))!=expected_adaptations:
            raise ValueError('Executable adaptations not verified')
    if next(r for r in fw['vendor_usb']['modules'] if r['name']=='SPMI')['pe_sha256']!=record['spmi_polling_fix']['spmi_patched_sha256']:
        raise ValueError('SPMI polling correction was lost')
    pmic_tests=None
    ulog_tests=None
    if args.ulog_dependency:
        if not args.ulog_tests:raise ValueError('NPA machine-code test receipt required')
        ulog_tests=json.loads(args.ulog_tests.read_text())
        npa=next(r for r in fw['vendor_usb']['modules'] if r['name']=='NpaDxe')
        if not ulog_tests['passed'] or ulog_tests['pe_sha256']!=npa['pe_sha256']:
            raise ValueError('NPA test identity differs')
    if args.pmic_handoff:
        if not args.pmic_tests:raise ValueError('PMIC machine-code test receipt required')
        pmic_tests=json.loads(args.pmic_tests.read_text())
        pmic=next(r for r in fw['vendor_usb']['modules'] if r['name']=='PmicDxe')
        if not pmic_tests['passed'] or (not args.post_abl_power and pmic_tests['adapted_pe_sha256']!=pmic['pe_sha256']):
            raise ValueError('PMIC adaptation differs from tested bytes')
    post_tests=None
    if args.post_abl_power:
        if not args.post_abl_tests:raise ValueError('Post-ABL entrypoint test receipt required')
        post_tests=json.loads(args.post_abl_tests.read_text())
        if not fw['vendor_usb'].get('post_abl_power') or not post_tests['passed'] or (not args.exit_handoff and post_tests['adapted_pe_sha256']!=pmic['pe_sha256']):
            raise ValueError('Post-ABL policy differs from tested bytes')
    exit_tests=None
    if args.exit_handoff:
        if not args.exit_tests:raise ValueError('Exit cleanup test receipt required')
        exit_tests=json.loads(args.exit_tests.read_text())
        if not fw['vendor_usb'].get('exit_handoff') or not exit_tests['passed'] or exit_tests['adapted_pe_sha256']!=pmic['pe_sha256']:
            raise ValueError('Exit cleanup differs from tested bytes')
    mem=struct.unpack_from('<Q',raw,4096+0x200000+16)[0]
    start=4096+0x200000+mem;end=start+len(fd)
    if sha(raw[start:end])!=record['firmware_sha256']:raise ValueError('Firmware extent differs')
    result=raw[:start]+fd+raw[end:]
    args.out.mkdir(parents=True,exist_ok=False)
    label='047' if args.cdc_provider_wait else '046' if args.cdc_application else '045' if args.cdc_review else '044' if args.cdc else '043' if args.exit_handoff else '042' if args.post_abl_power else '041' if args.usb_scope else '040' if args.ulog_dependency else '039' if args.power_dependencies else '038' if args.pmic_handoff else '037'
    if args.cdc_boundary:label='048'
    if args.cdc_core_snapshot:label='049'
    if args.usb_core_errors:label='052'
    if args.usb_core_trace:label='053'
    image=args.out/('boot-pdx234-pac-abi-'+label+'.img');image.write_bytes(result)
    if image.read_bytes()!=result:raise ValueError('Delivery differs')
    record.update(image=str(image),label='PAC-ABI-'+label,sha256=sha(result),firmware_sha256=sha(fd),
        source_image_sha256=sha(raw),vendor_usb_firmware=checks,dal_dispatch_fixed=True,
        correction='Require real DAL protocol before NPA/ULog/RSC/USBConfig, retain SPMI polling init',
        hardware_boot_verified=False,usb_hardware_verified=False)
    if args.pmic_handoff:
        record.update(correction='Preserve XBOOT coin-cell state after ABL; retain SPMI and DAL corrections',
                      pmic_handoff_tests=pmic_tests,pmic_handoff_adaptation=True)
    if args.power_dependencies:
        record.update(correction='Require NPA/Clock/RPMh/CmdDb power prerequisites before consumers; retain SPMI/DAL/PMIC adaptations',
                      power_dispatch_fixed=True)
    if args.ulog_dependency:
        record.update(correction='Require ULog protocol before NPA initialization; retain power/DAL/SPMI/PMIC corrections',
                      ulog_dependency_fixed=True,ulog_tests=ulog_tests)
    if args.usb_scope:
        record.update(correction='Omit unrelated camera/PCIe RscDxe startup; retain USB power prerequisites and earlier adaptations',
                      usb_scope=True)
    if args.post_abl_power:
        record.update(correction='Preserve inherited charger/PS_HOLD policy after ABL and wait for PMIC/ICB before USB consumers',
                      post_abl_power=True,post_abl_tests=post_tests)
    if args.exit_handoff:
        record.update(correction='Preserve inherited PMIC IRQ/lock/channel ownership during secondary UEFI cleanup',
                      exit_handoff=True,exit_tests=exit_tests)
    if args.cdc:
        record.update(correction='Start Sony USB device with CDC descriptors and poll enumeration/class/data events',
                      uefi_cdc_frontend=True,uefi_cdc_payload='completion-accounted diagnostic banner; full firmware log ring not integrated')
    if args.cdc_review:
        record.update(correction='Repair CDC timer scheduling, asynchronous buffer ownership and startup/EBS lifecycle',
                      cdc_lifecycle_review=True,poweroff_root_cause_verified=False)
    if args.cdc_application:
        record.update(correction='Execute CDC StartEx and HandleEvent from the UniXNU menu at TPL_APPLICATION',
                      cdc_application=True,poweroff_root_cause_verified=False)
    if args.cdc_provider_wait:
        record.update(correction='Broadcast vendor initialization with EVT_NOTIFY_SIGNAL and wait for real USBFN/device providers before StartEx',
                      cdc_provider_wait=True)
    if args.cdc_boundary:
        record.update(correction='Observe first HandleEvent, original charger query return and standard reset notification; correct iOS menu/default',
                      cdc_boundary_diagnostic=True,cdc_poweroff_fixed=False,poweroff_root_cause_verified=False)
    if args.cdc_core_snapshot:
        record.update(correction='Read DWC3 core state before first HandleEvent and after first charger query; preserve startup behavior',
                      cdc_core_snapshot=True)
    if args.usb_core_errors:
        if not fw['vendor_usb'].get('usb_core_errors'):raise ValueError('Core error adaptation not selected')
        record.update(correction='Return EFI_DEVICE_ERROR after failed DWC initialization; prevent erroneous RUN_STOP',
            usb_core_errors_fixed=True,usb_core_errors_tests=json.loads((args.firmware/'usb-core-errors-tests.json').read_text()),
            cdc_poweroff_fixed=False,poweroff_root_cause_verified=False,desktop_verified=False)
    if args.usb_core_trace:
        if not fw['vendor_usb'].get('usb_core_trace'):raise ValueError('Core trace missing')
        record.update(usb_core_trace=True,usb_poll_errors_tests=json.loads((args.firmware/'usb-poll-errors-tests.json').read_text()),
            correction='Trace actual vendor connect, reset and DMA setup boundaries; preserve052 error propagation')
    if args.native_staging:
        record.update(staging_only=False,correction='Integrate display lifecycle and native USB corrections with consolidated vendor diagnostics and error propagation')
    if args.usb_prepare_errors:
        if not fw['vendor_usb'].get('usb_prepare_errors'):raise ValueError('Preparation fixes missing')
        record.update(usb_prepare_errors=True,usb_prepare_errors_tests=json.loads((args.firmware/'usb-prepare-errors-tests.json').read_text()))
    (args.out/'release.json').write_text(json.dumps(record,indent=2)+'\n')
    (args.out/'SHA256SUMS').write_text(sha(result)+'  '+image.name+'\n')
    print(json.dumps(dict(image=str(image),sha256=sha(result),firmware_sha256=sha(fd)),indent=2))

if __name__=='__main__':main()
