#!/usr/bin/env python3
"""Run actual Sony PMIC sampling, consumer HID and official observer helper tests."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
SHENG = Path('/mnt/f/UniXNU-Port-artifacts/platform067-20261118/sheng')
SHENG_REVISION = '6c42e1055ffb3b335fda991190ad221edaa7af3c'
HID = Path('/root/unixnu-build/pdx234-local-github-a6d2286-001/out/feeds/IOHIDFamily-f53ac321')
HID_REVISION = 'e31e90a24c27ad6cbe981650d12a1a4124065b03'


def sha(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(command: list[str], log: Path, timeout: int = 60) -> str:
    log.with_suffix('.command.json').write_text(json.dumps(command, indent=2) + '\n')
    done = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    log.write_text(done.stdout)
    if done.returncode:
        raise RuntimeError(f'{log}: exit {done.returncode}\n{done.stdout[-9000:]}')
    return done.stdout


def offline_evidence() -> dict:
    """Extract historical mapping facts, never manufacture a per-boot read grant."""
    bootshim = Path('/mnt/g/UniXNU-Port/ports/uefi-pdx234/BootShim/Pdx234Combo.S')
    extracted = BASE / 'sony-spmi-fix-001'
    pmic = next((BASE / 'sony-pmic-full-001').rglob('pm_spmi_config.c'))
    access = extracted / 'sony-yodo-1.2.0-rel_amss__BOOT.MXF.2.1.1__boot_images__boot__Settings__Kailua__Core__PMIC__access.dtsi'
    arb = access.with_name(access.name.replace('access.dtsi', 'arb.dtsi'))
    lib = extracted / 'full-spmi/yodo-1.2.0-rel_amss/BOOT.MXF.2.1.1/boot_images/boot/QcomPkg/Library/SPMILib/src'
    block = lib / 'platform/config/hoya7/kailua/SpmiBlock.c'
    cfg = lib / 'core/hal/hoya7/SpmiBusCfg.c'
    lookup = lib / 'core/hal/hoya7/PmicArb.c'
    linux = extracted / 'sony-yodo-1.2.0-rel__kernel_platform__msm-kernel__drivers__spmi__spmi-pmic-arb.c'
    table = pmic.read_text()
    rows = re.findall(r'\{\s*(\d+)\s*,\s*(\d+)\s*,\s*(0x[0-9A-Fa-f]+)\s*,\s*(SPMI_OWNER_\w+)\s*,\s*(SPMI_OWNER_\w+)\s*,\s*(SPMI_CHNL_\w+)\s*\}', table)
    selected = []
    for i, (bus, sid, peripheral, irq, owner, oem) in enumerate(rows):
        if (int(bus), int(sid), int(peripheral, 16)) in [(0, 0, 0x13), (0, 1, 0x8d)]:
            if (irq, owner) != ('SPMI_OWNER_APPS', 'SPMI_OWNER_APPS'):
                raise ValueError('OEM named-peripheral owner facts differ')
            selected.append(dict(bus=0, ppid=hex((int(sid) << 8) | int(peripheral, 16)),
                                 irq_owner=irq, peripheral_owner=owner, oem=oem,
                                 source_ordinal_not_apid=i))
    if len(selected) != 2:
        raise ValueError('OEM PON/GPIO ownership rows absent or duplicated')
    if 'SPMI_OWNER_APPS,    // ee id 0' not in block.read_text():
        raise ValueError('OEM APPS EE number differs')
    macro = '(((apid)      & 0x3FF) << 0)'
    if macro not in linux.read_text():
        raise ValueError('Linux hwirq APID schema changed')
    captures = Path('/mnt/g/UniXNU-Port/evidence/Xperia-XQ-DQ72')
    observations, files = [], [bootshim, pmic, access, arb, block, cfg, lookup, linux]
    for relative in ['20261118-touch-readonly-001/irq-state.txt',
                     '20261118-touch061-readonly-001/interrupts.txt',
                     '20261118-touch-live-logs-001/pre-interrupts.txt',
                     '20261118-touch-live-logs-001/post-interrupts.txt',
                     '20261118-platform-post066-readonly-001/interrupts.txt']:
        path = captures / relative
        files.append(path)
        for line in path.read_text().splitlines():
            match = re.search(r'pmic_arb\s+(\d+)\s+\w+\s+(pmic_pwrkey|pmic_resin)\s*$', line)
            if not match:
                continue
            irq = int(match[1])
            sid, periph, bit, apid = irq >> 28 & 15, irq >> 20 & 255, irq >> 16 & 7, irq & 1023
            if (sid, periph, bit, apid) != (0, 0x13, 7 if match[2] == 'pmic_pwrkey' else 6, 560):
                raise ValueError('Captured PON mapping conflicts with the historical APID560 fact')
            observations.append(dict(path=str(path), name=match[2], hwirq=irq, hex=hex(irq),
                                     sid=sid, peripheral=periph, irq_bit=bit, apid=apid))
    if len(observations) != 10:
        raise ValueError('Expected five retained captures of both PON inputs')
    text = bootshim.read_text()
    if 'cmp w14, #0x013' not in text or '_FindPon:' not in text or '.ascii "PXCBHOF1"' not in text:
        raise ValueError('Retained named-PON selector schema differs')
    info = text.split('_ComboInfo:', 1)[1]
    if 'x13' in info or 'owner' in info.lower():
        raise ValueError('Re-review BootShim: APID/owner handoff added')
    return dict(sources={str(p): sha(p) for p in files},
                requested_touch_board_reference_has_no_pmic_tables=True,
                actual_oem_table_from_retained_extraction=str(pmic),
                oem_named_peripheral_policy=selected, apps_ee=0,
                historical_android_observations=observations,
                historical_pon_read_apid_candidate=560,
                candidate_exact_addresses=dict(apid_map='0x0c4028c0', owner='0x0c42d8c0',
                    observer='0x0c444600', status='0x0c444608', data='0x0c444618'),
                bootshim_named_ppid_lookup=True, bootshim_peripheral_probe_sweep=False,
                bootshim_first_match_checks_owner=False, bootshim_saves_apid_or_owner=False,
                table_ordinal_is_not_runtime_apid=True,
                per_boot_hlos_owner_word_captured=False, per_boot_read_certificate_available=False,
                current_xnu_observer_read_proven=False,
                named_ppid_lookup_needed_with_candidate560=False,
                source_qualified_experimental_bringup=True,
                previous_completed_xnu_read_required=False,
                manual_test_bootargs=['sony-buttons=1','sony-buttons-read-qualified=1','sony-buttons-pon-apid=560'],
                first_observer_read_is_normal_initialization_after_sameboot_metadata_checks=True,
                fallback_plan='Select historical/OEM-qualified PPID013/APID560, validate sameboot v7/count/map/IRQowner/ownerEE0 in native prepare and eachsample, then issue first normal bounded observer read; reject a mismatch and do not search or change ownership. Runtime hardware acceptance remains false.',
                hardware_acceptance_verified=False)


def sony_linux_read_fixture(out: Path, flags: list[str], fixture: Path, reference: Path | None = None) -> tuple[str, Path]:
    linux = reference or BASE / 'sony-spmi-fix-001/sony-yodo-1.2.0-rel__kernel_platform__msm-kernel__drivers__spmi__spmi-pmic-arb.c'
    text = linux.read_text()
    # The standalone fixture supplies these public constants. Refuse drift
    # instead of accidentally comparing a hand-written register layout.
    for name, value in [('PMIC_ARB_CMD','0x00'), ('PMIC_ARB_STATUS','0x08'),
                        ('PMIC_ARB_RDATA0','0x18'), ('PMIC_ARB_RDATA1','0x1C'),
                        ('PMIC_ARB_TIMEOUT_US','1000'), ('PMIC_ARB_MAX_TRANS_BYTES','(8)')]:
        if not re.search(r'^#define\s+'+name+r'\s+'+re.escape(value)+r'\s*$',text,re.M):
            raise ValueError('Sony Linux fixture macro differs: '+name)
    functions = []
    for name in ['pmic_arb_set_rd_cmd', 'pmic_arb_read_data', 'pmic_arb_wait_for_done',
                 'pmic_arb_read_cmd', 'pmic_arb_offset_v7', 'pmic_arb_fmt_cmd_v2']:
        match = re.search(r'^static (?:inline )?(?:void|int|u32)(?:\s+|\n)'+name+r'\s*\(', text, re.M)
        if not match:
            raise ValueError('Verbatim Sony Linux function not found: ' + name)
        first = text.index('{', match.start()); depth = 1; last = first + 1
        while depth:
            depth += (text[last] == '{') - (text[last] == '}'); last += 1
        functions.append(text[match.start():last])
    generated = out / 'actual-sony-linux-read.inc'
    generated.write_text('// SPDX-License-Identifier: GPL-2.0-only\n// Verbatim Sony reference functions; platform/arbiter services modeled by test.\n'+'\n\n'.join(functions)+'\n')
    exe = out / 'linux-read'
    run(['clang','-std=gnu11',*flags,'-I',str(out),'-Wno-unused-parameter','-Wno-gnu-pointer-arith',
         str(fixture),'-o',str(exe)],out / 'linux-read-compile.log')
    return run([str(exe)],out / 'linux-read-run.log',20),linux


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--snapshot', type=Path, help='Builder-owned immutable source/include/tests-source snapshot')
    args = parser.parse_args()
    out = args.out.resolve()
    snapshot = args.snapshot.resolve() if args.snapshot else None
    if snapshot and (snapshot.parent != BASE or not snapshot.name.startswith('sony-buttons-driver-')):
        raise ValueError('Snapshot must be a dedicated BASE/sony-buttons-driver-* build')
    if not ((out.parent == BASE and out.name.startswith('sony-buttons-host-')) or
            (snapshot and out == snapshot / 'tests')):
        raise ValueError('Use a new isolated BASE/sony-buttons-host-* folder')
    if subprocess.check_output(['git', '-C', str(SHENG), 'rev-parse', 'HEAD'], text=True).strip() != SHENG_REVISION:
        raise ValueError('Official sheng snapshot differs')
    if subprocess.check_output(['git', '-C', str(HID), 'rev-parse', 'HEAD'], text=True).strip() != HID_REVISION:
        raise ValueError('Apple HID parser snapshot differs')
    helper = snapshot / 'include/BootResetCore.h' if snapshot else SHENG / 'package/BootResetCore.h'
    if helper.read_bytes() != subprocess.check_output(['git', '-C', str(SHENG), 'show', 'HEAD:package/BootResetCore.h']):
        raise ValueError('Official observer helper changed')
    out.mkdir(parents=True, exist_ok=False)
    driver = snapshot / 'source' if snapshot else ROOT / 'drivers/SonyButtons'
    own_headers = snapshot / 'include' if snapshot else driver
    fixtures = snapshot / 'tests-source' if snapshot else ROOT / 'tests'
    flags = ['-O1', '-g', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
             '-fno-omit-frame-pointer', '-I', str(driver), '-I', str(own_headers), '-I', str(fixtures),
             '-I', str(helper.parent)]
    obj = out / 'core.o'
    run(['clang', '-std=c11', *flags, '-c', str(driver / 'SonyButtonsCore.c'), '-o', str(obj)], out / 'core-compile.log')
    outputs = {}
    for name, source, extras in [
        ('core', fixtures / 'sony_buttons_core.cpp', []),
        ('hid', fixtures / 'sony_buttons_hid.cpp', []),
        ('spmi', fixtures / 'sony_buttons_spmi.cpp', [str(driver / 'SonyButtonsSpmi.cpp')]),
        ('startup', fixtures / 'sony_buttons_startup.cpp', [str(driver / 'SonyButtonsSpmi.cpp')]),
    ]:
        exe = out / name
        run(['clang++', '-std=c++17', *flags, '-DSONY_BUTTONS_HOST_TEST=1', str(source), *extras,
             str(obj), '-o', str(exe)], out / f'{name}-compile.log')
        if name == 'startup':
            outputs[name] = ''.join(run([str(exe), mode], out / f'{name}-{mode}-run.log', 20)
                                    for mode in ['neutral', 'missing-apid', 'bad-apid', 'foreign', 'read'])
        else:
            outputs[name] = run([str(exe)], out / f'{name}-run.log', 20)
    hid_source = snapshot / 'test-reference/IOHIDFamily' if snapshot else HID
    source = hid_source / 'IOHIDSystem/IOHIDDescriptorParser'
    parser_sources = sorted(source.glob('*.c'))
    exe = out / 'parser'
    # Unchanged Apple HIDNextItem.c:184 sign-extends with signed0xff<<24.
    # Suppress only shift-base on this separate upstream parser executable;
    # every Sony source above keeps the full ASan/UBSan set.
    run(['clang', '-std=c11', *flags, '-fno-sanitize=shift-base', '-DRTKIT=1', '-D__unused=__attribute__((unused))',
         '-Wno-multichar', '-Wno-misleading-indentation', '-include', 'string.h', '-I', str(hid_source / 'IOHIDFamily'),
         '-I', str(hid_source / 'IOHIDSystem/IOKit/hidsystem'), '-I', str(source),
         *map(str, parser_sources), str(fixtures / 'sony_buttons_parser.c'), '-o', str(exe)], out / 'parser-compile.log')
    outputs['parser'] = run([str(exe)], out / 'parser-run.log', 20)
    linux_reference = snapshot / 'test-reference/sony-linux-spmi-pmic-arb.c' if snapshot else None
    outputs['linux_read'], linux = sony_linux_read_fixture(out, flags, fixtures / 'sony_buttons_linux_read.c', linux_reference)
    offline = offline_evidence()
    (out / 'offline-evidence.json').write_text(json.dumps(offline, indent=2) + '\n')
    files = [*sorted(driver.glob('*.[ch]')), *sorted(driver.glob('*.cpp')), *sorted(fixtures.glob('sony_buttons*')),
             *sorted(own_headers.glob('SonyButtons*.h')), *sorted(source.glob('*.h')),
             *sorted((hid_source / 'IOHIDFamily').glob('*.h')),
             *sorted((hid_source / 'IOHIDSystem/IOKit/hidsystem').glob('*.h')),
             *parser_sources, helper, linux, Path(__file__)]
    result = dict(passed=True, sources={str(p): sha(p) for p in files if p.is_file()}, output=outputs,
                  offline_evidence=str(out / 'offline-evidence.json'), offline_evidence_sha256=sha(out / 'offline-evidence.json'),
                  official_sheng=SHENG_REVISION, apple_parser=HID_REVISION,
                  actual_core_and_hid_and_spmi_executed=True, platform_services_modeled=True,
                  official_br_read8_executed=True, no_home_usage=True, debounce_ms=15,
                  verbatim_sony_linux_read_executed=True,
                  linux_read_offsets_opcode_and_status_match=True,
                  previous_completed_xnu_read_is_not_a_prerequisite=True,
                  source_qualified_experimental_power_volume_up=True,
                  compiled_snapshot=str(snapshot) if snapshot else None,
                  tested_production_snapshot={str(p):sha(p) for p in [*driver.glob('SonyButtons*.c'),
                      *driver.glob('SonyButtons*.cpp'),*own_headers.glob('SonyButtons*.h'),helper]},
                  linux_read_fixture=str(out / 'actual-sony-linux-read.inc'),
                  linux_read_fixture_sha256=sha(out / 'actual-sony-linux-read.inc'),
                  bounded_read_wait_iterations=100000, terminal_failure_limit=3,
                  deferred_event_matching_queue=32, failed_release_retried=True,
                  hardware_status_bytes_are_models_not_captured_press_trace=True,
                  handset_read_mapping_qualified=False, backboardd_runtime_verified=False,
                  neutral_hid_ready_without_mmio=True, historical_pon_apid_candidate=560,
                  sanitizers=['address', 'undefined'],
                  upstream_parser_only_shift_base_excluded='Unmodified HIDNextItem.c:184 signed sign-extension; host003 records original UBSan diagnostic')
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(''.join(outputs.values()), end='')


if __name__ == '__main__':
    main()
