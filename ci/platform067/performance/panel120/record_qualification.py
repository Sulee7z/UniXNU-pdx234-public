#!/usr/bin/env python3
"""Bind Sony panel modes, reference source and pure preflight tests to one receipt."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import sys
import urllib.request

from build_check import sha

HERE=Path(__file__).resolve().parent
SNAP=Path('/mnt/f/UniXNU-Port-artifacts/platform067-20261118')
REF=SNAP/'backlight-reference'
DSI=REF/'source/yodo-1.2.0-rel/vendor/qcom/opensource/display-drivers/msm/dsi'
HAL=REF/'source/yodo-1.2.0-rel_amss/BOOT.MXF.2.1.1/boot_images/boot/QcomPkg/Library/HALDSILib'
SDE=SNAP/'panel120-sde-reference-001'
MDSS=HAL.parent/'HALMDSSLib/mdssreg_900.h'
CAPTURE=Path('/mnt/g/UniXNU-Port/evidence/Xperia-XQ-DQ72/20261118-platform-post066-readonly-001')


def region(path,start,end):
    lines=path.read_text().splitlines();source='\n'.join(lines[start-1:end])+'\n'
    return dict(path=str(path),file_sha256=sha(path),first_line=start,last_line=end,
                source=source)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--qualification',type=Path,default=SNAP/'panel120-audit-006')
    p.add_argument('--build',type=Path,default=SNAP/'panel120-preflight-003');a=p.parse_args()
    info=json.loads((a.qualification/'modes.json').read_text());build=json.loads((a.build/'result.json').read_text())
    if not build['passed'] or sha(a.qualification/'modes.json')!=build['qualification_sha256']:
        raise ValueError('Qualification/test identity mismatch')
    for file,digest in build['source_hashes'].items():
        if sha(file)!=digest:raise ValueError('Preflight source changed: '+file)
    # Match the extra reference files against the separately extracted receipts.
    provenance=json.loads((REF/'provenance.json').read_text())
    pins={str(REF/'source'/row['member']):row['sha256'] for row in provenance['selected']}
    for row in json.loads((SDE/'result.json').read_text())['files']:pins[row['path']]=row['sha256']
    needed=[DSI/n for n in ('dsi_panel.c','dsi_display.c','dsi_ctrl.c','dsi_ctrl_hw_cmn.c','dsi_ctrl_reg.h','dsi_drm.c')]
    needed += [HAL/n for n in ('dsiHost.h','dsiHost.c','dsiHostShared.c','dsiDriver.c','HALdsi_Config.c')]
    needed += [SDE/n for n in ('sde_encoder_phys_cmd.c','sde_hw_intf.c','sde_hw_ctl.c','sde_hw_pingpong.c','sde_hw_dsc.c')]+[MDSS]
    for file in needed:
        if sha(file)!=pins[str(file)]:raise ValueError('Reference source changed: '+str(file))
    snippets={
        'command_mode_fps_dms':region(DSI/'dsi_display.c',5095,5116),
        'same_clock_does_not_request_reclock':region(DSI/'dsi_display.c',5231,5266),
        'skip_pps_on_fps_only':region(DSI/'dsi_display.c',8650,8687),
        'command_hs_vs_lp':region(DSI/'dsi_panel.c',539,576),
        'host_timing_commit':region(DSI/'dsi_ctrl.c',3030,3062),
        'dual_host_broadcast_order':region(DSI/'dsi_display.c',3273,3348),
        'link_clock_override':region(DSI/'dsi_ctrl.c',1065,1124),
        'mdp_budget_and_bitclock':region(DSI/'dsi_panel.c',4311,4349),
        'tearcheck_uses_refresh_and_real_vsync_clock':region(SDE/'sde_encoder_phys_cmd.c',1123,1157),
        'external_te_bit_vs_synthetic_counter':region(SDE/'sde_hw_intf.c',790,807),
        'te_counter_readback':region(SDE/'sde_hw_intf.c',810,834),
        'te_counter_single_buffer_order':region(SDE/'sde_hw_intf.c',671,698),
        'firmware_refresh_enum_not_implemented':region(HAL/'dsiHost.c',603,620),
        'firmware_cmd_config_not_fps_only':region(HAL/'HALdsi_Config.c',449,493),
    }
    (a.qualification/'source-evidence.json').write_text(json.dumps(snippets,indent=2)+'\n')
    fw=json.loads((REF/'retained-firmware.json').read_text())
    if sha(fw['retained_fd'])!=fw['sha256'] or fw['qcom_display_dxe_present_in_current_fd']:
        raise ValueError('Retained firmware identity changed')
    simple=Path(fw['source'])
    if sha(simple)!=fw['source_sha256']:raise ValueError('SimpleFb inspection source changed')
    modes=info['modes'];facts=[]
    for id in range(4):
        m=modes['timing@'+str(id)]
        facts.append(dict(id=id,property_hash=info['mode_property_hashes']['timing@'+str(id)],
            width_per_link=m['qcom,mdss-dsi-panel-width'][0],full_width=m['qcom,mdss-dsi-panel-width'][0]*2,
            height=m['qcom,mdss-dsi-panel-height'][0],supported_hz=m['qcom,mdss-dsi-panel-framerate'][0],
            bit_clock_hz=m['qcom,mdss-dsi-panel-clockrate'][0],mdp_transfer_us=m['qcom,mdss-mdp-transfer-time-us'][0],
            phy=m['qcom,mdss-dsi-panel-phy-timings'],dsc={k:v for k,v in m.items() if 'dsc-' in k},
            timing_switch=m['qcom,mdss-dsi-timing-switch-command'],
            default='qcom,mdss-dsi-timing-default' in m))
    log=CAPTURE/'android-dmesg.txt';text=re.sub(r'\x1b\[[0-9;]*m','',log.read_text(errors='replace'))
    observations=[line for line in text.splitlines() if 'dsi_display_set_mode' in line and 'hactive=' in line]
    request=urllib.request.Request('https://api.github.com/repos/UniXNU/GopFramebuffer/commits/main',
                                  headers={'User-Agent':'PDX234-panel120-source-audit'})
    latest=json.load(urllib.request.urlopen(request,timeout=45))
    (a.qualification/'latest-gop-api.json').write_text(json.dumps(latest,indent=2)+'\n')
    pin=latest['sha']
    if pin!='b0d812d578efa2acb005b66f73168891719af09a':raise ValueError('GOP upstream changed; review new driver API')
    gop_files={}
    for name in ('NativeLegacyDisplay.cpp','NativeGOPWire.h','README.md'):
        data=urllib.request.urlopen('https://raw.githubusercontent.com/UniXNU/GopFramebuffer/'+pin+'/'+name,timeout=45).read()
        dst=a.qualification/('official-GopFramebuffer-'+name);dst.write_bytes(data)
        gop_files[name]=dict(path=str(dst),sha256=sha(dst))
    brightness=HERE.parents[3]/'drivers/SonyOledBacklight/SonyDsi.h'
    result=dict(schema=1,date='2026-11-18',scope='Sony somc,1_panel actual120 qualification; no inherited-mode assumption',
        modes=str(a.qualification/'modes.json'),modes_sha256=sha(a.qualification/'modes.json'),
        live_dtb=str(CAPTURE/'live.dtb'),live_dtb_sha256=info['sha256'],mode_facts=facts,
        panel=info['panel'],hardware=info['hardware'],
        source_pin_manifest={str(p):pins[str(p)] for p in needed},
        reference_archive_sha256=provenance['archive_sha256'],reference_only=True,
        source_evidence=str(a.qualification/'source-evidence.json'),source_evidence_sha256=sha(a.qualification/'source-evidence.json'),
        supported120_vs_inherited=dict(current_mode_unknown=True,current_hz_unknown=True,
            gop_geometry_is_not_panel_timing=True,current_uefi_fd=fw['retained_fd'],current_fd_sha256=fw['sha256'],
            current_fd_has_simplefb=True,current_fd_has_qcom_displaydxe=False,
            simplefb_source=str(simple),simplefb_source_sha256=sha(simple),
            simplefb_setmode='unconditional EFI_SUCCESS, no DSI/PLL/MDP changes',
            original_sony_displaydxe=fw['original_display_dxe'],
            android_log=str(log),android_log_sha256=sha(log),android_mode_requests=observations,
            android_requests_not_ios_or_panel_te_proof=True),
        transition_facts=dict(native_resolution='timing@1 (60) -> timing@3 (120)',
            low_resolution='timing@0 (60) -> timing@2 (120)',
            retune_pll_required_by_dtb=False,change_phy_values_required_by_dtb=False,
            dsc_parameters_change_for_same_resolution=False,
            fps_only_reference_skips_pps=True,
            unknown_inherited_dsc_requires_readback_not_blind_pps=True,
            native_mdp_budget_us=[15300,7680],low_mdp_budget_us=[7680,7680],
            panel120_batch='7 HS packets / 72 bytes, all VC0, ack0, last1, no post-wait; dual-host broadcast',
            native120_payloads=[p['data'] for p in modes['timing@3']['qcom,mdss-dsi-timing-switch-command']['packets']],
            low120_payloads=[p['data'] for p in modes['timing@2']['qcom,mdss-dsi-timing-switch-command']['packets']],
            hmd_commands_are_not_fps_switch=True,lp_exit_and_on_commands_differ=True,
            vendor_opcode_meaning_without_ddic_spec='0x60 observed delta, not independently decoded DDIC register definition'),
        required_backend=dict(single_display_owner=True,
            ownership='Same exclusive epoch/lease as OLED brightness; pin clocks/rails, exit ULPS, quiesce MDP/GOP producer, wait both DMA engines; no nested apps-SMMU lock',
            acquire_snapshot='actual DSI0/1 HW version/control, stream/DSC/PPS readback, PLL/PHY live values, CTL route, panel identity/SDR/HMD, TE source and active mode',
            host_timing='equivalent dsi_ctrl_host_timing_update for both hosts, no PLL retune if readback matches identical clocks',
            hs_batch='owner sends arbitrary pinned payloads in HS mode, stage both hosts and trigger slave then master, wait both done/errors under same lease',
            mdp='apply 7680us budget and external-TE tearcheck via actual VSYNC clock, active CTL/intf/PP allocation; no single hardcoded MDSS budget register is defined',
            measurement='actual external TE for both links at ~8333us, over >=1s after commit; not software vsync, ordinary interface frames or unqualified synthetic tear counter',
            resume='after confirmed host/MDP/panel completion and TE, resume producer; only then publish requested/observed refresh separately',
            failure='partial packet/timeout/ownership loss retains poisoned lease until owner recovery; no blind reset, relock success or rollback claim'),
        precise_register_inputs=dict(
            dsi_hosts=['0xae94000','0xae96000'],dsi_bytes='0x1000',
            dsi_offsets={'version':'0x0','control':'0x4','status':'0x8','dma_ctrl':'0x3c','stream0_ctrl':'0x58','stream0_total':'0x5c',
                         'trigger_ctrl':'0x84','dma_sw_trigger':'0x90','interrupt':'0x110'},
            intf_bases=['0xae36000','0xae37000'],
            intf_offsets={'timestamp_ctrl':'0x210','panel_vsync_ts_lo':'0x214','panel_vsync_ts_hi':'0x218',
                          'tear_enable':'0x284','tear_vsync_config':'0x288','tear_height':'0x28c','vsync_init':'0x294',
                          'read_pointer_frame_line':'0x298','threshold':'0x29c','start_pos':'0x2a0','rd_irq_line':'0x2a4',
                          'wr_irq_line':'0x2a8','line_count':'0x2b0','autorefresh':'0x2b4'},
            external_te_enable_bit=20,synthetic_counter_enable_bit=19,
            te_line_count_low19='must derive from actual VSYNC clock / (vtotal*fps), never assume 19.2MHz',
            active_ctl_pp_dsc_route='unknown: DT lists available blocks, not inherited selected instance',
            board_register_values_available=False),
        brightness_api_review=dict(header=str(HERE.parents[3]/'drivers/SonyOledBacklight/SonyDsi.h'),
            header_sha256=sha(brightness),
            reference_only=True,existing='sony_dsi_start_write(dbv)/read52 fixed 8byte FIFO transactions; no arbitrary HS panel mode sequence',
            required_extension='single owner generic batch + mode snapshot/host/MDP/TE operations; do not create another competing DMA engine',
            edited=False),
        latest_official_display_api=dict(pin=pin,discovery=str(a.qualification/'latest-gop-api.json'),
            discovery_sha256=sha(a.qualification/'latest-gop-api.json'),files=gop_files,
            available=['native_legacy_refresh_hz weak board hook for reported cadence',
                       'native_legacy_set_refresh_properties original family publisher',
                       'native_legacy_vsync_notify original family vsync sender',
                       'NativeGOPWire NGPMode geometry and present/swap/complete selectors'],
            not_provided=['generic Sony DSI command batch','DSC/PHY/PLL inherited-mode capture',
                          'exclusive display hardware owner/lease','panel TE IRQ backend','Sony panel mode switch'],
            integration_after_real_switch='board measured state may supply native_legacy_refresh_hz, followed by family refresh-property update; current driver caches its IOTimer interval at startVsync, so an already-running timer needs a workloop-owned refresh/restart path or real-TE backend',
            no_upstream_core_upgrade_needed=True),
        preflight=build,automatic_startup=False,mmio_enabled=False,
        panel120_proven=False,mode_switch_executable=False,native_or_firmware_changed=False,
        no_device_operations=True,performance006_unchanged=True,
        missing=['inherited iOS DSI/DSC/PLL/PHY/CTL/TE snapshot',
                 'live display-owner lease and generic HS batch transmitter',
                 'quiesced MDP host timing/transfer-budget/tearcheck backend',
                 'external TE source verification and measured post-switch period',
                 'qualified recovery for a partially transmitted manufacturer batch'])
    # Source ABI is a read-only description; no brightness file is modified.
    (HERE/'qualification.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(qualification=str(HERE/'qualification.json'),sha256=sha(HERE/'qualification.json'),
                         preflight_archive=build['archive'],archive_sha256=build['archive_sha256'],
                         missing=result['missing']),indent=2))


if __name__=='__main__':main()
