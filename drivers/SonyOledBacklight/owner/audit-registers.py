#!/usr/bin/env python3
"""Check predicates against exact Sony OEM macros; emit a read-only capture list.

No ADB, device mapping, register reads or device writes are performed here.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent
REF=Path('/mnt/f/UniXNU-Port-artifacts/platform067-20261118/backlight-reference')

def sha(p):
    with Path(p).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',required=True,type=Path);a=p.parse_args()
    a.out.mkdir(parents=True,exist_ok=False)
    rel='yodo-1.2.0-rel_amss/BOOT.MXF.2.1.1/boot_images/boot/QcomPkg/Library/HALMDSSLib/mdssreg_900.h'
    source=REF/'source'/rel;provenance=json.loads((REF/'provenance.json').read_text())
    if sha(source)!=next(r['sha256'] for r in provenance['selected'] if r['member']==rel):raise ValueError('Sony register reference changed')
    lines=source.read_text().splitlines();macros={}
    for i,line in enumerate(lines,1):
        match=re.match(r'#define\s+(\w+)\s+(0x[0-9a-fA-F]+)\s*$',line)
        if match:macros[match[1]]=(int(match[2],16),i)
    needed={
        'HWIO_DSI_0_CTRL_DSI_EN_BMSK':1,'HWIO_DSI_0_CTRL_CMD_MODE_EN_BMSK':4,
        'HWIO_DSI_0_CTRL_VIDEO_MODE_EN_BMSK':2,'HWIO_DSI_0_CTRL_CLKLN_EN_BMSK':0x100,
        'HWIO_DSI_0_CTRL_DLN3_EN_BMSK':0x80,'HWIO_DSI_0_CTRL_DLN2_EN_BMSK':0x40,
        'HWIO_DSI_0_CTRL_DLN1_EN_BMSK':0x20,'HWIO_DSI_0_CTRL_DLN0_EN_BMSK':0x10,
        'HWIO_DSI_0_LANE_STATUS_CLKLN_ULPS_ACTIVE_NOT_BMSK':0x1000,
        'HWIO_DSI_0_LANE_STATUS_DLN3_ULPS_ACTIVE_NOT_BMSK':0x800,
        'HWIO_DSI_0_LANE_STATUS_DLN2_ULPS_ACTIVE_NOT_BMSK':0x400,
        'HWIO_DSI_0_LANE_STATUS_DLN1_ULPS_ACTIVE_NOT_BMSK':0x200,
        'HWIO_DSI_0_LANE_STATUS_DLN0_ULPS_ACTIVE_NOT_BMSK':0x100,
        'HWIO_DSI_0_LANE_STATUS_CLKLN_STOPSTATE_BMSK':0x10,
        'HWIO_DSI_0_LANE_STATUS_DLN3_STOPSTATE_BMSK':8,
        'HWIO_DSI_0_LANE_STATUS_DLN2_STOPSTATE_BMSK':4,
        'HWIO_DSI_0_LANE_STATUS_DLN1_STOPSTATE_BMSK':2,
        'HWIO_DSI_0_LANE_STATUS_DLN0_STOPSTATE_BMSK':1,
        'HWIO_DSI_0_CLK_STATUS_DSI_AON_ESCCLK_ACTIVE_BMSK':0x100,
        'HWIO_DSI_0_CLK_STATUS_DSI_AON_BYTECLK_ACTIVE_BMSK':0x40,
        'HWIO_DSI_0_CLK_STATUS_DSI_AON_DSICLK_ACTIVE_BMSK':0x10,
        'HWIO_DSI_0_CLK_STATUS_DSI_AON_AHBS_HCLK_ACTIVE_BMSK':4,
        'HWIO_DSI_0_CLK_STATUS_DSI_AON_AHBM_HCLK_ACTIVE_BMSK':1,
        'HWIO_DSI_0_CLK_STATUS_DSIPLL_UNLOCKED_BMSK':0x10000,
        'HWIO_DSI_0_CLK_CTRL_DSI_ESCCLK_ON_BMSK':0x20,
        'HWIO_DSI_0_CLK_CTRL_DSI_BYTECLK_ON_BMSK':0x10,
        'HWIO_DSI_0_CLK_CTRL_DSI_DSICLK_ON_BMSK':8,
        'HWIO_DSI_0_CLK_CTRL_DSI_AHBM_SCLK_ON_BMSK':2,
        'HWIO_DSI_0_CLK_CTRL_DSI_AHBS_HCLK_ON_BMSK':1,
        'HWIO_DSI_0_CLK_CTRL_DSI_DMA_CLK_STOP_BMSK':0x400000,
        'HWIO_MDSS_HW_INTR_STATUS_DSI0_BMSK':0x10,'HWIO_MDSS_HW_INTR_STATUS_DSI1_BMSK':0x20,
        'HWIO_MDP_INTF_1_TEAR_AUTOREFRESH_CONFIG_ENABLE_BMSK':0x80000000,
        'HWIO_MDP_INTF_2_TEAR_AUTOREFRESH_CONFIG_ENABLE_BMSK':0x80000000
    }
    checked=[]
    for name,value in needed.items():
        actual,line=macros[name]
        if actual!=value:raise ValueError('Exact OEM predicate mismatch '+name)
        checked.append(dict(macro=name,value=hex(actual),line=line))
    irq=[(name,value,line) for name,(value,line) in macros.items()
         if name.startswith('HWIO_DSI_0_INT_CTRL_') and name.endswith('_MASK_BMSK')]
    mask=0
    for name,value,line in irq:mask|=value
    if mask!=0xaa22aa0a:raise ValueError('Incomplete exact OEM IRQ mask')
    # These are readable status/config registers only. Both controller bases and
    # INTF resources are independently in the actual liveDT. They are NOT an
    # authorization to access unpowered/protected MMIO via /dev/mem.
    offsets=[(0x000,'HW_VERSION'),(0x004,'CTRL'),(0x008,'STATUS'),(0x00c,'FIFO_STATUS'),
             (0x03c,'COMMAND_MODE_DMA_CTRL'),(0x058,'MDP_STREAM0_CTRL'),(0x05c,'MDP_STREAM0_TOTAL'),
             (0x068,'ACK_ERR_STATUS'),(0x084,'TRIG_CTRL'),(0x0a8,'LANE_STATUS'),(0x0ac,'LANE_CTRL'),
             (0x0b4,'DLN0_PHY_ERR'),(0x0c0,'TIMEOUT_STATUS'),(0x100,'DMA_SCHEDULE_CTRL'),
             (0x104,'DMA_SCHEDULE_CTRL2'),(0x110,'INT_CTRL'),(0x118,'SOFT_RESET'),(0x11c,'CLK_CTRL'),
             (0x120,'CLK_STATUS'),(0x12c,'PHY_SW_RESET'),(0x15c,'TEST_PATTERN_GEN_CTRL'),
             (0x2b8,'READ_BACK_DISABLE_STATUS'),(0x2cc,'SECURE_DISPLAY_STATUS')]
    hosts=[dict(host=h,base=hex(0xae94000+h*0x2000),registers=[dict(offset=hex(o),physical=hex(0xae94000+h*0x2000+o),name=n) for o,n in offsets]) for h in range(2)]
    minimum=dict(stage='actual UEFI->XNU retained state with visible scanout; not Android alone',
        source='existing mapped/safe debug snapshot only; no probe-unpowered ranges and no GIC/DSI clears',
        pair_samples='two samples at one visible steady mode; label timestamps,source image SHA and power state',
        hosts=hosts,
        dpu_autorefresh=[dict(intf=h,physical=hex(0xae362b4+h*0x1000),name='TEAR_AUTOREFRESH_CONFIG',blocking=True) for h in range(2)],
        mdss_interrupt=dict(physical='0xae00010',name='MDSS_HW_INTR_STATUS',blocking=True),
        supply_clock_software_state=dict(blocking=True,
            clocks=['disp_cc_mdss_ahb_clk','disp_cc_mdss_byte0_clk','disp_cc_mdss_byte0_intf_clk',
                    'disp_cc_mdss_byte1_clk','disp_cc_mdss_byte1_intf_clk','disp_cc_mdss_esc0_clk','disp_cc_mdss_esc1_clk'],
            regulators=['pm_humu_l12/vddio','pm_humu_l13/vci','pm_v6d_l3/vddr',
                        'pm_v6e_l3/vdda1p2','pm_v6e_l1/vdda0p9'],
            evidence='existing regulator_summary/clk_summary plus native resource owner lifetime; DSI regs cannot prove it'),
        panel=dict(existing_readonly_files=['panel name/identity','hmd_mode','thermal_limit','somc_max_brightness'],
                   no_sysfs_panel_read_store=True,
                   reason='panel_reg_read SHOW returns last cached diagnostic; STORE issues new DSI commands'),
        optional_for_brightness=dict(nits_calibration='not required for raw level operation; no measured-nits claim',
            external_te='only needed for scheduling coexistence/120 qualification, not proof of DBV',
            phy_pll_diagnostics=['PHY0/1+0x140 refgen/PHY/PLL ready','PLL0/1+0x1b0 CORE_READY; only if already safely mapped']))
    result=dict(reference=str(source),sha256=sha(source),exact_macros=checked,
                interrupt_enable_mask=hex(mask),interrupt_enable_fields=[dict(macro=n,value=hex(v),line=l) for n,v,l in irq],
                capture=minimum,all_predicates_derivable_from_dsi_registers=False,
                non_register_blockers=['physical resource lifetime and safe initial register access',
                    'software producer/ISR closure', 'panel readback support or independently qualified write-only verification policy'],
                no_device_access=True)
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print('PASS',len(checked),'exact Sony predicate macros; complete IRQ mask',hex(mask),'read-only capture list emitted')
if __name__=='__main__':main()
