"""Sony PDX070 follow-up: preserve negative gates and publish their operands."""
from platform069.recovery070 import PATCH_NAME, adapt_exec, adapt_boot_log as bootlog070, once


def picker(text):
    # IDR0.EXIDS advertises capability. CR0.EXIDENABLE selects the active
    # format. Continue to reject active extended format and keep USFCFG.
    text = once(text, ' || (id0 & (1u << 8))', '')
    return once(text, 'if ((scr0 & 1) || !(scr0 & (1u << 10)))',
                'if (scr0 == UINT32_MAX || (scr0 & ((1u << 3) | 1u)) || !(scr0 & (1u << 10)))')


def dma(text):
    text = once(text, 'volatile uint32_t sony069_wifi_dma_atos[8];',
                'volatile uint32_t sony069_wifi_dma_atos[8], sony071_wifi_dma_probe[8];')
    text = once(text, '    e=sm8550_apps_smmu_pick(&io,&sid,1,&domain);', '''    sony071_wifi_dma_probe[1]=rd(nullptr,0x20);
    sony071_wifi_dma_probe[2]=rd(nullptr,0x24);
    sony071_wifi_dma_probe[3]=rd(nullptr,0x28);
    sony071_wifi_dma_probe[4]=rd(nullptr,0);
    sony071_wifi_dma_probe[0]=1;
    e=sm8550_apps_smmu_pick(&io,&sid,1,&domain);''')
    text = once(text, '    // The picker requires 4KiB register pages.', '''    sony071_wifi_dma_probe[5]=domain.bank;
    sony071_wifi_dma_probe[0]=2;
    // The picker requires 4KiB register pages.''')
    text = once(text, 'cb>SONY_APPS_SMMU_REG_BYTES-0x7f8 || rd(nullptr,cb+4)){',
                'cb>SONY_APPS_SMMU_REG_BYTES-0x7f8 || (sony071_wifi_dma_probe[6]=rd(nullptr,cb+4))){')
    for step, anchor in enumerate(('    const IOOptionBits flags=', '    unsigned widths[]=',
        '    if(ArmSmmu4KEncodeContext(', '    uint32_t irq_state=',
        '    poisoned=true;\n    ArmSmmu4KStatus status=', '    e=sm8550_apps_smmu_route(',
        '    sony069_wifi_dma_va=cpu;'), 3):
        text = once(text, anchor, f'    sony071_wifi_dma_probe[0]={step};\n' + anchor)
    return text


def display_resources(text):
    text = once(text, 'static const uint32_t gdsc_cfg_regs[]=', '''/* Last attempted resource operation plus raw GDSC config values. */
#ifdef __cplusplus
extern "C" {
#endif
volatile uint32_t sony071_display_resource_probe[4];
#ifdef __cplusplus
}
#endif
static const uint32_t gdsc_cfg_regs[]=''')
    # Preserve the actual source-defined two-domain check. The Sony DT gives
    # 1500 us for each domain. Never turn on an unowned domain or touch DSI
    # registers when the readiness check fails.
    text = once(text, '''        r->gdsc_cfg[i]=readr(r,D69Dispcc,gdsc_cfg_regs[i]);
        if(r->gdsc_cfg[i]==UINT32_MAX||!(r->gdsc_cfg[i]&(1u<<16))){error=D69Resource;break;}''', '''        sony071_display_resource_probe[0]=D69Dispcc;
        sony071_display_resource_probe[1]=gdsc_cfg_regs[i];
        const uint64_t deadline=r->io.now_us(r->io.context)+1500;
        for(;;){
            r->gdsc_cfg[i]=readr(r,D69Dispcc,gdsc_cfg_regs[i]);
            sony071_display_resource_probe[2+i]=r->gdsc_cfg[i];
            if(r->gdsc_cfg[i]!=UINT32_MAX && (r->gdsc_cfg[i]&(1u<<16)))break;
            if(r->gdsc_cfg[i]==UINT32_MAX || r->io.now_us(r->io.context)>=deadline){error=D69Resource;break;}
            r->io.delay_us(r->io.context,1);
        }
        if(error)break;''')
    return once(text, '    *old=readr(r,region,reg);', '''    sony071_display_resource_probe[0]=region;
    sony071_display_resource_probe[1]=reg;
    *old=readr(r,region,reg);''')


def adapt_boot_log(text):
    text = bootlog070(text)
    return once(text, '    if (diag == 1 || log_crash_evidence_on) text = diag_msg_lines', '''    if (log_crash_evidence_on) {
      extern volatile uint32_t sony071_wifi_dma_probe[8] __attribute__((weak_import));
      extern volatile uint32_t sony071_display_resource_probe[4] __attribute__((weak_import));
      extern volatile uint32_t native_bluetooth_discovery[18] __attribute__((weak_import));
      char row[256];
      if (&sony071_wifi_dma_probe) {
        const volatile uint32_t *s=sony071_wifi_dma_probe;
        snprintf(row,sizeof row,"[sony071-wifi-dma] phase=%u id=%08x/%08x/%08x cr0=%08x bank=%u actlr=%08x",
            s[0],s[1],s[2],s[3],s[4],s[5],s[6]);
        text=put((char *)boot_log_buffer,text,LogSlotBlocks*LogBlock,row,sizeof row);
      }
      if (&sony071_display_resource_probe) {
        const volatile uint32_t *s=sony071_display_resource_probe;
        snprintf(row,sizeof row,"[sony071-display-resource] region=%u reg=%x cfg=%08x/%08x",s[0],s[1],s[2],s[3]);
        text=put((char *)boot_log_buffer,text,LogSlotBlocks*LogBlock,row,sizeof row);
      }
      if (&native_bluetooth_discovery) {
        const volatile uint32_t *d=native_bluetooth_discovery;
        snprintf(row,sizeof row,"[sony071-bt-scan] tx/reply/status inquiry=%u/%u/%u legacy-param=%u/%u/%u legacy-enable=%u/%u/%u ext-param=%u/%u/%u ext-enable=%u/%u/%u reports=%u/%u/%u",
            d[0],d[1],d[2],d[3],d[4],d[5],d[6],d[7],d[8],d[9],d[10],d[11],d[12],d[13],d[14],d[15],d[16],d[17]);
        text=put((char *)boot_log_buffer,text,LogSlotBlocks*LogBlock,row,sizeof row);
      }
    }
    if (diag == 1 || log_crash_evidence_on) text = diag_msg_lines''')


ADAPTERS = {PATCH_NAME: adapt_exec, 'crashes069-persistent-lines': adapt_boot_log}
