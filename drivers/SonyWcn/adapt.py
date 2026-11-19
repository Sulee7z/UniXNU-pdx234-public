"""Guarded, reproducible board deltas over the pinned official adapters.

Copies are generated in an isolated build tree. Never edit the reference repos.
"""
from __future__ import annotations


def once(text: str, before: str, after: str) -> str:
    if text.count(before) != 1:
        raise ValueError("official adapter anchor changed: " + before[:120])
    return text.replace(before, after)


def wifi(text: str) -> str:
    # Discard the source board's descriptive preamble together with its power
    # assumptions. Preserve original executable code through checked deltas.
    text='''// SPDX-License-Identifier: BSD-2-Clause-Patent
// Sony XQ-DQ72 WCN7850: pinned official core/OS adapter with Sony FDT inputs.
// Shared rails/GCC/ITS/SMMU remain under the installed platform provider.
''' + text[text.index('#include <IOKit/IOLib.h>'):]
    text = once(text, '#include "QcomRpmh.h"\n', '')
    text = once(text, '#include "WifiPcieTables.h"', '#include "WifiPcieTables.h"\n#include "Sm8550GeniUart.h"')
    text = once(text, '#include "WcnPower.h"', '#include "SonyWcnPower.h"\n#include "SonyWcnPlatform.h"\n#include "SonyWcnBoard.h"')
    # The official adapter embeds sheng-only rail voltages, unarbitrated TCS0,
    # PMIC scans and charging/RTC code. None belongs in Sony's radio owner.
    begin = text.index('// ---- PMIC state through the SPMI arbiter')
    end = text.index('// The MEM window of pcie@1c00000:', begin)
    text = text[:begin] + '// Shared power is supplied by SonyWcnPlatform, not a private TCS writer.\n' + text[end:]
    end = text.index('// ---- The charger PMIC\'s own registers')
    text = text[:end]
    text = text.replace('sheng_wcn_power_get(SHENG_WCN_WLAN)', 'sony_wcn_power_get(SONY_WCN_WLAN)')
    text = once(text, '    if (gPmic.obs.va) {pmicSurvey(true); pmicFind1800(gPmic, native_wifi_ldo + 12);}\n', '')
    text = once(text, '    if (&native_ufs_extra_va == nullptr || !native_ufs_extra_va || !native_ufs_extra_bytes) return false;',
                '''    if (&native_ufs_extra_va == nullptr || !native_ufs_extra_va ||
        &native_ufs_extra_stream == nullptr || native_ufs_extra_stream != 0x1401 ||
        &native_ufs_extra_bytes == nullptr || native_ufs_extra_bytes < 32u*1024*1024 ||
        &native_ufs_extra_iova == nullptr || !native_ufs_extra_iova ||
        native_ufs_extra_bytes > UINT32_MAX-native_ufs_extra_iova) return false;''')
    first = text.index('    p[kPowerDownControl / 4] |= 3u;')
    end = text.index('    g[kPipeMux / 4] &= ~3u;', first)
    text = text[:first] + '''    // Exact Sony downstream PHY sequence, including Sony's different SerDes values.
    for (const auto &write : kSonyPciePhy) {
        p[write.offset / 4] = write.value;
        __asm__ volatile("dsb sy" ::: "memory");
        if(write.delay_us)IODelay(write.delay_us);
    }
''' + text[end:]
    # Sony WLAN active pin: 16mA, bias-up; PERST: 2mA, bias-down.
    text = text.replace('1u | 3u << 6 | 1u << 9, 1', '3u | 7u << 6 | 1u << 9, 1')
    text = text.replace('1u | 3u << 6 | 1u << 9, 0', '1u | 1u << 9, 0')
    # All shared GCC vote/collapse/reset words use the same SoC lock as other
    # engines. Only PCIe0-exclusive RCG/PHY/DBI words remain direct MMIO.
    text = once(text, '    g[kCollapse / 4] &= ~(1u << 0 | 1u << 3);',
                '    const int collapseError=sony_wcn_gcc_update(kCollapse,1u<<0|1u<<3,0);if(collapseError){native_wifi_stats[0]=(uint32_t)-collapseError;return;}')
    text = once(text, '    g[kVote8 / 4] |= kVote8Bits;\n    g[kVote0 / 4] |= kVote0Bits;',
                '    int voteError=sony_wcn_gcc_update(kVote8,0,kVote8Bits);if(!voteError)voteError=sony_wcn_gcc_update(kVote0,0,kVote0Bits);\n'
                '    if(voteError){native_wifi_stats[0]=(uint32_t)-voteError;return;}')
    # reset bit updates are exclusive to this controller but their serialization
    # shares the SoC provider as well. Failure must stop before touching PARF.
    text = once(text, '''void pulseReset(volatile uint32_t *gcc, uint32_t bcr) {
    gcc[bcr / 4] |= 1u;
    IODelay(1000);
    gcc[bcr / 4] &= ~1u;
    IODelay(1000);
}''', '''int pulseReset(volatile uint32_t *, uint32_t bcr) {
    int e=sony_wcn_gcc_update(bcr,0,1u);if(e)return e;
    IODelay(1000);
    e=sony_wcn_gcc_update(bcr,1u,0);if(e)return e;
    IODelay(1000);return 0;
}''')
    text = once(text, '    pulseReset(g, kPcieBcr);\n    pulseReset(g, kPhyBcr);',
                '    int resetError=pulseReset(g,kPcieBcr);if(!resetError)resetError=pulseReset(g,kPhyBcr);\n'
                '    if(resetError){native_wifi_stats[0]=(uint32_t)-resetError;return;}')
    text = once(text, '        if ((config.va[0] & 0xffff) == 0x17cb) endpointProbe(a, config.va, d);',
                '        unsigned requested=0;PE_parse_boot_argn("wifi",&requested,sizeof(requested));\n'
                '        if (config.va[0] == 0x110717cb && (config.va[8/4]&255)==1) {if(requested>=4)endpointProbe(a, config.va, d);}\n'
                '        else native_wifi_stats[0]=(uint32_t)-ENODEV;')
    text=once(text,'    if (!(mask & ~0xfu) || !size || size > kMemSize) return;',
              '    if (!(mask & ~0xfu) || size!=0x200000 || size > kMemSize) {ep[0]=(uint32_t)-ENODEV;return;}')
    # Do not run the retired experimental MHI path at wifi=3/4.
    first = text.index('    const uint32_t bhi = m[0x28 / 4];', text.index('void endpointProbe('))
    end = text.index('    release(bar);', first)
    text = text[:first] + '    // wifi=4 only maps/inspects the endpoint. Production MHI starts at wifi=5.\n' + text[end:]
    text = once(text, '    const int r = nw_wifi_start(&plat, &board);',
                '    if(control){st[0]=(uint32_t)-control;return;}\n'
                '    const int irq=msiAttach();if(irq){st[0]=(uint32_t)-irq;return;}\n'
                '    const int r = nw_wifi_start(&plat, &board);\n'
                '    if(r){st[0]=(uint32_t)r;nw_wifi_stop();return;}')
    # BAR mappings and the power vote stay pinned while the endpoint may DMA.
    # Failed startup records the real failure and returns, never a fake run loop.
    text = once(text, 'int pMsiTarget(uint32_t *lo, uint32_t *hi, uint32_t *data) {*lo = (uint32_t)gArena.iova; *hi = (uint32_t)(gArena.iova >> 32); *data = 0; return 0;}',
                'int pMsiTarget(uint32_t *lo, uint32_t *hi, uint32_t *data) {return sony_wcn_wifi_msi_target(lo,hi,data);}')
    begin=text.index('constexpr uint32_t kMsiAddrLo =')
    end=text.index('// Sleeps until an MSI,',begin)
    text=text[:begin]+'''volatile uint32_t gMsiCount, gMsiBits, gMsiWake;
void msiDeliver(void *,uint32_t vectors) {
    __atomic_add_fetch(&gMsiCount,1u,__ATOMIC_RELAXED);
    __atomic_fetch_or(&gMsiBits,vectors,__ATOMIC_RELAXED);
    __atomic_fetch_or(&gMsiPending,vectors,__ATOMIC_RELEASE);
    __atomic_store_n(&gMsiWake,1u,__ATOMIC_RELEASE);
    thread_wakeup(event_t(&gMsiWake));
}
int msiAttach() {
    if(gMsiAttached)return 0;
    const int result=sony_wcn_wifi_msi_attach(msiDeliver,nullptr);
    gMsiAttached=!result;return result;
}
''' + text[end:]
    text=text.replace('MSI line attached (SPI 141), sleeping between interrupts','Sony ITS route attached, sleeping between interrupts')
    first=text.index('// ---- the endpoint\'s MSIs as a real interrupt ----')
    last=text.index('volatile uint32_t gMsiCount, gMsiBits, gMsiWake;',first)
    text=text[:first]+'// Sony PCIe0 uses the GIC ITS provider resolved by live.dtb msi-map.\n'+text[last:]
    text = once(text, '    unsigned stage = 0;\n    if (!PE_parse_boot_argn("wifi", &stage, sizeof stage) || stage < 1 || native_wifi_stats[0]) return;',
                '''    unsigned stage = 0;
    static uint32_t started;
    if (!PE_parse_boot_argn("wifi", &stage, sizeof stage) || stage < 1) return;
    if(stage!=1 && stage!=2 && stage!=4 && stage!=5){native_wifi_stats[0]=(uint32_t)-EINVAL;return;}
    // Fail before any power/reset/MMIO/thread when prerequisites are missing.
    int ready=stage>=2?sony_wcn_platform_ready():0;
    if(!ready && stage>=5)ready=sony_wcn_platform_wifi_ready();
    if(!ready && stage>=5)ready=sony_wcn_wifi_inputs_ready();
    if(!ready && stage>=5 && (&native_ufs_extra_va==nullptr || !native_ufs_extra_va ||
        &native_ufs_extra_stream==nullptr || native_ufs_extra_stream!=0x1401 ||
        &native_ufs_extra_bytes==nullptr || native_ufs_extra_bytes<32u*1024*1024))ready=ENXIO;
    if(ready){native_wifi_stats[0]=(uint32_t)-ready;return;}
    uint32_t expected=0;
    if(!__atomic_compare_exchange_n(&started,&expected,1u,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return;''')
    text = once(text, '    else native_wifi_stats[0] = -7;', '    else {native_wifi_stats[0] = (uint32_t)-ENOMEM;__atomic_store_n(&started,0u,__ATOMIC_RELEASE);}')
    text = text.replace('void sheng_wifi_probe(void)', 'void native_sony_wifi_start(void)')
    text = text.replace('// WiFi bring-up on the sheng board.', '// Sony WCN7850 adapter generated from the pinned official WifiProbe.')
    return text


def bluetooth(text: str) -> str:
    text = once(text, '#include "WcnPower.h"', '#include "SonyWcnPower.h"\n#include "SonyWcnPlatform.h"\n#include "SonyWcnBoard.h"')
    text = text.replace('sheng_wcn_power_get(SHENG_WCN_BLUETOOTH)', 'sony_wcn_power_get(SONY_WCN_BLUETOOTH)')
    text = text.replace('sheng_wcn_power_put(SHENG_WCN_BLUETOOTH)', 'sony_wcn_power_put(SONY_WCN_BLUETOOTH)')
    text = text.replace('sheng_wcn_power_owners()', 'sony_wcn_power_owners()')
    text = once(text, 'constexpr uint32_t kBtEnableCfg=(7u<<6)|(1u<<9); // bt-en-pins: 16 mA, no bias, output',
                'constexpr uint32_t kBtEnableCfg=1u|(1u<<9); // Sony bt_en_sleep: 2mA, bias down')
    text = once(text, '    for(unsigned gpio=76;gpio<=79;gpio++)pin(gpio,gpio>=78?3u:1u);',
                '    for(unsigned i=0;i<4;i++)pin(76+i,kSonyUartDefault[i]);')
    text = once(text, '    for(unsigned gpio=76;gpio<=79;gpio++)pin(gpio,(1u<<2)|(gpio>=78?3u:1u));',
                '    for(unsigned i=0;i<4;i++)pin(76+i,kSonyUartActive[i]);')
    text=once(text,'    pin(kSwCtrl,1u);pin(kBtEnable,kBtEnableCfg,0);IOSleep(100);',
              '    // Sony DT names SW_CTRL82 but does not qualify a new pull/mux. Preserve its owner.\n'
              '    pin(kBtEnable,kBtEnableCfg,0);IOSleep(100);')
    text = once(text, 'pin(kRx,3u|(1u<<2));', 'pin(kRx,kSonyUartActive[3]);')
    text = once(text, 'r[3]=0;pin(kRx,3u);', 'r[3]=0;pin(kRx,kSonyUartDefault[3]);')
    begin=text.index('bool serialClock(bool enabled) {')
    end=text.index('size_t rxBytes(',begin)
    text=text[:begin]+'''int serialClock(bool enabled) {
    const int e=sony_wcn_uart14_clock_vote(enabled);if(e)return -e;
    if(!enabled){bt.clocked=false;return 0;}
    for(unsigned i=0;i<1000;i++){if(!(grd(nullptr,0x1e754)&(1u<<31))){bt.clocked=true;return 0;}IODelay(1);}
    return -ETIMEDOUT;
}
''' + text[end:]
    text=once(text,'        if(!serialClock(true))return -EIO;','        const int clock=serialClock(true);if(clock)return clock;')
    text=once(text,'    if(!serialClock(false)){bt.gated=false;disarmRxWake();qbt_geni_resume(&bt.geni);return -EIO;}',
              '    const int clock=serialClock(false);if(clock){bt.gated=false;disarmRxWake();qbt_geni_resume(&bt.geni);return clock;}')
    text=once(text,'    if(!sm8550_gcc_update32(bt.gcc.va+0x52018/4,0,1u))return -EIO;',
              '    e=sony_wcn_gcc_update(0x52018,0,1u);if(e)return -e;')
    text=once(text,'    if(!(grd(nullptr,0)&(1u<<31)) || !serialClock(true))return -EIO;',
              '    if(!(grd(nullptr,0)&(1u<<31)))return -ETIMEDOUT;\n    e=serialClock(true);if(e)return e;')
    # Old Sony touch has its own config lock. Merely importing the newer SoC
    # lock would not serialize with it. Require the real platform DMA owner.
    begin=text.index('    AppsSmmuLock guard;if(!guard.ready())return -ENOMEM;')
    end=text.index('    if(error) {',begin)
    text=text[:begin]+'''    const int dmaError=sony_wcn_bluetooth_dma_prepare(pa,kDmaBytes,&bt.domain.slot,&bt.domain.bank);
    const char *error=dmaError?"shared Sony QUP2 DMA provider rejected range":nullptr;
''' + text[end:]
    text=once(text,'        return -EIO;\n    }\n    bt.dma_address=pa;',
              '        return -dmaError;\n    }\n    bt.dma_address=pa;')
    text = once(text, '    if(bt.powered)return 0;',
                '    if(bt.powered){struct qbt_info info;qbt_get_info(bt.core,&info);return info.state==2?0:-EBUSY;}')
    text = once(text, '    if(!retired)bt.gated=serialClock(false);',
                '''    if(retired)return e; // keep clocks, DMA and shared vote pinned after an unquiesced engine
    const int clock=serialClock(false);if(clock)return e?e:clock;
    bt.gated=true;''')
    text = once(text, '    int released=sony_wcn_power_put(SONY_WCN_BLUETOOTH);if(!e)e=-released;',
                '''    int released=sony_wcn_power_put(SONY_WCN_BLUETOOTH);if(!e)e=-released;
    if(released)bt.powered=true; // a failed release retains the ownership for retry''')
    text = once(text, '    bt.core=qbt_create(&ops);if(!bt.core){native_bluetooth_stats[0]=3;return;}',
                '    bt.core=qbt_create(&ops);if(!bt.core){native_bluetooth_stats[0]=3;native_bluetooth_stats[1]=(uint64_t)(int64_t)-ENOMEM;return;}')
    text = once(text, '    int e=qbt_transport_init(&transport);if(e){native_bluetooth_stats[0]=3;return;}',
                '    int e=qbt_transport_init(&transport);if(e){native_bluetooth_stats[0]=3;native_bluetooth_stats[1]=(uint64_t)(int64_t)e;qbt_destroy(bt.core);bt.core=nullptr;return;}')
    text = once(text, 'if(n && qbt_transmit(bt.core,tx,n))e=-EIO;',
                'if(n){const int sent=qbt_transmit(bt.core,tx,n);if(sent){e=sent;qbt_fail(bt.core,sent);}}')
    text = once(text, '    if(!PE_parse_boot_argn("bluetooth",&enabled,sizeof(enabled)) || !enabled)return;',
                '''    if(!PE_parse_boot_argn("bluetooth",&enabled,sizeof(enabled)) || !enabled)return;
    int ready=enabled==1?sony_wcn_platform_ready():EINVAL;
    if(!ready)ready=sony_wcn_platform_bluetooth_ready();
    if(!ready)ready=sony_wcn_bluetooth_inputs_ready();
    if(ready){native_bluetooth_stats[0]=3;native_bluetooth_stats[1]=(uint64_t)(int64_t)-ready;return;}''')
    text = text.replace('void sheng_bluetooth_probe(void)', 'void native_sony_bluetooth_start(void)')
    text = once(text, '    else native_bluetooth_stats[0]=3;',
                '    else {native_bluetooth_stats[0]=3;native_bluetooth_stats[1]=(uint64_t)(int64_t)-ENOMEM;__atomic_store_n(&bt.started,0u,__ATOMIC_RELEASE);}')
    text += '\nextern "C" int native_sony_bluetooth_publish(void){return address()?0:ENOENT;}\n'
    return text
