extern "C" int native_sony_wifi_publish(void);
// SPDX-License-Identifier: BSD-2-Clause-Patent
// Sony XQ-DQ72 WCN7850: pinned official core/OS adapter with Sony FDT inputs.
// Shared rails/GCC/ITS/SMMU remain under the installed platform provider.
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IODeviceMemory.h>
#include <kern/thread.h>
#include <kern/cpu_data.h>
#include <pexpert/pexpert.h>
#include "WifiPcieTables.h"
#include "Sm8550GeniUart.h"
#include <string.h>
#include "BootResetCore.h"
#include "MhiBoot.h"
#include "nw_abi.h"
#include "WifiFirmware.h"
#include "SonyWcnPower.h"
#include "SonyWcnPlatform.h"
#include "SonyWcnBoard.h"
#include "SonyBoard2.h"
extern "C" int sony069_wifi_dma_prepare(void);
extern "C" bool sony069_wifi_dma_faulted(void);
#include "nw_control_endpoint.h"
#include <IOKit/IOLocks.h>
#include <sys/kern_control.h>
#include <sys/kern_control_private.h>
#include <sys/kpi_mbuf.h>
#include <sys/errno.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <libkern/c++/OSData.h>
#include <libkern/OSKextLib.h>
#include <mach/kmod.h>
#include <stdarg.h>
#include <kern/task.h>
#include <stdint.h>

extern "C" void native_wifi_logf(int level, const char *fmt, ...);

// [0] stage (1 mapped, 2 clocks read, 3 controller read; negative: the step that failed), [1] vote 0x52008, [2] vote 0x52000,
// [3] GDSC, [4] halt bits (bit i set: branch i of kBranches is off), [5] GPIO 80 | 82 << 8 | 94 << 16 (bit 0 input level, bit 1 output),
// [6] PARF LTSSM, [7] root port vendor/device, [8] link control/status, [9] PARF PHY control.
// Stage 2 steps in [0]: 10 WLAN_EN high, 11 GDSCs on, 12 clocks on, 13 PARF set up, 14 PHY ready and root port set up, 15 PERST# released, 16 link up,
// 17 endpoint ID read. [10] GPIO word after WLAN_EN, [11] GDSC bits (bit 0 PCIe0, bit 1 PHY) | halt bits << 8, [12] PCS_STATUS1 |
// PHY poll count << 16, [13] port debug 0 (LTSSM state in bits 0-5), [14] port debug 1, [15] endpoint vendor/device, [16] link ms
extern "C" int armcpu_spi_attach(uint32_t, bool, void (*)(void *), void *, uint32_t *, uint64_t *) __attribute__((weak_import));
extern "C" volatile uint32_t sony069_wifi_dma_stream __attribute__((weak_import));
extern "C" uint8_t *sony069_wifi_dma_va __attribute__((weak_import));
extern "C" volatile uint32_t sony069_wifi_dma_uncached __attribute__((weak_import));
extern "C" int sony069_wifi_dma_fault(uint32_t *) __attribute__((weak_import));
extern "C" volatile uint32_t sony069_wifi_dma_atos[8] __attribute__((weak_import));
extern "C" volatile uint32_t sony069_wifi_dma_iova __attribute__((weak_import)), sony069_wifi_dma_bytes __attribute__((weak_import));
extern "C" {volatile uint32_t native_wifi_stats[29]; volatile uint32_t native_wifi_dump[6 * 18];
// PMIC state read through the SPMI arbiter, which does not depend on RPMh answering. [0] arbiter version, [1] APIDs, [2] regulators found before | after << 16,
// [3] PMK8550 gpio3 (the sleep clock pin) APID | owner << 16 (0xffff: none), [4..6] its registers 04 05 40 41 | 42 43 44 45 | 46 4a before, [7..9] after,
// [10] result of the sleep clock write (0 written, 0xff not needed, other: the step that failed), [11..16] command database addresses of the six rails
// (0 when not found), [17] pipe clock branch halt register after the PHY is ready, [18] PERST# pin config | io << 16 after its release, [19] port debug 0 20 ms after
// the LTSSM enable, [20] pipe source mux register at the end, [21] port debug 1 at 20 ms. Regulator tables follow: 112 entries of two words, first word PPID << 16 | type << 8 | subtype, second
// 0x08 << 24 | 0x46 << 16 | 0x40 << 8 | 0x41; before at [24], after at [248].
volatile uint32_t native_wifi_pmic[24 + 2 * 2 * 112];
// The endpoint after the link is up (stage 4): [0] stage reached, [1] BAR0 sizing mask, [2] BAR0 as assigned, [3] command register read back, [4] root port memory
// window register, [5..11] MHI MHIREGLEN MHIVER MHICFG BHIOFF BHIEOFF MHICTRL MHISTATUS, [12] BHI version major | minor << 16, [13] BHI execution environment,
// [14] BHI status, [15] BHI error code.
volatile uint32_t native_wifi_ep[16];
volatile uint32_t native_wifi_pon[12];
volatile uint32_t native_wifi_cfg[32];
volatile uint32_t native_wifi_chip[16];
volatile uint32_t native_wifi_ev[48];
volatile uint32_t native_wifi_ldo[24];
// The firmware download (stage 5): [0] step (1 Data firmware found, 2 amss.bin read, 3 DMA buffers, 4 SMMU stream mapped, 5 MHI opened and SBL started,
// 6 contexts programmed, 7 mission mode), negative: the step that failed; [1] SMMU slot | bank << 16 (or the planner's error index); [2] partition LUN | first block << 8;
// [3] amss.bin size; [4] segments; [5] MhiBoot phase | error << 8 | failed phase << 16; [6] execution environment; [7] MHI state; [8] BHI status; [9] BHI error code;
// [10..12] BHI debug words; [13] MHI status register; [14] ms spent; [15] BHIe status.
volatile uint32_t native_wifi_mhi[16];
// Milliseconds since the download started when: [0] the buffers were ready, [1] Data firmware was found, [2] the image was read, [3] the SMMU stream was mapped,
// [4] the boot loader was started, [5] the contexts were programmed, [6] the run ended.
volatile uint32_t native_wifi_mhi_ms[8];
// The WiFi module's messages: a ring of 512 lines, newest at native_wifi_text_n - 1.
char native_wifi_text[512][112]; volatile uint32_t native_wifi_text_n;
// The same messages of level 6 and below (notices, warnings, errors) in a ring of their own, which the driver's debug lines do not push out.
char native_wifi_note[128][112]; volatile uint32_t native_wifi_note_n;}

extern kmod_info_t g_kernel_kmod_info;
extern "C" void native_wifi_net_static_init(void) __asm__("__GLOBAL__sub_I_WifiNet.cpp");
extern "C" void sheng_wifi_net_start(const uint8_t mac[6]);
namespace {
constexpr uint64_t kGcc = 0x100000, kTlmm = 0xf100000, kParf = 0x1c00000, kDbi = 0x60000000, kPhy = 0x1c06000, kTcsrClkref = 0x1fd5000;
constexpr uint64_t kAtu = 0x60001000, kConfig = 0x60100000;
constexpr uint32_t kVote8 = 0x52008, kVote0 = 0x52000, kGdsc = 0x6b004, kPhyGdsc = 0x6c000, kCollapse = 0x52020;
// slv_axi, mstr_axi, cfg_ahb, aux, pipe, slv_q2a, cnoc_sf, aggre_noc, ddrss_sf, phy_rchng
constexpr uint32_t kBranches[] = {0x6b020, 0x6b02c, 0x6b038, 0x6b03c, 0x6b048, 0x6b01c, 0x10030, 0x1003c, 0x1004c, 0x6b054};
constexpr uint32_t kNeeded = 0xf;   // slv_axi, mstr_axi, cfg_ahb, aux
constexpr unsigned kGpios[] = {80, 82, 94};
constexpr uint32_t kParfLtssm = 0x1b0, kParfPhyCtrl = 0x40, kLinkControl = 0x80;
constexpr unsigned kWlanEn = 80, kPerst = 94, kClkReq = 95;
// gcc-sm8550.c: block resets, the pipe source mux (0 PHY, 2 TCXO) and the aux (TCXO) and rchng (GPLL0 even / 3) sources
constexpr uint32_t kPcieBcr = 0x6b000, kPhyBcr = 0x6c01c, kPipeMux = 0x6b070, kAuxRcg = 0x6b074, kRchngRcg = 0x6b058;
constexpr uint32_t kVote8Bits = 0x7f, kVote0Bits = 1u << 12 | 1u << 19 | 1u << 22;
// pcie-qcom.c
constexpr uint32_t kParfSysCtrl = 0x0, kParfPmCtrl = 0x20, kParfDbiBase = 0x350, kParfDbiBaseHi = 0x354, kParfMhiClockReset = 0x174;
constexpr uint32_t kParfAxiHalt = 0x1a8, kParfAtuBase = 0x634, kParfAtuBaseHi = 0x638, kParfDeviceType = 0x1000;
constexpr uint32_t kParfSlvSpace = 0x358, kParfSlvSpaceHi = 0x35c, kSlvSpaceBytes = 0x80000000;
// pcie-designware.h
constexpr uint32_t kPortDebug0 = 0x728, kPortDebug1 = 0x72c, kBusNumbers = 0x18, kCommand = 0x4;

struct Window {IOMemoryMap *map; volatile uint32_t *va;};
bool mapWindow(Window &w, uint64_t base, uint64_t size, IOOptionBits cache = kIOMapInhibitCache) {
    IODeviceMemory *memory = IODeviceMemory::withRange(base, size);
    w.map = memory ? memory->map(kIOMapAnywhere | cache) : nullptr;
    if (memory) memory->release();
    w.va = w.map ? reinterpret_cast<volatile uint32_t *>(w.map->getVirtualAddress()) : nullptr;
    return w.va != nullptr;
}
void release(Window &w) {if (w.map) w.map->release(); w = {};}

// TLMM pin config: pull in bits 0-1 (1 down, 3 up), function in 2-5, drive (mA / 2 - 1) in 6-8, output enable bit 9; io bit 1 drives
void setPin(volatile uint32_t *tlmm, unsigned pin, uint32_t config, int level) {
    if (level >= 0) tlmm[(pin * 0x1000 + 4) / 4] = level ? 2u : 0u;
    tlmm[pin * 0x1000 / 4] = config;
    if (level >= 0) tlmm[(pin * 0x1000 + 4) / 4] = level ? 2u : 0u;
}

uint32_t pinWord(volatile uint32_t *tlmm) {
    uint32_t gpios = 0;
    for (unsigned i = 0; i < 3; ++i) gpios |= (tlmm[(kGpios[i] * 0x1000 + 4) / 4] & 3u) << (8 * i);
    return gpios;
}

bool waitClear(volatile uint32_t *reg, uint32_t mask, unsigned tries, unsigned *used = nullptr) {
    unsigned i = 0;
    for (; i < tries && (*reg & mask); ++i) IODelay(100);
    if (used) *used = i;
    return !(*reg & mask);
}

int pulseReset(volatile uint32_t *, uint32_t bcr) {
    int e=sony_wcn_gcc_update(bcr,0,1u);if(e)return e;
    IODelay(1000);
    e=sony_wcn_gcc_update(bcr,1u,0);if(e)return e;
    IODelay(1000);return 0;
}

// Shared power is supplied by SonyWcnPlatform, not a private TCS writer.
// The MEM window of pcie@1c00000: CPU and PCI addresses are the same, 0x60300000 for 0x3d00000 bytes (sm8550.dtsi ranges).
constexpr uint64_t kMemBase = 0x60300000, kMemSize = 0x3d00000;

// ---- stage 5: the firmware into the endpoint (SMMU stream, DMA buffers, BHI secondary boot loader, MHI contexts, BHIe full image) ----
constexpr uint32_t kSegment = 128 * 1024, kSbl = 512 * 1024, kMaxSegments = 48;

// DMA memory: carved in order out of the buffer the storage driver mapped for the endpoint's stream (see NativeUfs); pa is the address the endpoint uses.
struct Dma {uint8_t *va; uint64_t pa; size_t bytes;};
uint32_t gDmaUsed;
bool dmaAlloc(Dma &b, size_t bytes) {
    if (&sony069_wifi_dma_va == nullptr || !sony069_wifi_dma_va || gDmaUsed + bytes > sony069_wifi_dma_bytes) {native_wifi_mhi[11] = 1; return false;}
    b.va = sony069_wifi_dma_va + gDmaUsed;
    b.pa = (uint64_t)sony069_wifi_dma_iova + gDmaUsed;
    b.bytes = bytes;
    gDmaUsed += (uint32_t)((bytes + 4095) & ~4095ull);
    bzero(b.va, bytes);
    return true;
}

int pFwGet(const char *path, const uint8_t **data, size_t *size);
struct Fw {const uint8_t *image; uint32_t amssSize;};
bool findFirmware(Fw &f) {
    for (unsigned i = 0; i < 240; ++i) {
        size_t size = 0;
        if (!pFwGet("amss.bin", &f.image, &size) && size <= UINT32_MAX) {
            f.amssSize = static_cast<uint32_t>(size); return size != 0;
        }
        IOSleep(500);
    }
    return false;
}

struct BarIo {volatile uint32_t *m;};
uint32_t barRead(void *ctx, uint32_t reg) {return static_cast<BarIo *>(ctx)->m[reg / 4];}
uint32_t gTraceWrites, gSkipReg;   // a register whose write is left out (the boot loader's doorbell)
uint32_t gSkipped;
   // while non-zero every register write is announced in the log and followed by a pause long enough for a log slot to be written
void barWrite(void *ctx, uint32_t reg, uint32_t value) {
    if (gTraceWrites) {
        native_wifi_mhi[14] = (gTraceWrites << 16) | (reg & 0xffff); native_wifi_mhi[13] = value;
        IOSleep(2500);
        ++gTraceWrites;
    }
    if (gSkipReg && reg == gSkipReg) {gSkipped = value | 0x80000000u; return;}
    static_cast<BarIo *>(ctx)->m[reg / 4] = value; __asm__ volatile("dsb sy" ::: "memory");
}

void put64(volatile uint32_t *regs, uint32_t lowOffset, uint64_t value) {regs[lowOffset / 4] = (uint32_t)value; regs[(lowOffset + 4) / 4] = (uint32_t)(value >> 32);}

// The device context arrays and rings (mhi_init_dev_ctxt): 128 channel contexts left disabled, two event rings (control 32 elements, data 256) and the
// primary command ring, in one buffer; then the registers that point the device at them (mhi_init_mmio).
uint8_t *gEvVa[2]; uint8_t *gCtxVa; uint8_t *gSinkVa;
void programContexts(volatile uint32_t *m, Dma &c, uint64_t mapped) {
    constexpr uint32_t kCtx = 44, kChannels = 128, kEvents = 2, kCmdEl = 8, kEl = 16;
    const uint32_t evLen[kEvents] = {32 * kEl, 256 * kEl};
    uint8_t *va = c.va;
    gCtxVa = va;
    const uint64_t pa = c.pa;
    const uint32_t chOff = 0, evOff = kChannels * kCtx, cmdOff = evOff + kEvents * kCtx;
    uint32_t ringOff = (cmdOff + kCtx + 4095) & ~4095u;
    uint32_t cur = ringOff;
    auto w32 = [&](uint32_t at, uint32_t v) {memcpy(va + at, &v, 4);};
    auto w64 = [&](uint32_t at, uint64_t v) {memcpy(va + at, &v, 8);};
    uint64_t evBase[kEvents];
    for (uint32_t i = 0; i < kEvents; ++i) {
        evBase[i] = pa + cur;
        gEvVa[i] = va + cur;
        const uint32_t at = evOff + i * kCtx;
        w32(at, i == 0 ? 0 : 1u << 16);          // interrupt moderation 0 / 1 ms
        w32(at + 4, 1);                          // MHI_ER_TYPE_VALID
        w32(at + 8, i + 1);                      // MSI vector
        w64(at + 12, evBase[i]);
        w64(at + 20, evLen[i]);
        w64(at + 28, evBase[i]);                 // read pointer
        w64(at + 36, evBase[i] + evLen[i] - kEl);   // write pointer: the whole ring is free for the device
        cur += evLen[i];
    }
    const uint64_t cmdBase = pa + cur;
    w64(cmdOff + 12, cmdBase);
    w64(cmdOff + 20, kCmdEl * kEl);
    w64(cmdOff + 28, cmdBase);
    w64(cmdOff + 36, cmdBase);
    __asm__ volatile("dsb sy" ::: "memory");
    put64(m, 0x58, pa + chOff);                  // CCABAP
    put64(m, 0x60, pa + evOff);                  // ECABAP
    put64(m, 0x68, pa + cmdOff);                 // CRCBAP
    put64(m, 0x80, 0); put64(m, 0x88, 0xffffffffull);   // control base and limit
    put64(m, 0x98, 0); put64(m, 0xa0, 0xffffffffull);   // data base and limit
    m[0x10 / 4] = (m[0x10 / 4] & ~0xff000000u & ~0x00ff0000u) | (kEvents << 16);   // MHICFG: NER = 2, NHWER = 0
    // event ring doorbells (ERDBOFF + 8 * ring): the write pointers
    const uint32_t erdb = m[0x20 / 4];
    if (erdb + 8 * kEvents <= mapped) for (uint32_t i = 0; i < kEvents; ++i) put64(m, erdb + 8 * i, evBase[i] + evLen[i] - kEl);
    __asm__ volatile("dsb sy" ::: "memory");
}

// The endpoint's and the root port's configuration view, kept for looking at the link while the boot loader runs. When the endpoint answers in
// configuration space but its BAR0 or memory enable was cleared (its PCIe core restarting), they are written back.
volatile uint32_t *gCfg, *gDbi;
uint32_t gBar0, gRestored;
void linkSnapshot(volatile uint32_t *out) {
    out[0] = gCfg[0]; out[1] = gCfg[1]; out[2] = gCfg[0x10 / 4]; out[3] = gCfg[0x14 / 4];
    out[4] = gDbi[0x80 / 4]; out[5] = gDbi[kPortDebug0 / 4]; out[6] = gDbi[0x20 / 4]; out[7] = gDbi[1];
}
void linkRecover() {
    if (gCfg[0] != 0x110717cb) return;
    if ((gCfg[0x10 / 4] & ~0xfu) != (gBar0 & ~0xfu) || (gCfg[1] & 6u) != 6u) {
        gCfg[0x10 / 4] = gBar0; gCfg[0x14 / 4] = 0;
        gCfg[1] = (gCfg[1] & 0xffffu) | 0x6u;
        __asm__ volatile("dsb sy" ::: "memory");
        ++gRestored;
    }
}

// The chip's own power-up recipe (ath12k_pci_power_up): the boot loader is only started on a chip whose power control, interrupts and warm-boot marker were
// put in order first. Chip registers above 0x80000 are seen through a window: the window register at BAR + 0x310c takes 0x40000000 | (offset & GENMASK(24, 19)),
// (the field value, offset bits 24 to 19 shifted down), the register is then at BAR + 0x80000 + (offset & 0x7ffff); the MHI block (0x1e0e100 and up) is at the start of the BAR.
uint32_t gWindow = 0xffffffffu;
uint32_t chipRead(volatile uint32_t *m, uint32_t off) {
    if (off < 0x80000) return m[off / 4];
    const uint32_t window = (off >> 19) & 0x3fu;
    if (window != gWindow) {m[0x310c / 4] = 0x40000000u | window; (void)m[0x310c / 4]; gWindow = window;}
    if (off >= 0x1e0e100u && off <= 0x1e0effcu) return m[((off - 0x1e0e100u) & 0x7ffffu) / 4];
    return m[(0x80000u + (off & 0x7ffffu)) / 4];
}
void chipWrite(volatile uint32_t *m, uint32_t off, uint32_t value) {
    if (off < 0x80000) {m[off / 4] = value; __asm__ volatile("dsb sy" ::: "memory"); return;}
    const uint32_t window = (off >> 19) & 0x3fu;
    if (window != gWindow) {m[0x310c / 4] = 0x40000000u | window; (void)m[0x310c / 4]; gWindow = window;}
    if (off >= 0x1e0e100u && off <= 0x1e0effcu) m[((off - 0x1e0e100u) & 0x7ffffu) / 4] = value;
    else m[(0x80000u + (off & 0x7ffffu)) / 4] = value;
    __asm__ volatile("dsb sy" ::: "memory");
}
// ath12k_pci_sw_reset(power on). Values seen along the way go to native_wifi_chip: [0] LTSSM word, [1] hot reset word, [2] Q6 cookie, [3] warm entry,
// [4] warm entry after clearing, [5] reset cause, [6] global reset word before, [7] after, [8] MHISTATUS before the MHI reset, [9] MHISTATUS after, [10] EE after.
void chipPowerUp(volatile uint32_t *m) {
    volatile uint32_t *c = native_wifi_chip;
    gWindow = 0xffffffffu;
    uint32_t v = chipRead(m, 0x1e081b0u);
    for (unsigned i = 0; v != 0x111u && i < 5; ++i) {
        if (v == 0xffffffffu) IOSleep(5);
        chipWrite(m, 0x1e081b0u, 0x111u);
        v = chipRead(m, 0x1e081b0u);
    }
    c[0] = v;
    v = chipRead(m, 0x1e40304u); v |= 0x10u; chipWrite(m, 0x1e40304u, v); c[1] = chipRead(m, 0x1e40304u);
    IOSleep(5);
    chipWrite(m, 0x1e08228u, 0xffffffffu);   // interrupts left over from a hot reset
    v = chipRead(m, 0x1f8031cu); v &= ~0x4u; chipWrite(m, 0x1f8031cu, v);
    chipWrite(m, 0x360, 0); chipWrite(m, 0x368, 0); chipWrite(m, 0x394, 0); chipWrite(m, 0x39c, 0);   // BHIe vector doorbells and status
    c[2] = chipRead(m, 0x1f80500u);
    c[3] = chipRead(m, 0x1f80504u);
    IOSleep(10);
    chipWrite(m, 0x1f80504u, 0);             // keeps the Q6 off the warm boot path
    IOSleep(10);
    c[4] = chipRead(m, 0x1f80504u);
    c[5] = chipRead(m, 0x1f8060cu);          // read-clear
    v = chipRead(m, 0x3008u); c[6] = v;
    chipWrite(m, 0x3008u, v | 1u); (void)chipRead(m, 0x3008u);
    IOSleep(10);
    chipWrite(m, 0x3008u, v & ~1u); (void)chipRead(m, 0x3008u);
    IOSleep(10);
    c[7] = chipRead(m, 0x3008u);
    m[0x310c / 4] = 0x40000000u | (gWindow == 0xffffffffu ? 0u : gWindow);   // the window register is cleared by the reset; put the cached window back
    (void)m[0x310c / 4];
    c[8] = m[0x48 / 4];
    m[0x38 / 4] = 2;                         // MHICTRL reset: clears a SYSERR left by the global reset
    __asm__ volatile("dsb sy" ::: "memory");
    IOSleep(10);
    c[9] = m[0x48 / 4];
    c[10] = m[(m[0x28 / 4] + 0x28) / 4];
}
// Without ASPM during the load, and MSI enabled (the endpoint raises its completions as MSI writes; they land in a sink in the DMA buffer, polled later).
void endpointLinkSetup(uint64_t sinkAddress) {
    uint8_t cap = (uint8_t)(gCfg[0x34 / 4] & 0xff);
    for (unsigned guard = 0; cap >= 0x40 && guard < 48; ++guard) {
        const uint32_t w = gCfg[cap / 4];
        const uint8_t id = (uint8_t)w, next = (uint8_t)(w >> 8);
        if (id == 0x10) {   // PCI Express: link control, ASPM bits
            const uint32_t lc = gCfg[(cap + 0x10) / 4];
            native_wifi_chip[11] = lc;
            gCfg[(cap + 0x10) / 4] = lc & ~3u;
        } else if (id == 0x05) {   // MSI: address, data, then 4 vectors and enable
            const bool is64 = (w >> 16) & 0x80;
            gCfg[(cap + 4) / 4] = (uint32_t)sinkAddress;
            if (is64) {gCfg[(cap + 8) / 4] = (uint32_t)(sinkAddress >> 32); gCfg[(cap + 0xc) / 4] = 0;}
            else gCfg[(cap + 8) / 4] = 0;
            gCfg[cap / 4] = (w & 0xffffu) | (((w >> 16) & ~0x70u) | 0x20u | 1u) << 16;
            native_wifi_chip[12] = gCfg[cap / 4];
        }
        cap = next;
    }
    __asm__ volatile("dsb sy" ::: "memory");
}


// ---- Stage 6: the WiFi module (Ath12kWifi) on this board. It does its own chip power-up, MHI boot, QRTR/QMI and driver start; the board provides
// register access, configuration space, DMA memory from the endpoint's SMMU window, Data firmware files, a clock and a log.
// The block table is allocated once, at the first start (a static table would sit in the kernel's __DATA).
constexpr unsigned kArenaBlocks = 16384;
struct Arena {uint8_t *va; uint64_t iova; size_t bytes; struct Block {uint32_t off, size; bool used;} *blocks; unsigned count; size_t used, peak; unsigned failures;} gArena;
bool arenaInit() {
    if (&sony069_wifi_dma_va == nullptr || !sony069_wifi_dma_va ||
        &sony069_wifi_dma_stream == nullptr || sony069_wifi_dma_stream != 0x1401 ||
        &sony069_wifi_dma_bytes == nullptr || sony069_wifi_dma_bytes < 32u*1024*1024 ||
        &sony069_wifi_dma_iova == nullptr || !sony069_wifi_dma_iova ||
        sony069_wifi_dma_bytes > UINT32_MAX-sony069_wifi_dma_iova) return false;
    if (!gArena.blocks) gArena.blocks = static_cast<Arena::Block *>(IOMallocData(kArenaBlocks * sizeof(Arena::Block)));
    if (!gArena.blocks) return false;
    gArena.va = sony069_wifi_dma_va; gArena.iova = sony069_wifi_dma_iova; gArena.bytes = sony069_wifi_dma_bytes;
    gArena.blocks[0] = {4096, (uint32_t)(gArena.bytes - 4096), false}; gArena.count = 1;   // the first page is the interrupt sink
    gArena.used = gArena.peak = 4096; gArena.failures = 0;
    return true;
}
// Buffers the endpoint reads or writes sit at addresses aligned to their size rounded up to a power of two, with no upper limit: the boot loader
// refuses an image address that is only page aligned, before it makes any transfer (the registers that name the address and size of a failed transfer
// stay zero), the firmware's host memory regions (several MiB) go through the same address translation, and an IOMMU-backed DMA allocator hands out
// addresses aligned that way.
void pLog(int level, const char *line);
void *arenaAlloc(size_t n, uint64_t *bus) {
    if(!n || n>gArena.bytes)return nullptr;
    n = (n + 63) & ~(size_t)63;
    if (n >= 4096) n = (n + 4095) & ~(size_t)4095;
    uint32_t align = 64;
    if (n >= 4096) {align = 4096; while (align < n) align <<= 1;}
    for (unsigned i = 0; i < gArena.count; ++i) {
        Arena::Block &b = gArena.blocks[i];
        if (b.used) continue;
        const uint32_t start = (b.off + align - 1) & ~(align - 1), pad = start - b.off;
        if (b.size < pad + n) continue;
        const bool tail = b.size > pad + n;
        if (gArena.count + (pad ? 1 : 0) + (tail ? 1 : 0) > kArenaBlocks) continue;
        const unsigned extra = (pad ? 1u : 0u) + (tail ? 1u : 0u);
        const Arena::Block whole = b;
        memmove(&gArena.blocks[i + extra], &gArena.blocks[i], (gArena.count - i) * sizeof(Arena::Block));
        gArena.count += extra;
        unsigned at = i;
        if (pad) {gArena.blocks[at] = {whole.off, pad, false}; ++at;}
        gArena.blocks[at] = {start, (uint32_t)n, true};
        if (tail) gArena.blocks[at + 1] = {start + (uint32_t)n, whole.size - pad - (uint32_t)n, false};
        uint8_t *p = gArena.va + start;
        gArena.used += n; if (gArena.used > gArena.peak) gArena.peak = gArena.used;
        bzero(p, n);
        if (bus) *bus = gArena.iova + start;
        return p;
    }
    ++gArena.failures;
    uint32_t freeTotal = 0, freeMax = 0;
    for (unsigned i = 0; i < gArena.count; ++i) if (!gArena.blocks[i].used) {freeTotal += gArena.blocks[i].size; if (gArena.blocks[i].size > freeMax) freeMax = gArena.blocks[i].size;}
    char line[96];
    snprintf(line, sizeof line, "dma window full: want %zu free %u largest %u blocks %u", n, freeTotal, freeMax, gArena.count);
    pLog(3, line);
    // used blocks by size class: up to 4 KiB, 64 KiB, 512 KiB, larger (count and KiB)
    uint32_t cnt[4] = {0, 0, 0, 0}, kib[4] = {0, 0, 0, 0}, big[4] = {0, 0, 0, 0};
    for (unsigned i = 0; i < gArena.count; ++i) if (gArena.blocks[i].used) {
        const uint32_t sz = gArena.blocks[i].size;
        const unsigned c = sz <= 4096 ? 0 : sz <= 65536 ? 1 : sz <= 524288 ? 2 : 3;
        ++cnt[c]; kib[c] += sz / 1024;
        for (unsigned k = 0; k < 4; ++k) if (sz > big[k]) {for (unsigned m = 3; m > k; --m) big[m] = big[m - 1]; big[k] = sz; break;}
    }
    snprintf(line, sizeof line, "dma used: <=4K %u/%uK <=64K %u/%uK <=512K %u/%uK more %u/%uK", cnt[0], kib[0], cnt[1], kib[1], cnt[2], kib[2], cnt[3], kib[3]);
    pLog(3, line);
    snprintf(line, sizeof line, "dma largest used: %u %u %u %u", big[0], big[1], big[2], big[3]);
    pLog(3, line);
    return nullptr;
}
void arenaFree(void *p) {
    if (!p || (uint8_t *)p < gArena.va || (uint8_t *)p >= gArena.va + gArena.bytes) return;
    const uint32_t off = (uint32_t)((uint8_t *)p - gArena.va);
    for (unsigned i = 0; i < gArena.count; ++i) {
        if (gArena.blocks[i].off != off || !gArena.blocks[i].used) continue;
        gArena.used -= gArena.blocks[i].size;
        gArena.blocks[i].used = false;
        if (i + 1 < gArena.count && !gArena.blocks[i + 1].used) {gArena.blocks[i].size += gArena.blocks[i + 1].size; memmove(&gArena.blocks[i + 1], &gArena.blocks[i + 2], (gArena.count - i - 2) * sizeof(Arena::Block)); --gArena.count;}
        if (i > 0 && !gArena.blocks[i - 1].used) {gArena.blocks[i - 1].size += gArena.blocks[i].size; memmove(&gArena.blocks[i], &gArena.blocks[i + 1], (gArena.count - i - 1) * sizeof(Arena::Block)); --gArena.count;}
        return;
    }
}

uint64_t pNowNs() {uint64_t ns = 0; absolutetime_to_nanoseconds(mach_absolute_time(), &ns); return ns;}
uint64_t pBootNs() {uint64_t ns = 0; absolutetime_to_nanoseconds(mach_continuous_time(), &ns); return ns;}
void pBusyDelayUs(unsigned int us) { IODelay(us); }
uint64_t pNow() {return pNowNs() / 1000000;}
void pSleep(unsigned ms) {IOSleep(ms);}
volatile uint32_t gMsiPending;
bool gMsiAttached;
void pPoll() {
    nw_wifi_irq_mode(gMsiAttached);
    const uint32_t pending = __atomic_exchange_n(&gMsiPending, 0u, __ATOMIC_ACQ_REL);
    if (pending) nw_wifi_irq_pending(pending);
    nw_wifi_poll();
}
// Each line carries the milliseconds since the first one; a line equal to one of the last sixteen is only counted, so that the messages the driver
// repeats every round (the seven interrupt groups it polls each millisecond, a send that waits for credits) cannot push the history out of the ring.
uint32_t gLogRepeats;
volatile uint32_t *gNwBar;   // the endpoint's registers, for the RAM dump reader
void rddmScan();
extern "C" int boot_log_export_put(uint32_t generation, uint32_t total, uint32_t offset, const void *data, uint32_t size) __attribute__((weak_import));
bool has(const char *s, const char *w) {for (; *s; ++s) {size_t k = 0; while (w[k] && s[k] == w[k]) ++k; if (!w[k]) return true;} return false;}
bool hasRddm(const char *s) {return has(s, "MHI_CB_EE_RDDM");}
void pLog(int level, const char *line) {
    // one line per channel would push the start-up messages out of the ring
    if (has(line, "chan scan list") || has(line, "mac channel [")) {++gLogRepeats; return;}
    // nor may the lines of every received buffer and interrupt (the beacon count is in [wifi-nw])
    if (level >= 7 && (has(line, "htc rx completion") || has(line, "rx ce pipe") || has(line, "ext irq:") || has(line, "event mgmt rx") ||
                       has(line, "mgmt rx event") || has(line, "chan info vdev_id") || has(line, "scan event foreign channel"))) {++gLogRepeats; return;}
    static uint64_t first;
    static uint32_t recent[16];
    uint32_t h = 2166136261u;
    for (const char *c = line; *c; ++c) h = (h ^ static_cast<uint8_t>(*c)) * 16777619u;
    h ^= static_cast<uint32_t>(level);
    for (uint32_t r : recent) if (r == h) {++gLogRepeats; return;}
    memmove(&recent[1], &recent[0], sizeof recent - sizeof recent[0]);
    recent[0] = h;
    const uint64_t now = pNow();
    if (!first) first = now;
    const uint32_t i = __atomic_fetch_add(const_cast<uint32_t *>(&native_wifi_text_n), 1u, __ATOMIC_RELAXED) % 512;
    snprintf(native_wifi_text[i], sizeof native_wifi_text[i], "%u %d %.100s", static_cast<uint32_t>(now - first), level, line);
    if (level <= 6) {
        const uint32_t j = __atomic_fetch_add(const_cast<uint32_t *>(&native_wifi_note_n), 1u, __ATOMIC_RELAXED) % 128;
        memcpy(native_wifi_note[j], native_wifi_text[i], sizeof native_wifi_note[j]);
    }
    // when the driver reports a command stuck: what the root port saw (device status, link, advanced error reporting)
    static bool rootShown;
    if (!rootShown && gDbi && has(line, "stuck: wmi credits")) {
        rootShown = true;
        char text[112];
        snprintf(text, sizeof text, "root port: devctl/sta %08x link %08x ue %08x mask %08x ce %08x rootsta %08x src %08x",
                 gDbi[0x78 / 4], gDbi[0x80 / 4], gDbi[0x104 / 4], gDbi[0x108 / 4], gDbi[0x110 / 4], gDbi[0x130 / 4], gDbi[0x134 / 4]);
        pLog(3, text);
        snprintf(text, sizeof text, "root port: aer header %08x %08x %08x %08x ltssm-debug %08x", gDbi[0x11c / 4], gDbi[0x120 / 4], gDbi[0x124 / 4], gDbi[0x128 / 4], gDbi[kPortDebug0 / 4]);
        pLog(3, text);
    }
    // the first time the device reports its RAM dump state: did its DMA fault in the SMMU (global FSR, context FSR, FAR, FSYNR0)?
    static bool faultShown;
    if (!faultShown && &sony069_wifi_dma_fault && hasRddm(line)) {
        faultShown = true;
        uint32_t f[10] = {};
        sony069_wifi_dma_fault(f);
        char text[112];
        snprintf(text, sizeof text, "smmu at rddm: gfsr %08x cb-fsr %08x far %08x%08x fsynr0 %08x sctlr %08x", f[0], f[2], f[4], f[3], f[5], f[6]);
        pLog(3, text);
        if (&sony069_wifi_dma_atos) {
            snprintf(text, sizeof text, "smmu window sweep: tested %u pages, %u faults, %u elsewhere, first bad %08x", sony069_wifi_dma_atos[0], sony069_wifi_dma_atos[1], sony069_wifi_dma_atos[2], sony069_wifi_dma_atos[3]);
            pLog(3, text);
            snprintf(text, sizeof text, "smmu window sweep: first page par %08x%08x, table pa %08x%08x", sony069_wifi_dma_atos[5], sony069_wifi_dma_atos[4], sony069_wifi_dma_atos[7], sony069_wifi_dma_atos[6]);
            pLog(3, text);
        }
        rddmScan();
    }
}

// The device uploads its RAM dump into the buffers of the receive vector table the MHI core programmed at power up. Once the transfer is complete
// the dump is searched for the messages a firmware error leaves (an assertion or fatal error text, or a source file with a line number).
bool printable(uint8_t c) {return c >= 0x20 && c < 0x7f;}
bool looksLikeError(const char *t, size_t n) {
    for (size_t i = 0; i < n; ++i) if (t[i] == '%') return false;   // a format string of the image, not a message
    for (size_t i = 0; i + 3 < n; ++i) {
        if (t[i] == '.' && t[i + 1] == 'c' && t[i + 2] == ':' && t[i + 3] >= '0' && t[i + 3] <= '9') return true;
        if (i + 5 <= n && (!memcmp(t + i, "ssert", 5) || !memcmp(t + i, "SSERT", 5) || !memcmp(t + i, "FATAL", 5))) return true;
        if (i + 8 <= n && !memcmp(t + i, "rr_fatal", 8)) return true;
    }
    return false;
}
void rddmScan() {
    volatile uint32_t *m = gNwBar;
    if (!m) return;
    const uint32_t bhie = m[0x2c / 4];
    if (bhie == 0 || bhie > 0x1000 || (bhie & 3)) return;
    uint32_t status = 0;
    unsigned waited = 0;
    for (; waited < 400; ++waited) {status = m[(bhie + 0x78) / 4]; if ((status >> 30) >= 2) break; IOSleep(10);}
    const uint64_t vec = m[(bhie + 0x60) / 4] | (uint64_t)m[(bhie + 0x64) / 4] << 32;
    const uint32_t vecBytes = m[(bhie + 0x68) / 4];
    char text[112];
    snprintf(text, sizeof text, "rddm upload: status %08x after %u ms, table %llx %u bytes", status, waited * 10, (unsigned long long)vec, vecBytes);
    pLog(3, text);
    auto toVa = [](uint64_t iova, uint64_t n) -> const uint8_t * {
        if (iova < gArena.iova || iova + n > gArena.iova + gArena.bytes) return nullptr;
        return gArena.va + (iova - gArena.iova);
    };
    const uint8_t *table = toVa(vec, vecBytes);
    if (!table || (status >> 30) != 2) return;
    unsigned found = 0;
    uint64_t scanned = 0;
    uint32_t seen[48] = {};
    for (uint32_t e = 0; e + 16 <= vecBytes && found < 40; e += 16) {
        uint64_t addr, size;
        memcpy(&addr, table + e, 8); memcpy(&size, table + e + 8, 8);
        const uint8_t *seg = toVa(addr, size);
        if (!seg) continue;
        scanned += size;
        for (uint64_t i = 0; i < size && found < 40;) {
            if (!printable(seg[i])) {++i; continue;}
            uint64_t j = i;
            while (j < size && printable(seg[j]) && j - i < 200) ++j;
            const size_t n = (size_t)(j - i);
            if (n >= 10 && looksLikeError(reinterpret_cast<const char *>(seg + i), n)) {
                uint32_t h = 2166136261u;
                for (size_t k = 0; k < n; ++k) h = (h ^ seg[i + k]) * 16777619u;
                bool dup = false;
                for (unsigned k = 0; k < found && k < 48; ++k) if (seen[k] == h) dup = true;
                if (!dup) {
                    seen[found] = h;
                    ++found;
                    char body[85];
                    const size_t len = n < 84 ? n : 84;
                    memcpy(body, seg + i, len); body[len] = 0;
                    snprintf(text, sizeof text, "rddm %u+%llx: %s", e / 16, (unsigned long long)i, body);
                    for (char *c = text; *c; ++c) if (!printable((uint8_t)*c)) *c = '?';
                    pLog(3, text);
                }
            }
            i = j;
        }
    }
    snprintf(text, sizeof text, "rddm scan: %llu bytes, %u messages", (unsigned long long)scanned, found);
    pLog(3, text);
    // Context: every text in the crash record (segment 0 up to 0x1000), and the runtime log the firmware kept before it (segment 1, 0x78000 on): the
    // first as it is, the second without format strings, 4 bytes per word of the record shown where no text is.
    struct Range {uint32_t seg; uint64_t from, to; size_t min; bool formats;};
    const Range ranges[] = {{0, 0, 0x1000, 4, true}, {0, 0xec00, 0xf400, 4, true}, {1, 0x78000, 0x80000, 12, false}};
    unsigned lines = 0;
    for (const Range &r : ranges) {
        if ((r.seg + 1) * 16 > vecBytes) continue;
        uint64_t addr, size;
        memcpy(&addr, table + r.seg * 16, 8); memcpy(&size, table + r.seg * 16 + 8, 8);
        const uint8_t *seg = toVa(addr, size);
        if (!seg) continue;
        const uint64_t to = r.to < size ? r.to : size;
        for (uint64_t i = r.from; i < to && lines < 160;) {
            if (!printable(seg[i])) {++i; continue;}
            uint64_t j = i;
            while (j < to && printable(seg[j]) && j - i < 200) ++j;
            const size_t n = (size_t)(j - i);
            bool format = false;
            for (size_t k = 0; k < n; ++k) if (seg[i + k] == '%') format = true;
            if (n >= r.min && (r.formats || !format)) {
                char body[85];
                const size_t len = n < 84 ? n : 84;
                memcpy(body, seg + i, len); body[len] = 0;
                snprintf(text, sizeof text, "rddm-ctx %u+%llx: %s", r.seg, (unsigned long long)i, body);
                pLog(3, text);
                ++lines;
            }
            i = j;
        }
    }
    // the crash record's first 0x200 bytes as words (registers and addresses sit there)
    {
        uint64_t addr, size;
        memcpy(&addr, table, 8); memcpy(&size, table + 8, 8);
        const uint8_t *seg = toVa(addr, size);
        if (seg && size >= 0x200) for (uint32_t o = 0; o < 0x200; o += 32) {
            uint32_t w[8];
            memcpy(w, seg + o, 32);
            snprintf(text, sizeof text, "rddm-rec %03x: %08x %08x %08x %08x %08x %08x %08x %08x", o, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]);
            pLog(3, text);
        }
    }
    // The whole dump goes to the boot log's export area, read back on the host: the receive vector table as table.bin and each of its buffers as
    // segNN.bin, in the container the log reader unpacks (SHEXR001 holding an M2VCACH1 file list). Its generation has the top bit set, which keeps
    // a later export from replacing it.
    if (!&boot_log_export_put) return;
    static const char root[] = "/rddm";
    uint64_t total = 8 + 4 + sizeof root - 1 + 4, files = 1;
    total += 24 + 9 + vecBytes;
    for (uint32_t e = 0; e + 16 <= vecBytes; e += 16) {
        uint64_t addr, size;
        memcpy(&addr, table + e, 8); memcpy(&size, table + e + 8, 8);
        if (toVa(addr, size)) {total += 24 + 9 + size; ++files;}
    }
    const uint64_t blobBytes = 16 + total;
    uint8_t *blob = blobBytes < (64u << 20) ? static_cast<uint8_t *>(IOMallocData(blobBytes)) : nullptr;
    if (!blob) {pLog(3, "rddm export: no memory"); return;}
    uint8_t *w = blob;
    auto put = [&w](const void *d, size_t n) {memcpy(w, d, n); w += n;};
    auto put32 = [&put](uint32_t v) {put(&v, 4);};
    auto file = [&](const char *name, const uint8_t *d, uint64_t n) {
        const uint32_t head[4] = {(uint32_t)strlen(name), 0644, 0, 0};
        put(head, 16); put(&n, 8); put(name, strlen(name)); put(d, n);
    };
    put("SHEXR001", 8); put32((uint32_t)total); put32(0);
    put("M2VCACH1", 8); put32(sizeof root - 1); put(root, sizeof root - 1); put32((uint32_t)files);
    file("table.bin", table, vecBytes);
    for (uint32_t e = 0; e + 16 <= vecBytes; e += 16) {
        uint64_t addr, size;
        memcpy(&addr, table + e, 8); memcpy(&size, table + e + 8, 8);
        const uint8_t *seg = toVa(addr, size);
        if (!seg) continue;
        char name[16];
        snprintf(name, sizeof name, "seg%02u.bin", e / 16);
        file(name, seg, size);
    }
    const uint32_t generation = 0x80000000u | (uint32_t)(pNow() & 0x7fffffff);
    const int rc = (uint64_t)(w - blob) == blobBytes ? boot_log_export_put(generation, (uint32_t)blobBytes, 0, blob, (uint32_t)blobBytes) : -100;
    IOFreeData(blob, blobBytes);
    snprintf(text, sizeof text, "rddm export: %llu bytes in %llu files, result %d", (unsigned long long)blobBytes, (unsigned long long)files, rc);
    pLog(3, text);
}
void pHalt() {for (;;) IOSleep(1000);}
void *hAlloc(size_t n) {
    uint8_t *p = static_cast<uint8_t *>(IOMallocData(n + 16));
    if (!p) return nullptr;
    *reinterpret_cast<size_t *>(p) = n + 16;
    return p + 16;
}
void hFree(void *q) {
    if (!q) return;
    uint8_t *p = static_cast<uint8_t *>(q) - 16;
    IOFreeData(p, *reinterpret_cast<size_t *>(p));
}
void *pDmaAlloc(size_t n, uint64_t *bus) {return arenaAlloc(n, bus);}
void pDmaFree(size_t, void *p, uint64_t) {arenaFree(p);}
uint64_t pDmaMap(void *p, size_t bytes, int) {
    const uintptr_t start=(uintptr_t)gArena.va, address=(uintptr_t)p;
    if (!bytes || address<start || address-start>=gArena.bytes || bytes>gArena.bytes-(address-start)) return 0;
    return gArena.iova + (address-start);
}
// PCIe0 has dma-coherent in the captured Sony FDT. Order CPU and DMA accesses
// to coherent memory, including doorbells, without cleaning unrelated lines.
void pDmaSync(uint64_t bus, size_t bytes, int) {
    if(bus>=gArena.iova && bus-gArena.iova<gArena.bytes && bytes<=gArena.bytes-(bus-gArena.iova))
        __asm__ volatile("dsb sy" ::: "memory");
}

// Data-backed firmware files, each read once and kept for the boot.
struct FwCache {char name[24]; uint8_t *data; size_t size; bool tried;} gFw[8];
// The radio's address (wlan_mac.bin): this board's firmware reports none, so a locally administered address is made from /chosen/unique-chip-id,
// the same on every boot of the same image.
// The address itself: made from /chosen/unique-chip-id (FNV-1a, locally administered, unicast), the same at every boot.
bool boardMac(uint8_t m[6]) {
    IORegistryEntry *chosen = IORegistryEntry::fromPath("/chosen", gIODTPlane);
    OSData *id = chosen ? OSDynamicCast(OSData, chosen->getProperty("unique-chip-id")) : nullptr;
    uint64_t seed = 0;
    if (id && id->getLength() >= sizeof seed) memcpy(&seed, id->getBytesNoCopy(), sizeof seed);
    OSSafeReleaseNULL(chosen);
    if (!seed) return false;
    uint64_t h = 0xcbf29ce484222325ull;
    for (unsigned i = 0; i < 8; ++i) h = (h ^ ((seed >> (8 * i)) & 0xff)) * 0x100000001b3ull;
    for (unsigned i = 0; i < 6; ++i) m[i] = (uint8_t)(h >> (8 * i));
    m[0] = (uint8_t)((m[0] & 0xfe) | 0x02);
    return true;
}
int macFile(const uint8_t **data, size_t *size) {
    static char text[40]; static size_t len;
    if (!len) {
        uint8_t m[6];
        if (!boardMac(m)) return -1;
        len = (size_t)snprintf(text, sizeof text, "address=%02x%02x%02x%02x%02x%02x\n", m[0], m[1], m[2], m[3], m[4], m[5]);
    }
    *data = (const uint8_t *)text; *size = len;
    return 0;
}
// The system's own record of the Wi-Fi address, as a boot loader leaves it in the device tree: the wireless daemon derives every network's
// private address from it (MobileGestalt WifiAddressData) and aborts a join without it.
void publishMac() {
    uint8_t m[6];
    if (!boardMac(m)) return;
    if (IORegistryEntry *chosen = IORegistryEntry::fromPath("/chosen", gIODTPlane)) {
        if (!chosen->getProperty("mac-address-wifi0")) chosen->setProperty("mac-address-wifi0", m, sizeof m);
        chosen->release();
    }
    if (IORegistryEntry *wlan = IORegistryEntry::fromPath("/arm-io/wlan", gIODTPlane)) {
        if (!wlan->getProperty("local-mac-address")) wlan->setProperty("local-mac-address", m, sizeof m);
        wlan->release();
    }
}
int pFwGet(const char *path, const uint8_t **data, size_t *size) {
    const char *base = path;
    for (const char *c = path; *c; ++c) if (*c == '/') base = c + 1;
    if (!strcmp(base, "wlan_mac.bin")) return macFile(data, size);
    if (!strcmp(base,"board-2.bin")){int e=sony069_wifi_board2(data,size);return e?-e:0;}
    char want[24]; strlcpy(want, base, sizeof want);
    uint32_t which = 1;
    PE_parse_boot_argn("wifi-fw", &which, sizeof which);
    if (!strcmp(want, "amss.bin") && which == 2) strlcpy(want, "amss2.bin", sizeof want);
    FwCache *slot = nullptr;
    for (auto &f : gFw) {if (f.tried && !strncmp(f.name, want, 24)) {slot = &f; break;} }
    if (!slot) for (auto &f : gFw) if (!f.tried) {slot = &f; strlcpy(f.name, want, sizeof f.name); f.tried = true; break;}
    if (!slot) return -1;
    if (!slot->data && slot->size == 0) {
        const int error = sony_wifi_firmware_read(want, &slot->data, &slot->size);
        if (error) return -1;
        native_wifi_logf(6, "wifi: Data firmware %s bytes %zu", want, slot->size);
    }
    if (!slot->data) return -1;
    *data = slot->data; *size = slot->size;
    return 0;
}

// Configuration space of the endpoint: 32-bit accesses through the iATU window; offsets with bit 31 set are relative to the PCI Express capability.
uint32_t gPcieCap, gMsiCap;
int findCaps() {
    uint8_t cap = (uint8_t)(gCfg[0x34 / 4] & 0xff);
    for (unsigned guard = 0; cap >= 0x40 && guard < 48; ++guard) {
        const uint32_t w = gCfg[cap / 4];
        if ((uint8_t)w == 0x10) gPcieCap = cap;
        if ((uint8_t)w == 0x05) gMsiCap = cap;
        cap = (uint8_t)(w >> 8);
    }
    return gPcieCap && gMsiCap;
}
int pCfgRead(int off, int size, uint32_t *v) {
    uint32_t o = (uint32_t)off;
    if (o & 0x80000000u) o = gPcieCap + (o & 0x7fffffffu);
    const uint32_t w = gCfg[(o & ~3u) / 4];
    *v = size == 4 ? w : size == 2 ? (w >> ((o & 2) * 8)) & 0xffff : (w >> ((o & 3) * 8)) & 0xff;
    return 0;
}
int pCfgWrite(int off, int size, uint32_t v) {
    uint32_t o = (uint32_t)off;
    if (o & 0x80000000u) o = gPcieCap + (o & 0x7fffffffu);
    if (size == 4) {gCfg[o / 4] = v; return 0;}
    const unsigned shift = (size == 2 ? (o & 2) : (o & 3)) * 8;
    const uint32_t mask = (size == 2 ? 0xffffu : 0xffu) << shift;
    gCfg[(o & ~3u) / 4] = (gCfg[(o & ~3u) / 4] & ~mask) | ((v << shift) & mask);
    return 0;
}
int pMsiTarget(uint32_t *lo, uint32_t *hi, uint32_t *data) {return sony_wcn_wifi_msi_target(lo,hi,data);}

// The network side (WifiNet.cpp): its classes are registered with the kernel's module like the other late classes, then the interface is made.
extern "C" void native_wifi_logf(int level, const char *fmt, ...) {
    char line[160]; va_list ap; va_start(ap, fmt); vsnprintf(line, sizeof line, fmt, ap); va_end(ap);
    pLog(level, line);
}
void netStart() {
    struct nw_wifi_status status; nw_wifi_status_get(&status);
#if defined(XNU_TARGET_OS_OSX) && XNU_TARGET_OS_OSX
    // macOS: WifiNet.cpp defines no classes there (en0 is ShengEthernet of the original IONetworkingFamily).
    sheng_wifi_net_start(status.mac);
#else
    void *handle = OSMetaClass::preModLoad(g_kernel_kmod_info.name);
    if (!handle) {native_wifi_logf(3, "wifi: network classes: no module handle"); return;}
    native_wifi_net_static_init();
    const OSReturn r = OSMetaClass::postModLoad(handle);
    if (r) {native_wifi_logf(3, "wifi: network classes not registered: %d", (int)r); return;}
    sheng_wifi_net_start(status.mac);
#endif
}

// Sony PCIe0 uses the GIC ITS provider resolved by live.dtb msi-map.
volatile uint32_t gMsiCount, gMsiBits, gMsiWake;
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
// Sleeps until an MSI, a frame to send (sheng_wifi_wake) or ms milliseconds pass; returns at once if one came since the last wait.
void msiWait(unsigned ms) {
    if (__atomic_exchange_n(&gMsiWake, 0u, __ATOMIC_ACQ_REL)) return;
    assert_wait_timeout(event_t(&gMsiWake), THREAD_UNINT, ms, NSEC_PER_MSEC);
    if (__atomic_exchange_n(&gMsiWake, 0u, __ATOMIC_ACQ_REL)) {clear_wait(current_thread(), THREAD_AWAKENED); return;}
    thread_block(THREAD_CONTINUE_NULL);
    __atomic_store_n(&gMsiWake, 0u, __ATOMIC_RELEASE);
}
}  // namespace
// The network side calls this after it queued a frame: the WiFi thread sends it now instead of at its next wake.
extern "C" void sheng_wifi_wake(void) {__atomic_store_n(&gMsiWake, 1u, __ATOMIC_RELEASE); thread_wakeup(event_t(&gMsiWake));}
namespace {

struct ControlClient {uint64_t session; uint32_t unit;};
kern_ctl_ref gControlRef;
IOLock *gControlLock;
ControlClient *gControlClient;
errno_t controlError(int status) {
    switch (status) {
        case NW_CONTROL_OK: return 0;
        case NW_CONTROL_INVALID: return EINVAL;
        case NW_CONTROL_BUSY: return EWOULDBLOCK;
        case NW_CONTROL_NOT_READY: return ENXIO;
        case NW_CONTROL_AUTH_FAILED: return EACCES;
        case NW_CONTROL_TIMED_OUT: return ETIMEDOUT;
        case NW_CONTROL_UNSUPPORTED: return EOPNOTSUPP;
        case NW_CONTROL_NO_MEMORY: return ENOBUFS;
        case NW_CONTROL_NOT_FOUND: return ENOENT;
        case NW_CONTROL_STALE: return ESTALE;
        default: return EIO;
    }
}
errno_t controlConnect(kern_ctl_ref, sockaddr_ctl *address, void **information) {
    auto *owner = static_cast<ControlClient *>(IOMalloc(sizeof(ControlClient)));
    if (!owner) return ENOMEM;
    const int status = nw_wifi_control_attach(&owner->session);
    if (status) {IOFree(owner, sizeof(*owner)); return controlError(status);}
    owner->unit = address->sc_unit;
    IOLockLock(gControlLock); gControlClient = owner; IOLockUnlock(gControlLock);
    *information = owner; return 0;
}
errno_t controlDisconnect(kern_ctl_ref, uint32_t, void *information) {
    // XNU invokes disconnect after a failed connect, with no client context.
    if (!information) return 0;
    auto *owner = static_cast<ControlClient *>(information);
    nw_wifi_control_detach(owner->session);
    IOLockLock(gControlLock); if (gControlClient == owner) gControlClient = nullptr; IOLockUnlock(gControlLock);
    IOFree(owner, sizeof(*owner)); return 0;
}
int controlReadMbuf(void *source, void *destination, size_t length) {
    return mbuf_copydata(static_cast<mbuf_t>(source), 0, length, destination);
}
errno_t controlReceive(kern_ctl_ref, uint32_t, void *information, mbuf_t packet, int) {
    auto *owner = static_cast<ControlClient *>(information);
    const int status = nw_wifi_control_receive(owner->session, mbuf_pkthdr_len(packet), controlReadMbuf, packet);
    mbuf_freem(packet); return controlError(status);
}
void controlReceived(kern_ctl_ref, uint32_t, void *information, int) {
    nw_wifi_control_writable(static_cast<ControlClient *>(information)->session);
}
errno_t controlGetOption(kern_ctl_ref, uint32_t, void *information, int option, void *bytes, size_t *length) {
    if (option != NW_CONTROL_GET_SESSION) return ENOPROTOOPT;
    if (!length) return EINVAL;
    if (!bytes || *length < sizeof(uint64_t)) {*length = sizeof(uint64_t); return EMSGSIZE;}
    const uint64_t session = static_cast<ControlClient *>(information)->session;
    memcpy(bytes, &session, sizeof(session)); *length = sizeof(session); return 0;
}
int controlSend(void *, uint64_t session, const void *bytes, size_t length) {
    IOLockLock(gControlLock);
    const bool active = gControlClient && gControlClient->session == session;
    const uint32_t unit = active ? gControlClient->unit : 0;
    IOLockUnlock(gControlLock);
    if (!active) return NW_CONTROL_SEND_CLOSED;
    // No adapter lock is held while the socket layer takes its own locks.
    const errno_t result = ctl_enqueuedata(gControlRef, unit, const_cast<void *>(bytes), length, CTL_DATA_EOR);
    if (!result) return NW_CONTROL_SEND_OK;
    if (result == ENOBUFS || result == EWOULDBLOCK) return NW_CONTROL_SEND_AGAIN;
    return NW_CONTROL_SEND_CLOSED;
}
void controlWake(void *) {sheng_wifi_wake();}
int controlStart() {
    if (gControlRef) return 0;
    if (!gControlLock) gControlLock = IOLockAlloc();
    if (!gControlLock) return ENOMEM;
    kern_ctl_reg registration{};
    snprintf(registration.ctl_name, sizeof(registration.ctl_name), "%s", NW_CONTROL_NAME);
    registration.ctl_flags = CTL_FLAG_PRIVILEGED | CTL_FLAG_REG_EXTENDED;
    registration.ctl_sendsize = 256 * 1024; registration.ctl_recvsize = 512 * 1024;
    registration.ctl_connect = controlConnect; registration.ctl_disconnect = controlDisconnect;
    registration.ctl_send = controlReceive; registration.ctl_getopt = controlGetOption; registration.ctl_rcvd = controlReceived;
    const errno_t result = ctl_register(&registration, &gControlRef);
    if (result) return result;
    const nw_control_transport transport{nullptr, controlSend, controlWake};
    const int status = nw_wifi_control_transport_set(&transport);
    if (status) {ctl_deregister(gControlRef); gControlRef = nullptr; return controlError(status);}
    return 0;
}

void wifiStack(volatile uint32_t *m, uint64_t barBytes) {
    volatile uint32_t *st = native_wifi_mhi;
    if (!arenaInit()) {st[0] = (uint32_t)-11; return;}
    pLog(6, sony069_wifi_dma_uncached ? "wifi: DMA window mapped uncached" : "wifi: DMA window mapped cached (no second mapping)");
    uint32_t diagnostics = 0; PE_parse_boot_argn("log-wifi", &diagnostics, sizeof diagnostics);
    // log-wifi=1: what reading the window costs the CPU next to ordinary memory. Every received frame is read out of the window once
    // (the copy into the stack's buffer), and the driver reads its descriptors and headers there.
    if (diagnostics) {
        constexpr size_t kProbe = 256 * 1024;
        if (uint8_t *plain = static_cast<uint8_t *>(IOMallocData(2 * kProbe))) {
            memset(plain, 0x5a, 2 * kProbe);
            const uint64_t began = pNowNs(); memcpy(plain, gArena.va + 4096, kProbe);
            const uint64_t middle = pNowNs(); memcpy(plain, plain + kProbe, kProbe);
            const uint64_t ended = pNowNs();
            native_wifi_logf(6, "wifi: reading 256 KiB of the DMA window %llu us, of ordinary memory %llu us", (middle - began) / 1000, (ended - middle) / 1000);
            IOFreeData(plain, 2 * kProbe);
        }
    }
    if (!findCaps()) {st[0] = (uint32_t)-12; return;}
    static const struct lx_platform plat = {pNow, pSleep, pPoll, pLog, pHalt, hAlloc, hFree, pDmaAlloc, pDmaFree, pDmaMap, pDmaSync, pFwGet, pNowNs, pBootNs, pBusyDelayUs, _disable_preemption, _enable_preemption};
    nw_wifi_set_platform(&plat);
    static struct nw_board board;
    gNwBar = m;
    board.bar = const_cast<uint32_t *>(m); board.bar_len = barBytes; board.device_id = (uint16_t)(gCfg[0] >> 16); board.msi_cap = (uint16_t)gMsiCap; board.irq_base = 1000;
    board.cfg_read = pCfgRead; board.cfg_write = pCfgWrite; board.msi_target = pMsiTarget; board.map_phys = nullptr;
    board.diagnostics = diagnostics;   // log-wifi=1: the module also asks the firmware for its receive statistics ("wifi: fw stats" lines)
    // the board's address window for the endpoint to reach sleep clock and sibling blocks is already set up by the earlier stages
    st[0] = 20;
    Fw firmware{};
    if (!findFirmware(firmware)) {
        native_wifi_logf(3, "wifi: Data firmware unavailable at %s", SHENG_WIFI_FIRMWARE_ROOT);
        st[0] = (uint32_t)-2; return;
    }
    const int control = controlStart();
    if (control) native_wifi_logf(3, "wifi: control endpoint registration failed: %d", control);
    if(control){st[0]=(uint32_t)-control;return;}
    const int irq=msiAttach();if(irq){st[0]=(uint32_t)-irq;return;}
    const int r = nw_wifi_start(&plat, &board);
    if(r){st[0]=(uint32_t)r;nw_wifi_stop();return;}
    st[0] = r ? (uint32_t)(0x80000000u | (uint32_t)(-r & 0xffff)) : 21;
    bool netDone = false;
    // The loop runs on interrupts once the MSI line is attached: it sleeps until the endpoint signals, a frame is queued to send or the
    // module's next timer may be due (10 ms), and goes round again at once while frames move. Without the line it falls back to polling
    // every millisecond.
    const int msi = msiAttach();
    nw_wifi_irq_mode(gMsiAttached);
    pLog(6, msi ? "wifi: MSI line not attached, polling" : "wifi: Sony ITS route attached, sleeping between interrupts");
    if (msi) native_wifi_logf(4, "wifi: MSI attach result %d", msi);
    uint64_t nextReport = 0, sliceStarted = pNowNs(), reportStarted = sliceStarted;
    uint64_t activeNs = 0, longestStep = 0, rounds = 0, yields = 0, reportedCpu = thread_get_runtime_self();
    uint32_t reportedFrames = 0, reportedMsis = 0;
    for (uint64_t n = 0;; ++n) {
        if(sony069_wifi_dma_faulted()){
            native_wifi_logf(3,"wifi: owned SMMU context fault; stopping the radio stack");
            st[0]=(uint32_t)-EIO;nw_wifi_stop();return;
        }
        const uint64_t began = pNowNs();
        const int busy = nw_wifi_step();
        const uint64_t stepNs = pNowNs() - began;
        activeNs += stepNs; rounds++;
        if (stepNs > longestStep) longestStep = stepNs;
        if (!netDone && nw_wifi_stats.stage >= 4) {netDone = true; netStart();}
        if (!busy) {
            if (gMsiAttached) {const unsigned wait = nw_wifi_wait_ms(1000); if (wait) msiWait(wait);}
            else IOSleep(1);
            sliceStarted = pNowNs();
        } else if (pNowNs() - sliceStarted >= 2000000) {
            // Let ready network/input threads run between sustained batches.
            // This checks pending preemption without adding a fixed sleep.
            thread_yield_to_preemption(); yields++; sliceStarted = pNowNs();
        }
        const uint64_t now = pNow();
        if (now >= nextReport) {
            nextReport = now + 30000;
            native_wifi_logf(6, "wifi: %u MSIs so far, vectors seen %08x", gMsiCount, gMsiBits);
            native_wifi_logf(6, "wifi: DMA used %zu peak %zu total %zu failures %u", gArena.used, gArena.peak, gArena.bytes, gArena.failures);
            nw_control_stats cs{}; nw_wifi_control_stats_get(&cs);
            native_wifi_logf(6, "wifi: control owner %llu opens %llu closes %llu last %u status %u", cs.active_session, cs.connections, cs.disconnections, cs.last_operation, cs.last_status);
            char link[128]; nw_wifi_link_state(link, sizeof(link));
            if (link[0]) native_wifi_logf(6, "wifi: link %s", link);
            const uint64_t end = pNowNs(), elapsed = end - reportStarted;
            native_wifi_logf(6, "wifi: worker rounds %llu active-permille %llu max-step-us %llu yields %llu",
                            rounds, elapsed ? activeNs * 1000 / elapsed : 0, longestStep / 1000, yields);
            // What this thread cost in that time and what it moved: its processor time (the steps' time above includes their
            // waits), the frames handed to the network side and the interrupts that woke it.
            const uint64_t cpu = thread_get_runtime_self(); uint64_t cpuNs = 0; absolutetime_to_nanoseconds(cpu - reportedCpu, &cpuNs);
            const uint32_t frames = nw_wifi_stats.frames, msis = gMsiCount;
            native_wifi_logf(6, "wifi: worker cpu-ms %llu step-ms %llu frames %u interrupts %u", cpuNs / 1000000, activeNs / 1000000,
                            frames - reportedFrames, msis - reportedMsis);
            reportedCpu = cpu; reportedFrames = frames; reportedMsis = msis;
            activeNs = longestStep = rounds = yields = 0; reportStarted = end;
        }
        if ((n & 63) == 0) st[1] = nw_wifi_stats.stage | nw_wifi_stats.scans << 8 | nw_wifi_stats.bss_seen << 16;
    }
}

// The host's half of the event rings (mhi_process_ctrl_ev_ring): the device advances the ring context's read pointer past each event it posts; the host takes
// them and tells the device the ring is free again by moving the write pointer to just behind that and ringing the ring's doorbell. Returns how many rings moved.
unsigned eventAck(volatile uint32_t *m) {
    constexpr uint32_t kCtx = 44, kChannels = 128;
    unsigned moved = 0;
    const uint32_t erdb = m[0x20 / 4];
    static uint64_t acked[2];
    for (unsigned r = 0; r < 2; ++r) {
        uint8_t *ctx = gCtxVa + kChannels * kCtx + r * kCtx;
        uint64_t base, len, rp;
        memcpy(&base, ctx + 12, 8); memcpy(&len, ctx + 20, 8); memcpy(&rp, ctx + 28, 8);
        if (rp == acked[r] || rp < base || rp >= base + len) continue;
        acked[r] = rp;
        const uint64_t wp = rp == base ? base + len - 16 : rp - 16;
        memcpy(ctx + 36, &wp, 8);
        __asm__ volatile("dc civac, %0\n dsb sy" :: "r"(ctx + 36) : "memory");
        m[(erdb + 8 * r) / 4] = (uint32_t)wp; m[(erdb + 8 * r + 4) / 4] = (uint32_t)(wp >> 32);
        ++moved;
    }
    return moved;
}

// What the device left for the host: the first events of both event rings, the event ring contexts' read and write pointers, the MSI sink and the BHIe block.
void eventSnapshot(volatile uint32_t *m, uint32_t slot) {
    volatile uint32_t *o = native_wifi_ev + slot * 24;
    if (!gCtxVa || !gEvVa[0]) return;
    for (unsigned i = 0; i < 8; ++i) {uint32_t w; memcpy(&w, gEvVa[0] + 4 * i, 4); o[i] = w;}      // ring 0: two entries
    for (unsigned i = 0; i < 4; ++i) {uint32_t w; memcpy(&w, gEvVa[1] + 4 * i, 4); o[8 + i] = w;}   // ring 1: one entry
    for (unsigned r = 0; r < 2; ++r) {
        uint32_t rp, wp;
        memcpy(&rp, gCtxVa + 128 * 44 + r * 44 + 28, 4); memcpy(&wp, gCtxVa + 128 * 44 + r * 44 + 36, 4);
        o[12 + 2 * r] = rp; o[13 + 2 * r] = wp;
    }
    for (unsigned i = 0; i < 2; ++i) {uint32_t w; memcpy(&w, gSinkVa + 4 * i, 4); o[16 + i] = w;}
    const uint32_t bhie = m[0x2c / 4];
    for (unsigned i = 0; i < 6; ++i) o[18 + i] = m[(bhie + 0x2c + 4 * i + (i >= 4 ? 4 : 0)) / 4];   // ADDR_LOW, ADDR_HIGH, SIZE, (0x38), DB, STATUS
}

void mhiBring(volatile uint32_t *m, uint64_t barBytes) {
    volatile uint32_t *st = native_wifi_mhi;
    const uint64_t t0 = mach_absolute_time();
    auto elapsed = [&]() {uint64_t ns = 0; absolutetime_to_nanoseconds(mach_absolute_time() - t0, &ns); return (uint32_t)(ns / 1000000);};
    static Dma seg[kMaxSegments], sbl, table, ctx;
    // the endpoint's DMA is limited to 32 bits (the Linux driver sets that mask): see whether the allocator has any memory below 4 GiB at all
    const bool low = &sony069_wifi_dma_va != nullptr && sony069_wifi_dma_va && sony069_wifi_dma_bytes >= 7u << 20;
    native_wifi_mhi_ms[7] = low ? sony069_wifi_dma_iova : 0xdead0000u | st[11];
    for (uint32_t i = 0; i < kMaxSegments; ++i)
        if (!dmaAlloc(seg[i], kSegment)) {st[0] = (uint32_t)-3; st[10] = 100 + i; return;}
    sbl = seg[0];   // the boot loader is the first 512 KiB of the image, consecutive segments
    if (!dmaAlloc(table, 4096)) {st[0] = (uint32_t)-3; st[10] = 201; return;}
    if (!dmaAlloc(ctx, 32 * 1024)) {st[0] = (uint32_t)-3; st[10] = 202; return;}
    st[15] = (uint32_t)(seg[0].pa >> 12);   // where the buffers landed (page numbers), kept until the registers are read after the load
    st[8] = (uint32_t)(sbl.pa >> 12); st[9] = (uint32_t)(table.pa >> 12); st[12] = (uint32_t)(ctx.pa >> 12);
    st[0] = 1; native_wifi_mhi_ms[0] = elapsed();
    Fw fw = {};
    if (!findFirmware(fw)) {st[0] = (uint32_t)-1; return;}
    native_wifi_mhi_ms[1] = elapsed();
    st[3] = fw.amssSize;
    const uint32_t segments = (fw.amssSize + kSegment - 1) / kSegment;
    st[4] = segments;
    if (segments > kMaxSegments) {st[0] = (uint32_t)-2; return;}
    constexpr size_t kChunk = 128 * 1024;
    uint8_t *bounce = static_cast<uint8_t *>(IOMallocData(kChunk));
    if (!bounce) {st[0] = (uint32_t)-3; st[10] = 2; return;}
    for (uint32_t done = 0; done < fw.amssSize; done += kChunk) {
        const uint32_t left = fw.amssSize - done, bytes = left < kChunk ? left : kChunk;
        memcpy(bounce, fw.image + done, bytes);
        for (uint32_t off = 0; off < bytes; off += kSegment) memcpy(seg[(done + off) / kSegment].va, bounce + off, bytes - off < kSegment ? bytes - off : kSegment);
    }
    IOFreeData(bounce, kChunk);
    st[0] = 2; native_wifi_mhi_ms[2] = elapsed();
    uint64_t addresses[kMaxSegments];
    for (uint32_t i = 0; i < segments; ++i) addresses[i] = seg[i].pa;
    const uint32_t entries = mhi_bhie_table(reinterpret_cast<MhiBhieEntry *>(table.va), 4096 / sizeof(MhiBhieEntry), addresses, fw.amssSize, kSegment);
    if (!entries) {st[0] = (uint32_t)-3; st[10] = 3; return;}
    {
        uint32_t sum = 0;
        for (uint32_t off = 0; off < kSbl; off += 4) {uint32_t w; memcpy(&w, seg[0].va + off, 4); sum += w;}
        uint32_t first; memcpy(&first, seg[0].va, 4);
        native_wifi_cfg[28] = sum; native_wifi_cfg[29] = first; native_wifi_cfg[31] = fw.amssSize;
    }
    for (uint32_t off = 0; off < gDmaUsed; off += 64) __asm__ volatile("dc civac, %0" :: "r"(sony069_wifi_dma_va + off) : "memory");   // the endpoint reads DRAM
    __asm__ volatile("dsb sy" ::: "memory");
    st[0] = 3;
    // the endpoint's pass-through stream 0x1401 was set up by the storage driver when it came up (it reads wifi): slot | bank << 16, bit 31 set
    st[1] = sony069_wifi_dma_stream;
    if (!(st[1] & 0x80000000u)) {st[0] = (uint32_t)-4; return;}
    st[0] = 4; native_wifi_mhi_ms[3] = elapsed();
    static Dma sink;
    if (!dmaAlloc(sink, 4096)) {st[0] = (uint32_t)-3; st[10] = 203; return;}
    gSinkVa = sink.va;
    uint32_t level0 = 0;
    PE_parse_boot_argn("wifi", &level0, sizeof level0);
    if (level0 >= 4) {chipPowerUp(m); endpointLinkSetup(sink.pa);}
    BarIo io = {m};
    MhiBoot boot = {};
    MhiIo mio = {barRead, barWrite, &io, (uint32_t)barBytes};
    if (mhi_boot_open(&boot, &mio)) {st[0] = (uint32_t)-5; return;}
    // the log writer needs a while to start; the next step is the one that can end the boot, so let it write a few slots first
    st[0] = 4; st[13] = elapsed();
    uint32_t level = 0;
    if (!PE_parse_boot_argn("wifi", &level, sizeof level) || level < 3 || !low) return;   // the load itself starts with wifi=3
    IOSleep(8000);
    programContexts(m, ctx, barBytes);
    for (uint32_t off = 0; off < gDmaUsed; off += 64) __asm__ volatile("dc civac, %0" :: "r"(sony069_wifi_dma_va + off) : "memory");
    __asm__ volatile("dsb sy" ::: "memory");   // the driver for this chip sets the device's context arrays up before the boot loader is started
    gTraceWrites = 1;
    gSkipReg = level >= 4 ? 0 : m[0x28 / 4] + MHI_BHI_IMGTXDB;   // wifi=3 sets everything up but leaves the doorbell alone
    st[14] = 1;   // about to write the boot loader's address and size into BHI
    uint32_t phase = mhi_boot_begin(&boot, 0, sbl.pa, kSbl < fw.amssSize ? kSbl : fw.amssSize, table.pa, entries * (uint32_t)sizeof(MhiBhieEntry), 0x5eed);
    gTraceWrites = 0;
    // the doorbell is written: stay off the endpoint for a while, each marker telling the log how far the boot got without touching it
    for (uint32_t quiet = 0; quiet < 3; ++quiet) {st[14] = 0x200 + quiet; IOSleep(2500);}
    st[14] = 0x203;
    st[14] = 2; st[0] = 5; native_wifi_mhi_ms[4] = elapsed();
    // one step per millisecond; every phase gets two seconds
    uint32_t last = phase, since = 0;
    for (unsigned i = 0; i < 20000 && phase != MhiDone && phase != MhiFailed; ++i) {   // five milliseconds a step, twenty seconds a phase (the driver for this chip waits as long)
        if (phase == MhiNeedContexts) {programContexts(m, ctx, barBytes); /* the boot loader resets the MHI registers when it starts: the contexts go in again once the device reports READY */ st[0] = 6; native_wifi_mhi_ms[5] = elapsed(); phase = mhi_boot_contexts_done(&boot);}
        else {
            if (i % 100 == 0 && (m[0x48 / 4] == 0xffffffffu)) {   // not answering: look at the link, put a cleared BAR back
                if (!native_wifi_cfg[16]) {linkSnapshot(native_wifi_cfg); native_wifi_cfg[16] = i + 1;}
                linkRecover();
                native_wifi_cfg[17] = gRestored;
            }
            phase = mhi_boot_step(&boot);
        }
        st[5] = boot.phase | boot.error << 8 | boot.failed_phase << 16; st[6] = boot.ee; st[7] = boot.state; st[14] = 100 + i;   // live, for a log slot written just before a reset
        if (phase != MhiNeedContexts && phase != MhiDone && phase != MhiFailed) native_wifi_chip[13] += eventAck(m);
        if (phase == MhiImageLoading && since == 600) eventSnapshot(m, 0);
        if (phase != last) {last = phase; since = 0;}
        else if (++since > 4000) {phase = mhi_boot_timeout(&boot); last = phase; since = 0;}
        IOSleep(5);
    }
    if (phase == MhiDone) st[0] = 7;
    eventSnapshot(m, 1);
    IOSleep(3000);
    linkSnapshot(native_wifi_cfg + 8);
    {uint32_t sum = 0; for (uint32_t off = 0; off < kSbl; off += 4) {uint32_t w; memcpy(&w, seg[0].va + off, 4); sum += w;} native_wifi_cfg[30] = sum;}
    if (&sony069_wifi_dma_fault) sony069_wifi_dma_fault(const_cast<uint32_t *>(native_wifi_cfg) + 18);
    st[5] = boot.phase | boot.error << 8 | boot.failed_phase << 16;
    st[6] = mhi_boot_ee(&boot); st[7] = mhi_boot_state(&boot);
    const uint32_t bhi = m[0x28 / 4], bhie = m[0x2c / 4];
    st[8] = m[(bhi + 0x2c) / 4]; st[9] = m[(bhi + 0x30) / 4];
    st[10] = m[(bhi + 0x34) / 4]; st[11] = m[(bhi + 0x38) / 4]; st[12] = m[(bhi + 0x3c) / 4];
    st[13] = m[0x48 / 4]; st[14] = elapsed(); st[15] = m[(bhie + 0x44) / 4]; native_wifi_mhi_ms[6] = st[14];
}

// Stage 4: forward the window to bus 1 (the root port's memory base and limit, outbound iATU region 1), give the endpoint's BAR0 an address in it, turn
// memory decoding and bus mastering on and read the MHI registers the BAR starts with. The endpoint's configuration space is reached through
// the 1 MiB window iATU region 0 maps to bus 1 (c), the root port's through the DBI (d), the iATU through a (unrolled, 0x200 per region).
void endpointProbe(volatile uint32_t *a, volatile uint32_t *c, volatile uint32_t *d) {
    gCfg = c; gDbi = d;
    volatile uint32_t *ep = native_wifi_ep;
    // region 1: memory, CPU window to the same PCI addresses
    volatile uint32_t *r1 = a + 0x200 / 4;
    r1[0x08 / 4] = uint32_t(kMemBase);
    r1[0x0c / 4] = uint32_t(kMemBase >> 32);
    r1[0x10 / 4] = uint32_t(kMemBase + kMemSize - 1);
    r1[0x20 / 4] = uint32_t((kMemBase + kMemSize - 1) >> 32);
    r1[0x14 / 4] = uint32_t(kMemBase);
    r1[0x18 / 4] = uint32_t(kMemBase >> 32);
    r1[0x00 / 4] = 0x0;
    r1[0x04 / 4] = 1u << 31;
    for (unsigned i = 0; i < 5 && !(r1[0x04 / 4] & (1u << 31)); ++i) IODelay(10);
    // type 1 header memory base (bits 15:4 = address bits 31:20) and limit (31:20)
    d[0x20 / 4] = uint32_t(((kMemBase + kMemSize - 1) & 0xfff00000u) | ((kMemBase >> 16) & 0xfff0u));
    ep[4] = d[0x20 / 4];
    ep[0] = 1;
    // BAR0: size it, put it at the start of the window
    const uint32_t saved = c[0x10 / 4];
    c[0x10 / 4] = 0xffffffffu;
    const uint32_t mask = c[0x10 / 4];
    c[0x10 / 4] = saved;
    ep[1] = mask;
    const uint32_t size = ~(mask & ~0xfu) + 1;
    if (!(mask & ~0xfu) || size!=0x200000 || size > kMemSize) {ep[0]=(uint32_t)-ENODEV;return;}
    // a BAR sits at an address aligned to its size: the first such address of the window
    const uint32_t address = uint32_t((kMemBase + size - 1) & ~uint64_t(size - 1));
    ep[1] = mask;
    c[0x10 / 4] = address | (mask & 0xfu);
    if ((mask & 6u) == 4u) c[0x14 / 4] = 0;
    c[0x04 / 4] = (c[0x04 / 4] & 0xffffu) | 0x6u;
    gBar0 = address | (mask & 0xfu);
    ep[2] = c[0x10 / 4];
    ep[3] = c[0x04 / 4];
    ep[0] = 2;
    Window bar = {};
    if (!mapWindow(bar, address, size < 0x200000 ? size : 0x200000)) return;
    volatile uint32_t *m = bar.va;
    for (unsigned i = 0; i < 7; ++i) {
        static const uint32_t regs[7] = {0x00, 0x08, 0x10, 0x28, 0x2c, 0x38, 0x48};
        ep[5 + i] = m[regs[i] / 4];
    }
    ep[0] = 3;
    uint32_t level5 = 0;
    PE_parse_boot_argn("wifi", &level5, sizeof level5);
    if (level5 >= 5) {ep[0] = 4; wifiStack(m, size < 0x200000 ? size : 0x200000); release(bar); return;}
    // wifi=4 only maps/inspects the endpoint. Production MHI starts at wifi=5.
    release(bar);
}

// Stage 2; the step reached stays in native_wifi_stats[0], a negative value names the step that failed.
void bringUp(Window &gcc, Window &tlmm) {
    volatile uint32_t *g = gcc.va, *t = tlmm.va;
    const int rails = sony_wcn_power_get(SONY_WCN_WLAN);
    IOSleep(20);
    if (rails) {native_wifi_stats[0] = -9; return;}
    IOSleep(5);
    // PERST# held low, CLKREQ# to its PCIe function, then WLAN_EN high and the WCN7850 power-up delay (pwrseq-qcom-wcn.c: 50 ms)
    setPin(t, kPerst, 1u | 1u << 9, 0);
    setPin(t, kClkReq, 3u | 1u << 2, -1);
    // the chip may still run what an earlier start left: WLAN_EN goes low first so that it starts from nothing
    setPin(t, kWlanEn, 1u | 1u << 9, 0);
    IOSleep(150);
    unsigned stage=0;PE_parse_boot_argn("wifi",&stage,sizeof(stage));
    if(stage>=5){
        if((t[kPerst*0x1000/4]&(1u<<9))==0 || (t[kWlanEn*0x1000/4]&(1u<<9))==0 ||
           ((t[(kPerst*0x1000+4)/4]|t[(kWlanEn*0x1000+4)/4])&3u)){
            native_wifi_stats[0]=(uint32_t)-EIO;return;
        }
        const int dmaError=sony069_wifi_dma_prepare();
        if(dmaError){native_wifi_stats[0]=(uint32_t)-dmaError;return;}
    }
    setPin(t, kWlanEn, 3u | 7u << 6 | 1u << 9, 1);
    IOSleep(60);
    native_wifi_stats[10] = pinWord(t);
    // what the pin registers hold now (a write TZ or the hypervisor drops reads back as written-nothing)
    native_wifi_stats[17] = (t[kWlanEn * 0x1000 / 4] & 0xffff) | t[(kWlanEn * 0x1000 + 4) / 4] << 16;
    native_wifi_stats[18] = (t[kPerst * 0x1000 / 4] & 0xffff) | t[(kPerst * 0x1000 + 4) / 4] << 16;
    native_wifi_stats[19] = (t[kClkReq * 0x1000 / 4] & 0xffff) | t[(kClkReq * 0x1000 + 4) / 4] << 16;
    native_wifi_stats[0] = 10;

    // both GDSCs are votable: a set bit in the collapse register (PCIe0 bit 0, PHY bit 3) keeps them collapsed
    const int collapseError=sony_wcn_gcc_update(kCollapse,1u<<0|1u<<3,0);if(collapseError){native_wifi_stats[0]=(uint32_t)-collapseError;return;}
    unsigned tries = 0;
    while (tries++ < 100 && (!(g[kGdsc / 4] & (1u << 31)) || !(g[kPhyGdsc / 4] & (1u << 31)))) IODelay(10);
    uint32_t power = (g[kGdsc / 4] >> 31) | (g[kPhyGdsc / 4] >> 31) << 1;
    native_wifi_stats[11] = power;
    if (power != 3) {native_wifi_stats[0] = -11; return;}
    native_wifi_stats[0] = 11;

    // sources first (an RCG takes a new CFG on CMD bit 0), the pipe mux parked on TCXO until the PHY runs, then the branch votes
    g[(kAuxRcg + 4) / 4] = 0;
    g[kAuxRcg / 4] |= 1u;
    g[(kRchngRcg + 4) / 4] = 6u << 8 | 5u;
    g[kRchngRcg / 4] |= 1u;
    waitClear(&g[kAuxRcg / 4], 1u, 100);
    waitClear(&g[kRchngRcg / 4], 1u, 100);
    g[kPipeMux / 4] = (g[kPipeMux / 4] & ~3u) | 2u;
    int voteError=sony_wcn_gcc_update(kVote8,0,kVote8Bits);if(!voteError)voteError=sony_wcn_gcc_update(kVote0,0,kVote0Bits);
    if(voteError){native_wifi_stats[0]=(uint32_t)-voteError;return;}
    Window clkref = {};
    if (!mapWindow(clkref, kTcsrClkref, 0x1000)) {native_wifi_stats[0] = -12; return;}
    clkref.va[0x100 / 4] |= 1u;
    release(clkref);
    IODelay(200);
    uint32_t off = 0;
    for (unsigned i = 0; i < sizeof kBranches / sizeof kBranches[0]; ++i)
        if (g[kBranches[i] / 4] & (1u << 31)) off |= 1u << i;
    native_wifi_stats[11] = power | off << 8;
    if (off & ~(1u << 4)) {native_wifi_stats[0] = -12; return;}   // the pipe branch runs only once the PHY drives it
    int resetError=pulseReset(g,kPcieBcr);if(!resetError)resetError=pulseReset(g,kPhyBcr);
    if(resetError){native_wifi_stats[0]=(uint32_t)-resetError;return;}
    native_wifi_stats[0] = 12;

    // qcom_pcie_init_2_7_0 after its resets, before the PHY powers on (qcom_pcie_host_init): PHY_CTRL's test power-down bit holds the PHY
    Window parf = {}, dbi = {};
    if (!mapWindow(parf, kParf, 0x3000) || !mapWindow(dbi, kDbi, 0x1000)) {release(parf); native_wifi_stats[0] = -13; return;}
    volatile uint32_t *f = parf.va, *d = dbi.va;
    f[kParfDeviceType / 4] = 4u;
    f[kParfPhyCtrl / 4] &= ~1u;
    f[kParfDbiBase / 4] = uint32_t(kDbi);
    f[kParfDbiBaseHi / 4] = uint32_t(kDbi >> 32);
    f[kParfAtuBase / 4] = uint32_t(kAtu);
    f[kParfAtuBaseHi / 4] = uint32_t(kAtu >> 32);
    f[kParfSlvSpace / 4] = 0;                 // qcom_pcie_configure_dbi_atu_base: the slave window spans 2 GiB << 32
    f[kParfSlvSpaceHi / 4] = kSlvSpaceBytes;
    f[kParfSysCtrl / 4] &= ~(1u << 29);
    f[kParfMhiClockReset / 4] |= 1u << 4;
    f[kParfPmCtrl / 4] &= ~(1u << 5);
    f[kParfAxiHalt / 4] |= 1u << 31;
    native_wifi_stats[0] = 13;

    // qmp_pcie_power_on: power-down control, the tables (both lanes), pipe clock from the PHY, out of reset, start, PHYSTATUS low
    Window phy = {};
    if (!mapWindow(phy, kPhy, 0x2000)) {release(dbi); release(parf); native_wifi_stats[0] = -14; return;}
    volatile uint32_t *p = phy.va;
    using namespace wifi_phy;
    // Exact Sony downstream PHY sequence, including Sony's different SerDes values.
    for (const auto &write : kSonyPciePhy) {
        p[write.offset / 4] = write.value;
        __asm__ volatile("dsb sy" ::: "memory");
        if(write.delay_us)IODelay(write.delay_us);
    }
    g[kPipeMux / 4] &= ~3u;
    p[kSwReset / 4] &= ~1u;
    p[kStartControl / 4] |= 3u;
    IODelay(1000);
    unsigned polls = 0;
    const bool ready = waitClear(&p[kPcsStatus1 / 4], 1u << 6, 100, &polls);
    native_wifi_stats[12] = (p[kPcsStatus1 / 4] & 0xffffu) | polls << 16;
    native_wifi_pmic[17] = g[kBranches[4] / 4];
    release(phy);
    if (!ready) {release(dbi); release(parf); native_wifi_stats[0] = -14; return;}

    // qcom_pcie_config_sid_1_9_0: the controller tells the SMMU which stream a requester's DMA belongs to from a hash table of requester IDs
    // (0x2000, 256 words: BDF << 16 | stream offset << 8 | next) once its bypass bit (0x2c00 bit 0) is off. The iommu-map is requester 0 -> stream 0x1400 and
    // requester 0x100 (bus 1, the endpoint) -> 0x1401; the hash is a CRC-8 (polynomial 7, MSB first) of the requester ID's two bytes, high one first.
    {
        volatile uint32_t *f = parf.va;
        for (unsigned i = 0; i < 256; ++i) f[(0x2000 + 4 * i) / 4] = 0;
        f[0x2c00 / 4] &= ~1u;
        auto crc8 = [](uint16_t bdf) {
            uint8_t crc = 0;
            const uint8_t bytes[2] = {(uint8_t)(bdf >> 8), (uint8_t)bdf};
            for (uint8_t byte : bytes) {
                crc ^= byte;
                for (int bit = 0; bit < 8; ++bit) crc = (crc & 0x80) ? (uint8_t)((crc << 1) ^ 7) : (uint8_t)(crc << 1);
            }
            return crc;
        };
        const uint8_t hash = crc8(0x100);
        f[(0x2000 + 4 * hash) / 4] = 0x100u << 16 | 1u << 8;   // requester 0 hashes to entry 0 with offset 0: the zeroed word already says that
        __asm__ volatile("dsb sy" ::: "memory");
        native_wifi_pon[10] = hash | f[0x2c00 / 4] << 8 | (f[(0x2000 + 4 * hash) / 4] != 0) << 31;   // hash, bypass register, entry written
    }

    // qcom_pcie_post_init_2_7_0 and the root port's bus numbers and command (dw_pcie_setup_rc)
    d[kBusNumbers / 4] = 0x00010100;   // primary 0, secondary 1, subordinate 1
    d[kCommand / 4] |= 0x6u;           // memory space and bus master
    native_wifi_stats[7] = d[0];
    native_wifi_stats[0] = 14;

    // qcom_ep_reset_deassert: PERST# low for at least 100 ms, then high, then the LTSSM (qcom_pcie_2_3_2_ltssm_enable)
    IOSleep(100);
    setPin(t, kPerst, 1u | 1u << 9, 1);
    IODelay(1000);
    native_wifi_stats[0] = 15;
    f[kParfLtssm / 4] |= 1u << 8;
    const uint64_t start = mach_absolute_time();
    unsigned ms = 0;
    for (; ms < 1000; ++ms) {
        if ((d[kPortDebug1 / 4] & (1u << 4)) && (d[kPortDebug0 / 4] & 0x3f) == 0x11) break;
        if (ms == 20) {native_wifi_pmic[19] = d[kPortDebug0 / 4]; native_wifi_pmic[21] = d[kPortDebug1 / 4];}
        IOSleep(1);
    }
    uint64_t ns = 0;
    absolutetime_to_nanoseconds(mach_absolute_time() - start, &ns);
    native_wifi_stats[16] = uint32_t(ns / 1000000);
    native_wifi_pmic[18] = (t[kPerst * 0x1000 / 4] & 0xffff) | t[(kPerst * 0x1000 + 4) / 4] << 16;
    native_wifi_pmic[20] = g[kPipeMux / 4];
    native_wifi_stats[13] = d[kPortDebug0 / 4];
    native_wifi_stats[14] = d[kPortDebug1 / 4];
    native_wifi_stats[6] = f[kParfLtssm / 4];
    native_wifi_stats[8] = d[kLinkControl / 4];
    native_wifi_stats[9] = f[kParfPhyCtrl / 4];
    if (ms == 1000) {release(dbi); release(parf); native_wifi_stats[0] = -16; return;}
    native_wifi_stats[0] = 16;

    // outbound iATU region 0 (unrolled at the ATU base) turns the 1 MiB config window into type 0 accesses to bus 1 device 0
    Window atu = {}, config = {};
    if (mapWindow(atu, kAtu, 0x1000) && mapWindow(config, kConfig, 0x1000)) {
        volatile uint32_t *a = atu.va;
        a[0x08 / 4] = uint32_t(kConfig);
        a[0x0c / 4] = uint32_t(kConfig >> 32);
        a[0x10 / 4] = uint32_t(kConfig + 0xfffff);
        a[0x20 / 4] = uint32_t((kConfig + 0xfffff) >> 32);
        a[0x14 / 4] = 1u << 24;
        a[0x18 / 4] = 0;
        a[0x00 / 4] = 0x4;
        a[0x04 / 4] = 1u << 31;
        for (unsigned i = 0; i < 5 && !(a[0x04 / 4] & (1u << 31)); ++i) IODelay(10);
        native_wifi_stats[15] = config.va[0];
        native_wifi_stats[0] = 17;
        unsigned requested=0;PE_parse_boot_argn("wifi",&requested,sizeof(requested));
        if (config.va[0] == 0x110717cb && (config.va[8/4]&255)==1) {if(requested>=4)endpointProbe(a, config.va, d);}
        else native_wifi_stats[0]=(uint32_t)-ENODEV;
    } else native_wifi_stats[0] = -17;
    release(config); release(atu); release(dbi); release(parf);
}

void wifiThread(void *arg, wait_result_t) {
    thread_set_thread_name(current_thread(), "wifi");
    if (reinterpret_cast<uintptr_t>(arg) >= 5) {
        uint32_t variant=1;
        if(PE_parse_boot_argn("wifi-fw",&variant,sizeof(variant)) && variant!=1){native_wifi_stats[0]=(uint32_t)-ENOTSUP;return;}
        int ready=EAGAIN;
        for(unsigned i=0;i<240 && ready==EAGAIN;++i){
            ready=sony_wcn_wifi_inputs_ready();
            if(ready==EAGAIN)IOSleep(500);
        }
        if(ready){native_wifi_stats[0]=(uint32_t)-ready;native_wifi_logf(3,"wifi: installed firmware rejected: %d",ready);return;}
    }
    publishMac();
    Window gcc = {}, tlmm = {}, parf = {}, dbi = {};
    if (!mapWindow(gcc, kGcc, 0x80000) || !mapWindow(tlmm, kTlmm, 0x60000)) {native_wifi_stats[0] = -1; release(gcc); release(tlmm); return;}
    native_wifi_stats[0] = 1;
    native_wifi_stats[1] = gcc.va[kVote8 / 4];
    native_wifi_stats[2] = gcc.va[kVote0 / 4];
    const uint32_t gdsc = gcc.va[kGdsc / 4];
    native_wifi_stats[3] = gdsc;
    uint32_t off = 0;
    for (unsigned i = 0; i < sizeof kBranches / sizeof kBranches[0]; ++i)
        if (gcc.va[kBranches[i] / 4] & (1u << 31)) off |= 1u << i;
    native_wifi_stats[4] = off;
    native_wifi_stats[5] = pinWord(tlmm.va);
    native_wifi_stats[0] = 2;
    if (reinterpret_cast<uintptr_t>(arg) >= 2) {bringUp(gcc, tlmm); release(tlmm); release(gcc); return;}
    if ((gdsc & (1u << 31)) && !(off & kNeeded) && mapWindow(parf, kParf, 0x3000) && mapWindow(dbi, kDbi, 0x1000)) {
        native_wifi_stats[6] = parf.va[kParfLtssm / 4];
        native_wifi_stats[9] = parf.va[kParfPhyCtrl / 4];
        native_wifi_stats[7] = dbi.va[0];
        native_wifi_stats[8] = dbi.va[kLinkControl / 4];
        native_wifi_stats[0] = 3;
    }
    release(dbi); release(parf); release(tlmm); release(gcc);
}
}  // namespace

// A cached Data firmware file by name, for the board's own test hooks.
extern "C" int sheng_wifi_file(const char *name, const uint8_t **data, size_t *size) {return pFwGet(name, data, size);}

extern "C" void native_sony_wifi_start(void) {
    unsigned stage = 0;
    static uint32_t started;
    if (!PE_parse_boot_argn("wifi", &stage, sizeof stage) || stage < 1) return;
    if(stage!=1 && stage!=2 && stage!=4 && stage!=5){native_wifi_stats[0]=(uint32_t)-EINVAL;return;}
    // Fail before any power/reset/MMIO/thread when prerequisites are missing.
    int ready=stage>=2?sony_wcn_platform_ready():0;
    if(!ready && stage>=5)ready=sony_wcn_platform_wifi_ready();
    if(ready){native_wifi_stats[0]=(uint32_t)-ready;return;}
    const int addressError069=native_sony_wifi_publish();
    if(addressError069){native_wifi_stats[0]=(uint32_t)-addressError069;return;}
    uint32_t expected=0;
    if(!__atomic_compare_exchange_n(&started,&expected,1u,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return;
    thread_t thread = nullptr;
    if (kernel_thread_start(wifiThread, reinterpret_cast<void *>(uintptr_t(stage)), &thread) == KERN_SUCCESS) thread_deallocate(thread);
    else {native_wifi_stats[0] = (uint32_t)-ENOMEM;__atomic_store_n(&started,0u,__ATOMIC_RELEASE);}
}

