// SPDX-License-Identifier: BSD-2-Clause-Patent
// Read-only Sony diagnostics. No display/SMMU programming or panel mode switch.
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IODeviceMemory.h>
#include <kern/thread.h>
#include <mach/mach_time.h>
#include <pexpert/pexpert.h>
#include <string.h>
#include "SonyPerformanceLimits.h"

extern "C" {
extern volatile uint32_t native_cpufreq_stage, native_cpufreq_gov[9], native_cpufreq_boosts;
extern volatile uint32_t native_cpufreq_frame[2], native_cpufreq_throttle[9];
extern volatile uint32_t native_gpu_dcvs[15], native_gpu_perf_vote[2], native_gpu_irq[6];
extern volatile uint64_t native_gpu_idle_sleeps, native_gpu_idle_spins, native_gpu_idle_timeouts;
extern volatile uint32_t native_adreno_fence_wake[8];
extern volatile uint32_t native_legacy_transfer_calls, native_legacy_retirement_calls;
extern char native_cpufreq_row[120];
unsigned native_legacy_state_words(char *,unsigned);
volatile uint32_t native_sony_performance_stage;
}

namespace {
// Qualified in the post066 FDT: dsi_ctrl{0,1}.reg-names="mdp_intf_base".
// The official DisplayTimingProbe uses identical DPU9 counter offsets. We only
// map the two 0x300-byte interface windows, not its broad tablet MDP window.
constexpr uint64_t kIntfBase[2] = {0xae36000, 0xae37000};
constexpr unsigned kTimingEnable=0x6c, kCountEnable=0xa8, kFrameCount=0xac;
constexpr unsigned kLineCount=0xb0, kHsync=0x08, kVsync=0x0c, kConfig=0x04;
IOMemoryMap *gMaps[2];
uintptr_t gVa[2];
unsigned arg(const char *name, unsigned fallback) {
    PE_parse_boot_argn(name, &fallback, sizeof(fallback)); return fallback;
}
uint32_t rd(unsigned i, unsigned off) {
    return *reinterpret_cast<volatile uint32_t *>(gVa[i]+off);
}
void performanceThread(void *, wait_result_t) {
    thread_set_thread_name(current_thread(), "sony-performance");
    const unsigned samples=pdx_performance_samples(arg("sony-perf-samples",60));
    if(!samples){native_sony_performance_stage=3;thread_terminate(current_thread());return;}
    // Keep this observer outside the GPU/touch/SMMU initialization paths.
    IOSleep(150000);
    if(arg("sony-display-timing", 0)) {
        PE_Video video={};
        if(PE_current_console(&video)==0)
            IOLog("[sony-gop] base=%llx width=%lu height=%lu stride=%lu depth=%lu inherited=1 mode-switch=0\n",
                  (unsigned long long)video.v_baseAddr, (unsigned long)video.v_width, (unsigned long)video.v_height,
                  (unsigned long)video.v_rowBytes, (unsigned long)video.v_depth);
        for(unsigned i=0;i<2;++i) {
            IODeviceMemory *memory=IODeviceMemory::withRange(kIntfBase[i], 0x300);
            gMaps[i]=memory?memory->map(kIOMapAnywhere|kIOMapInhibitCache|kIOMapReadOnly):nullptr;
            if(memory)memory->release();
            if(gMaps[i])gVa[i]=gMaps[i]->getVirtualAddress();
        }
    }
    uint32_t prior[2]={},copies=native_legacy_transfer_calls,retires=native_legacy_retirement_calls;
    bool havePrior[2]={};
    uint64_t previous=mach_absolute_time();
    native_sony_performance_stage=2;
    for(unsigned sample=0;sample<samples;++sample) {
        IOSleep(10000);
        uint64_t ns=0;const uint64_t now=mach_absolute_time();
        absolutetime_to_nanoseconds(now-previous,&ns);previous=now;
        IOLog("[sony-perf] cpufreq=%u stage=%u gov=%u/%u/%u,%u/%u/%u,%u/%u/%u boost=%u frames=%u/%u gpu-dcvs=%u level=%u changes=%u failures=%u busy=%u vote=%u/%u sleeps=%llu spins=%llu timeouts=%llu irq-since-boot=%u wake=%u/%u/%u\n",
              arg("cpufreq",0),native_cpufreq_stage,
              native_cpufreq_gov[0],native_cpufreq_gov[1],native_cpufreq_gov[2],
              native_cpufreq_gov[3],native_cpufreq_gov[4],native_cpufreq_gov[5],
              native_cpufreq_gov[6],native_cpufreq_gov[7],native_cpufreq_gov[8],
              native_cpufreq_boosts,native_cpufreq_frame[0],native_cpufreq_frame[1],
              native_gpu_dcvs[0],native_gpu_dcvs[1],native_gpu_dcvs[2],native_gpu_dcvs[3],native_gpu_dcvs[4],
              native_gpu_perf_vote[0],native_gpu_perf_vote[1],
              (unsigned long long)native_gpu_idle_sleeps,(unsigned long long)native_gpu_idle_spins,
              (unsigned long long)native_gpu_idle_timeouts,native_adreno_fence_wake[0],
              native_adreno_fence_wake[0],native_adreno_fence_wake[3],native_adreno_fence_wake[4]);
        char cpu[120]={};memcpy(cpu,native_cpufreq_row,sizeof(cpu)-1);
        IOLog("[sony-cpufreq-state] %s throttle=%u/%u/%u,%u/%u/%u,%u/%u/%u\n",cpu,
              native_cpufreq_throttle[0],native_cpufreq_throttle[1],native_cpufreq_throttle[2],
              native_cpufreq_throttle[3],native_cpufreq_throttle[4],native_cpufreq_throttle[5],
              native_cpufreq_throttle[6],native_cpufreq_throttle[7],native_cpufreq_throttle[8]);
        const uint32_t nc=native_legacy_transfer_calls,nr=native_legacy_retirement_calls;
        IOLog("[sony-present-rate] elapsed-us=%llu copies=%u retired=%u copy-delta=%u retire-delta=%u requested-vsync=%u panel-hz=unmeasured\n",
              (unsigned long long)(ns/1000),nc,nr,nc-copies,nr-retires,arg("vsync",0));
        copies=nc;retires=nr;
        char state[128]={};native_legacy_state_words(state,sizeof(state));
        // Reading an unclocked display block is not safe on every power path.
        // The qualified display009 helper reads only the retained D27 powered
        // word, never MMIO. Skip if the service is absent or reports powered=0.
        const bool displayPowered=pdx_performance_display_powered(state,sizeof(state));
        if(!displayPowered){havePrior[0]=havePrior[1]=false;}
        for(unsigned i=0;i<2;++i)if(gVa[i] && displayPowered) {
            const uint32_t frames=rd(i,kFrameCount),enable=rd(i,kTimingEnable),count=rd(i,kCountEnable);
            const uint32_t delta=havePrior[i]?frames-prior[i]:0;prior[i]=frames;havePrior[i]=true;
            IOLog("[sony-dpu-rate] interface=%u base=%llx timing=%x counter-enable=%x config=%x frame=%u delta=%u elapsed-us=%llu line=%u hsync=%x vsync-period=%u read-only=1\n",
                  i+1,(unsigned long long)kIntfBase[i],enable,count,rd(i,kConfig),frames,delta,
                  (unsigned long long)(ns/1000),rd(i,kLineCount),rd(i,kHsync),rd(i,kVsync));
        }
    }
    for(auto &map:gMaps)if(map){map->release();map=nullptr;}
    gVa[0]=gVa[1]=0;
    native_sony_performance_stage=3;
    thread_terminate(current_thread());
}
}
extern "C" void native_sony_performance_start(void) {
    if(native_sony_performance_stage)return;
    native_sony_performance_stage=1;
    thread_t thread=nullptr;
    if(kernel_thread_start(performanceThread,nullptr,&thread)==KERN_SUCCESS)thread_deallocate(thread);
    else native_sony_performance_stage=~0u;
}
