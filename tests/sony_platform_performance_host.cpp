// SPDX-License-Identifier: BSD-2-Clause-Patent
// Host harness for verbatim bodies extracted from the compiled official sources.
// No simulated hardware result is a handset qualification.
#include <algorithm>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <vector>
#include "SonyPerformanceLimits.h"

#define CHECK(x) do {if(!(x)){std::fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x);std::abort();}} while(0)
struct Stop {};
uint64_t now_abs, idle_abs[8];
std::function<void()> on_sleep;
unsigned checks, sleep_count, spin_count, wait_timeout_us;
bool irq_enabled=true, interrupt_context=false;
int preemption_level;
uint64_t mach_absolute_time(){return now_abs;}
void nanoseconds_to_absolutetime(uint64_t n,uint64_t *p){*p=n;}
void absolutetime_to_nanoseconds(uint64_t n,uint64_t *p){*p=n;}
using thread_t=void *;using wait_result_t=int;using event_t=void *;
constexpr int KERN_SUCCESS=0,THREAD_UNINT=0,THREAD_TIMED_OUT=1;
#define THREAD_CONTINUE_NULL nullptr
constexpr uint32_t NSEC_PER_USEC=1000;
void thread_deallocate(thread_t){}
int kernel_thread_start(void (*)(void *,int),void *,thread_t *t){*t=(void*)1;return 0;}
void IOSleep(unsigned ms){now_abs+=uint64_t(ms)*1000000;if(on_sleep)on_sleep();}
void IODelay(unsigned us){now_abs+=uint64_t(us)*1000;++spin_count;}
bool ml_get_interrupts_enabled(){return irq_enabled;}
bool ml_at_interrupt_context(){return interrupt_context;}
extern "C" int get_preemption_level(){return preemption_level;}
void assert_wait_timeout(event_t,int,unsigned us,uint32_t){wait_timeout_us=us;}
int thread_block(void *){now_abs+=uint64_t(wait_timeout_us)*1000;++sleep_count;return THREAD_TIMED_OUT;}
struct IOLock{};
IOLock *IOLockAlloc(){static IOLock lock;return &lock;}
void IOLockLock(IOLock*){}
void IOLockUnlock(IOLock*){}
uint32_t mmio[4][1024];
constexpr unsigned kIOMapAnywhere=1,kIOMapInhibitCache=2;
struct IOMemoryMap{uint32_t *p;uintptr_t getVirtualAddress(){return (uintptr_t)p;}};
struct IODeviceMemory {
    unsigned index;
    static IODeviceMemory *withRange(uint64_t base,uint64_t){
        static IODeviceMemory mem[4]={{0},{1},{2},{3}};
        unsigned n=base==0x17d90000?3:unsigned((base-0x17d91000)/0x1000);
        CHECK(n<4);return &mem[n];
    }
    IOMemoryMap *map(unsigned){static IOMemoryMap maps[4];maps[index].p=mmio[index];return &maps[index];}
    void release(){}
};
struct BootArg{const char *name;unsigned value;};
std::vector<BootArg> args;
bool PE_parse_boot_argn(const char *name,void *out,int size){
    for(auto a:args)if(!std::strcmp(a.name,name)){CHECK(size==4);std::memcpy(out,&a.value,4);return true;}return false;
}
extern "C" {
volatile uint32_t native_touch_seq,native_touch_count;
volatile uint32_t native_adreno_method_stats[20][4],native_hid_input_events[8];
uint64_t sheng_cpu_idle_mach(int c){return idle_abs[c];}
}
#include "cpu.inc"

void cpu_reset(){
    std::memset(mmio,0,sizeof(mmio));std::memset(idle_abs,0,sizeof(idle_abs));now_abs=0;
    gMode=0;gLock=nullptr;gCapKHz=0;gFloorKHz=0;
    gBoostMs=1000;gFrameMs=300;gFramePct=60;
    gPdxPerformanceTouch={};native_touch_seq=0;native_touch_count=0;
    native_cpufreq_boosts=0;native_cpufreq_frame[0]=0;native_cpufreq_frame[1]=0;
    native_adreno_method_stats[5][0]=0;
    std::memset(gDomain,0,sizeof(gDomain));gL3={};args.clear();on_sleep={};
    for(unsigned d=0;d<4;++d){
        mmio[d][0]=1;
        // One GPLL row, then 576, 1152, 1920 MHz and duplicate terminator.
        const uint32_t lut[]={0,(1u<<30)|30,(1u<<30)|60,(1u<<30)|100,(1u<<30)|100};
        for(unsigned i=0;i<5;++i)mmio[d][0x100/4+i]=lut[i];
        mmio[d][0x320/4]=0x5a;
    }
}
void cpu_run(unsigned windows,unsigned busy_pm,const std::function<void(unsigned)> &change={}){
    unsigned tick=0;
    on_sleep=[&]{
        if(++tick>windows)throw Stop{};
        for(auto &idle:idle_abs)idle+=16000000ull*(1000-busy_pm)/1000;
        if(change)change(tick);
    };
    try{governorThread(nullptr,0);}catch(const Stop&){}
    on_sleep={};
}
void test_cpu(){
    cpu_reset();args={{"cpufreq",1}};sheng_cpufreq_probe();
    for(unsigned d=0;d<3;++d)CHECK(mmio[d][0x320/4]==0x5a);
    CHECK(gL3.va==0);++checks;
    cpu_reset();args={{"cpufreq",4},{"cpufreq-boost-ms",0},{"cpufreq-frame-ms",0}};
    sheng_cpufreq_probe();cpu_run(4,0);
    CHECK(gDomain[0].votedKHz==300000);CHECK(gDomain[1].votedKHz==1152000);
    CHECK(gDomain[2].votedKHz==1152000);CHECK(gL3.votedKHz==1920000);++checks;
    cpu_reset();args={{"cpufreq",4},{"cpufreq-boost-ms",0},{"cpufreq-frame-ms",0}};
    sheng_cpufreq_probe();cpu_run(16,0);
    CHECK(gDomain[0].votedKHz==300000 && gDomain[1].votedKHz==300000 && gDomain[2].votedKHz==300000);++checks;
    cpu_reset();args={{"cpufreq",4},{"cpufreq-boost-ms",0},{"cpufreq-frame-ms",0}};
    sheng_cpufreq_probe();cpu_run(20,0,[](unsigned n){if(n==17)for(auto &v:idle_abs)v-=14400000;});
    // A single >=90% busy window ramps immediately, not by summed eight-core load.
    CHECK(gDomain[0].votedKHz==1920000);++checks;
    cpu_reset();args={{"cpufreq",4},{"cpufreq-cap",1200},{"cpufreq-boost-ms",0},{"cpufreq-frame-ms",0}};
    sheng_cpufreq_probe();cpu_run(1,1000);
    CHECK(gDomain[0].votedKHz==1152000 && gL3.votedKHz==1152000);++checks;
    cpu_reset();args={{"cpufreq",4},{"cpufreq-frame-ms",0}};sheng_cpufreq_probe();
    cpu_run(100,0,[](unsigned){native_touch_seq=native_touch_seq+2;});
    CHECK(native_cpufreq_boosts==0 && gDomain[1].votedKHz==300000);++checks;
    cpu_reset();args={{"cpufreq",4},{"cpufreq-frame-ms",0}};sheng_cpufreq_probe();
    cpu_run(100,0,[](unsigned n){if(n==20){native_touch_count=1;native_touch_seq=2;}
                               if(n==21){native_touch_count=0;native_touch_seq=4;}});
    CHECK(native_cpufreq_boosts==1 && gDomain[1].votedKHz==300000);++checks;
    cpu_reset();args={{"cpufreq",4},{"cpufreq-boost-ms",0}};sheng_cpufreq_probe();
    cpu_run(40,0,[](unsigned n){if(n==20 || n==22)native_adreno_method_stats[5][0]=native_adreno_method_stats[5][0]+1;});
    CHECK(native_cpufreq_frame[0]==1 && gDomain[0].votedKHz>=1152000);++checks;
    cpu_reset();args={{"cpufreq",4},{"cpufreq-boost-ms",0},{"cpufreq-frame-ms",0}};
    mmio[1][0]=0;sheng_cpufreq_probe();cpu_run(8,1000);
    CHECK(gDomain[1].voted<0 && gDomain[0].votedKHz==1920000);++checks;
    // LUT turbo entry is excluded, independently of row order.
    cpu_reset();args={{"cpufreq",1}};sheng_cpufreq_probe();
    mmio[0][0x100/4+3]=(1u<<30)|(1u<<16)|100;buildLevels(0);
    CHECK(gLevels[0].count==3 && gLevels[0].khz[2]==1152000);++checks;
    // Stable, torn, release and sequence-wrap touch snapshots.
    PdxPerformanceTouchState t;
    CHECK(t.observe(2,0,2)==0 && t.observe(3,1,3)==0 && t.observe(4,1,6)==0);
    CHECK(t.observe(6,1,6)==1 && t.observe(8,0,8)==2 && t.observe(10,0,10)==2);
    t.seen=0xfffffffeu;CHECK(t.observe(0,1,0)==3);++checks;
}

namespace gpuhost {
uint64_t busy_ticks;
bool pending,vote_fail;
std::vector<unsigned> votes;
struct Io {
    void *cookie=nullptr;
    int read32(void *,unsigned,size_t,uint32_t *out){*out=0;return 0;}
    int write32(void *,unsigned,size_t,uint32_t){return 0;}
    int barrier(void*){return 0;}
};
using ShengGmuIo=Io;
struct {Io io;unsigned hfi;}gColdDevice;
constexpr unsigned ShengGmuCore=0,A740_CP_RB_RPTR=1,A740_CP_RB_WPTR=2;
unsigned kGmuReg(unsigned n){return n*4-0x6a000;}
unsigned bootArg(const char *n,unsigned f){PE_parse_boot_argn(n,&f,4);return f;}
uint64_t gpuBusyTicks(){return busy_ticks;}
unsigned gpuRd(unsigned reg){return reg==A740_CP_RB_WPTR && pending?1:0;}
struct AdrenoHfiBcm{unsigned buswidth,fixed,perfmode,perfmode_kbps;};
#include "ShengGmuVotesSource.h"
#include "vote-index.inc"
unsigned last_vote_bw;
int hfiWait(void*){return 0;}
int AdrenoHfiExchange(unsigned*,unsigned opcode,const uint32_t *vote,size_t words,unsigned,
                      int (*)(void*),uint32_t*,unsigned,size_t *count,uint32_t *error){
    CHECK(opcode==30 && words==3 && vote[0]==1);
    votes.push_back(vote[1]);last_vote_bw=vote[2];*count=0;*error=0;
    return vote_fail?1:0;
}
void gpuPerfTick(uint64_t){}
template<class... T>void boot_latency_record(T...){}
uint32_t native_gpu_perf_vote[2]={1,1};
#include "gpu.inc"
void reset(){
    args.clear();now_abs=0;busy_ticks=0;pending=false;vote_fail=false;votes.clear();
    native_gpu_perf_vote[0]=8;native_gpu_dcvs[0]=0;native_gpu_dcvs[2]=0;native_gpu_dcvs[3]=0;
    native_gpu_dcvs[13]=native_gpu_dcvs[14]=0;
    gPdxPerformanceTouch={};native_touch_seq=0;native_touch_count=0;
}
void run(unsigned windows,const std::function<void(unsigned)> &change){
    unsigned tick=0;on_sleep=[&]{if(++tick>windows)throw Stop{};change(tick);};
    try{gpuDcvsThread(nullptr,0);}catch(const Stop&){}on_sleep={};
}
void test(){
    reset();args={{"gpu-dcvs-boost-ms",0}};run(8,[](unsigned){});
    CHECK(native_gpu_dcvs[1]==4 && votes.back()==4 && kGpuMHz[4]==348);++checks;
    reset();args={{"gpu-dcvs-boost-ms",0}};native_gpu_perf_vote[0]=4;
    run(1,[](unsigned){busy_ticks+=307200;});CHECK(native_gpu_dcvs[1]==8 && votes.back()==8 && kGpuMHz[8]==615);++checks;
    reset();run(150,[](unsigned){native_touch_seq=native_touch_seq+2;});
    CHECK(native_gpu_dcvs[13]==0 && native_gpu_dcvs[1]==4);++checks;
    reset();run(100,[](unsigned n){if(n==20){native_touch_count=1;native_touch_seq=2;}
                                if(n==21){native_touch_count=0;native_touch_seq=4;}});
    CHECK(native_gpu_dcvs[13]==1 && native_gpu_dcvs[1]==4);++checks;
    reset();args={{"gpu-dcvs-boost-ms",0}};run(10,[](unsigned n){if(n==10){pending=true;busy_ticks+=19200;}});
    CHECK(native_gpu_dcvs[14]==1 && native_gpu_dcvs[1]==8);++checks;
    reset();args={{"gpu-dcvs-boost-ms",0}};native_gpu_perf_vote[0]=4;vote_fail=true;
    run(1,[](unsigned){busy_ticks+=307200;});
    CHECK(native_gpu_dcvs[3]==1 && native_gpu_dcvs[1]==4);++checks;
    reset();args={{"gpu-dcvs-boost-ms",0},{"gpu-dcvs-min",999}};run(8,[](unsigned){});
    CHECK(native_gpu_dcvs[1]==8);++checks;
    reset();args={{"gpu-dcvs-boost-ms",0},{"gpu-dcvs-span",999}};
    run(24,[](unsigned n){if(n%4==0)busy_ticks+=19200;});
    CHECK(native_gpu_dcvs_windows[7]==8 && native_gpu_dcvs[1]>=4 && native_gpu_dcvs[1]<=8);++checks;
    reset();args={{"gpu-dcvs-boost-ms",0}};native_gpu_perf_vote[0]=4;
    run(1,[](unsigned){busy_ticks+=UINT64_C(19200000);});
    CHECK(native_gpu_dcvs[1]==8);++checks; // counter time clamps at elapsed time
    for(unsigned level=1;level<SHENG_GPU_OPPS;++level){
        CHECK(gpuVote(level));
        CHECK(native_gpu_perf_vote[0]==level && last_vote_bw==native_gpu_perf_vote[1]);
        CHECK(sheng_gpu_bandwidths[last_vote_bw]==sheng_gpu_opps[level].kbps);
    }
    CHECK(sheng_gpu_opps[1].hz==124800000 && sheng_gpu_opps[8].hz==615000000);++checks;
}
}

namespace fencehost {
using IOReturn=int;
constexpr int kIOReturnTimeout=1,kIOReturnNotReady=2;
struct NativeAdrenoAbiWaitFence{uint64_t fence,timeout_ns;};
struct FenceWaiter{uint32_t fence;bool armed;FenceWaiter *next,*prev;};
bool complete,fail_close,complete_in_check,complete_in_sleep;
uint64_t elapsed_us,last_deadline;
unsigned sleeps,polls,locks,held;
IOLock lock;
struct Core{int dispatch(unsigned,const void*,size_t,void*,size_t*,void*){++polls;return complete?0:kIOReturnTimeout;}}core;
struct Connection{bool live_=true;Core *core_=&core;}c;
struct Clock{void *cookie=nullptr;uint64_t (*now_us)(void*)=nullptr;int (*idle)(void*)=nullptr;};
uint64_t time(void*){return elapsed_us;}
int idle(void*){elapsed_us+=100;return 0;}
struct{Clock clock;bool interrupts=true,wake_by_interrupt=true;IOLock *wake_lock=&lock;FenceWaiter *waiters=nullptr;}g;
uint32_t native_adreno_wait_outer[5],native_adreno_fence_wake[8];
bool fencePending(uint64_t){
    if(complete_in_check){complete=true;if(g.waiters)g.waiters->armed=false;}
    return !complete;
}
void lockTimed(unsigned&){++locks;++held;}
void unlockTimed(unsigned&){CHECK(held==1);--held;}
void clock_interval_to_deadline(uint32_t us,uint32_t,uint64_t *out){*out=elapsed_us+us;}
int IOLockSleepDeadline(IOLock*,void *self,uint64_t deadline,int){
    ++sleeps;last_deadline=deadline;
    CHECK(held==0); // never the submission lock across sleep
    if(complete_in_sleep){elapsed_us+=100;complete=true;static_cast<FenceWaiter*>(self)->armed=false;return 0;}
    elapsed_us=deadline;return THREAD_TIMED_OUT;
}
int wait(uint64_t timeout_ns){
    unsigned lockWait=0,method=6;void *output=nullptr;size_t out=0,*output_size=&out;
    NativeAdrenoAbiWaitFence request{1,timeout_ns};const void *input=&request;
    auto *connection=&c;int status=0;
#include "fence.inc"
    return status;
}
void reset(){
    complete=fail_close=complete_in_check=complete_in_sleep=false;elapsed_us=last_deadline=0;sleeps=polls=locks=held=0;
    g.clock={nullptr,time,idle};g.interrupts=true;g.wake_by_interrupt=true;g.waiters=nullptr;c.live_=true;
}
void test(){
    reset();CHECK(wait(0)==kIOReturnTimeout && sleeps==0 && polls==1);++checks;
    reset();complete=true;CHECK(wait(1000000)==0 && sleeps==0 && polls==1);++checks;
    reset();complete_in_check=true;CHECK(wait(1000000)==0 && sleeps==0);++checks;
    reset();complete_in_sleep=true;CHECK(wait(1000000)==0 && sleeps==1 && elapsed_us==100 && last_deadline==1000);++checks;
    reset();CHECK(wait(1000000)==kIOReturnTimeout && elapsed_us==1000 && sleeps==1 && g.waiters==nullptr);++checks;
    reset();g.wake_by_interrupt=false;
    CHECK(wait(1000000)==kIOReturnTimeout && elapsed_us==1000 && sleeps==0);++checks;
    reset();c.live_=false;CHECK(wait(0)==kIOReturnNotReady && sleeps==0);++checks;
    reset();CHECK(wait(999)==kIOReturnTimeout && sleeps==0);++checks;
}
}

namespace ringhost {
#include "idle.inc"
void test(){
    gIrqAttached=true;irq_enabled=true;interrupt_context=false;preemption_level=0;
    gPauseUs=1000;sleep_count=spin_count=0;CHECK(ringIdle(nullptr)==0 && sleep_count==1 && wait_timeout_us==1000);++checks;
    gIrqAttached=false;ringIdle(nullptr);CHECK(spin_count==1);++checks;
    gIrqAttached=true;preemption_level=1;ringIdle(nullptr);CHECK(spin_count==2);++checks;
    preemption_level=0;irq_enabled=false;ringIdle(nullptr);CHECK(spin_count==3);++checks;
    irq_enabled=true;interrupt_context=true;ringIdle(nullptr);CHECK(spin_count==4);++checks;
    interrupt_context=false;
}
}
int main(){test_cpu();gpuhost::test();fencehost::test();ringhost::test();
    CHECK(pdx_performance_samples(0)==0 && pdx_performance_samples(1)==1 && pdx_performance_samples(60)==60 &&
          pdx_performance_samples(61)==60 && pdx_performance_samples(UINT32_MAX)==60);++checks;
    CHECK(pdx_performance_display_powered("D27 requested=0 powered=1 (generation unavailable)",49));
    CHECK(!pdx_performance_display_powered("D27 requested=0 powered=0 (generation unavailable)",49));
    CHECK(!pdx_performance_display_powered("no object",10) && !pdx_performance_display_powered("powered=10 ",12));++checks;
    std::printf("PASS %u checks: official CPU/GPU governor bodies, Sony contact boost, IRQ fence deadline, nonblocking fallback\n",checks);}
