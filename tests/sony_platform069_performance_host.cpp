// SPDX-License-Identifier: BSD-2-Clause-Patent
// Exercises exact compiled069 CPU/GPU/recount bodies with host-only I/O shims.
#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <thread>
#include <vector>
#include "SonyGovernor069.h"
#define CHECK(x) do{if(!(x)){std::fprintf(stderr,"%s:%d %s\n",__FILE__,__LINE__,#x);std::abort();}}while(0)
struct Stop{};
static unsigned checks;
uint64_t now_abs,idle_abs[8];
std::function<void()> on_sleep;
bool sample_valid=true;
unsigned started_threads;
uint64_t mach_absolute_time(){return now_abs;}
void nanoseconds_to_absolutetime(uint64_t n,uint64_t *p){*p=n;}
void absolutetime_to_nanoseconds(uint64_t n,uint64_t *p){*p=n;}
using thread_t=void*;using wait_result_t=int;
constexpr int KERN_SUCCESS=0;
int kernel_thread_start(void(*)(void*,int),void*,thread_t *p){++started_threads;*p=(void*)1;return 0;}
void thread_deallocate(thread_t){}
void IOSleep(unsigned ms){now_abs+=uint64_t(ms)*1000000;if(on_sleep)on_sleep();}
struct IOLock{};
IOLock *IOLockAlloc(){static IOLock lock;return &lock;}
void IOLockLock(IOLock*){}
void IOLockUnlock(IOLock*){}
uint32_t mmio[4][1024];
constexpr unsigned kIOMapAnywhere=1,kIOMapInhibitCache=2;
struct IOMemoryMap{uint32_t *p;uintptr_t getVirtualAddress(){return(uintptr_t)p;}};
struct IODeviceMemory{
    unsigned index;
    static IODeviceMemory *withRange(uint64_t base,uint64_t){
        static IODeviceMemory m[4]={{0},{1},{2},{3}};
        const unsigned i=base==0x17d90000?3:unsigned((base-0x17d91000)/0x1000);CHECK(i<4);return &m[i];
    }
    IOMemoryMap *map(unsigned){static IOMemoryMap m[4];m[index].p=mmio[index];return &m[index];}
    void release(){}
};
struct BootArg{const char *name;unsigned value;};
std::vector<BootArg> args;
bool PE_parse_boot_argn(const char *n,void *p,int bytes){
    for(auto a:args)if(!std::strcmp(a.name,n)){CHECK(bytes==4);std::memcpy(p,&a.value,4);return true;}return false;
}
extern "C"{
volatile uint32_t native_touch_seq,native_touch_count;
volatile uint32_t native_adreno_method_stats[20][4],native_hid_input_events[8];
uint64_t sheng_cpu_idle_mach(int c){return idle_abs[c];}
bool sony069_cpu_idle_sample(unsigned c,uint64_t *stamp,uint64_t *value){
    *stamp=now_abs;*value=idle_abs[c];return sample_valid;
}
}
#include "cpu069.inc"
void reset_cpu(){
    now_abs=0;std::memset(mmio,0,sizeof(mmio));std::memset(idle_abs,0,sizeof(idle_abs));
    gMode=gInit069=0;gLock=nullptr;gCapKHz=gFloorKHz=0;gL3Down069=0;gL3Dcvs069=false;
    gDomain[0]=gDomain[1]=gDomain[2]={};gL3={};
    native_touch_seq=native_touch_count=0;native_cpufreq_boosts=0;
    native_cpufreq_frame[0]=native_cpufreq_frame[1]=0;native_adreno_method_stats[5][0]=0;
    args.clear();on_sleep={};sample_valid=true;started_threads=0;
    for(unsigned d=0;d<4;++d){
        mmio[d][0]=1;
        const unsigned values[]={16,20,26,38,44,49,55,60,66,77,88,94,94};
        for(unsigned i=0;i<13;++i)mmio[d][0x100/4+i]=(1u<<30)|values[i];
        mmio[d][0x320/4]=0x5a;
    }
}
void run_cpu(unsigned windows,unsigned busy,const std::function<void(unsigned)> &change={}){
    unsigned tick=0;on_sleep=[&]{if(++tick>windows)throw Stop{};
        for(auto &idle:idle_abs)idle+=16000000ull*(1000-busy)/1000;
        if(change)change(tick);
    };
    try{governorThread(nullptr,0);}catch(const Stop&){}on_sleep={};
}
void test_cpu(){
    reset_cpu();args={{"cpufreq",1}};sheng_cpufreq_probe();
    for(unsigned i=0;i<3;++i)CHECK(mmio[i][0x320/4]==0x5a);
    CHECK(!gL3.va && started_threads==0);++checks;
    reset_cpu();args={{"cpufreq",4},{"cpufreq-boost-ms",0},{"cpufreq-frame-ms",0}};sheng_cpufreq_probe();
    CHECK(started_threads==1);auto *lock=gLock;const auto floor=gFloorKHz;
    args.push_back({"cpufreq-min",9999});sheng_cpufreq_probe();
    CHECK(started_threads==1 && gLock==lock && gFloorKHz==floor);++checks;
    run_cpu(20,0);CHECK(gDomain[0].votedKHz==307200 && gDomain[1].votedKHz==307200 && gDomain[2].votedKHz==307200);
    CHECK(gL3.votedKHz==307200 && native_cpufreq069_l3[1]>0);++checks;
    reset_cpu();args={{"cpufreq",4},{"cpufreq-boost-ms",0},{"cpufreq-frame-ms",0},{"cpufreq-l3-dcvs",0}};
    sheng_cpufreq_probe();run_cpu(20,0);CHECK(gL3.votedKHz==1804800);++checks;
    reset_cpu();args={{"cpufreq",4},{"cpufreq-boost-ms",0},{"cpufreq-frame-ms",0}};sheng_cpufreq_probe();
    run_cpu(20,0,[](unsigned n){if(n==17){for(auto &v:idle_abs)v-=14400000;}});
    CHECK(gDomain[0].votedKHz==1804800 && gL3.votedKHz>=1689600);++checks;
    // Per-core control mode writes every member of each domain.
    reset_cpu();for(unsigned d=0;d<3;++d)mmio[d][0xb0/4]=1;
    args={{"cpufreq",4},{"cpufreq-boost-ms",0},{"cpufreq-frame-ms",0}};sheng_cpufreq_probe();run_cpu(20,0);
    CHECK(mmio[0][0x324/4]==mmio[0][0x320/4] && mmio[0][0x328/4]==mmio[0][0x320/4]);
    CHECK(mmio[1][0x32c/4]==mmio[1][0x320/4]);++checks;
    reset_cpu();args={{"cpufreq",4},{"cpufreq-frame-ms",0}};sheng_cpufreq_probe();
    run_cpu(100,0,[](unsigned){native_touch_seq=native_touch_seq+2;});
    CHECK(native_cpufreq_boosts==0 && gDomain[1].votedKHz==307200);++checks;
    reset_cpu();args={{"cpufreq",4},{"cpufreq-frame-ms",0}};sheng_cpufreq_probe();
    run_cpu(100,0,[](unsigned n){if(n==20){native_touch_count=1;native_touch_seq=2;}
                               if(n==21){native_touch_count=0;native_touch_seq=4;}});
    CHECK(native_cpufreq_boosts==1 && gDomain[1].votedKHz==307200);++checks;
    reset_cpu();args={{"cpufreq",4},{"cpufreq-boost-ms",0}};sheng_cpufreq_probe();
    run_cpu(40,0,[](unsigned n){if(n==20 || n==22)native_adreno_method_stats[5][0]=native_adreno_method_stats[5][0]+1;});
    CHECK(native_cpufreq_frame[0]==1 && gDomain[0].votedKHz>=1113600);++checks;
    // Disabled cluster prevents reducing the shared L3 floor with unknown state.
    reset_cpu();mmio[1][0]=0;args={{"cpufreq",4},{"cpufreq-boost-ms",0},{"cpufreq-frame-ms",0}};sheng_cpufreq_probe();
    run_cpu(20,0);CHECK(gDomain[1].voted<0 && gL3.votedKHz==1804800);++checks;
    // A malformed/replaced L3 LUT fails closed to the original max-vote path.
    reset_cpu();args={{"cpufreq",4},{"cpufreq-boost-ms",0},{"cpufreq-frame-ms",0}};sheng_cpufreq_probe();
    mmio[3][0x104/4]=(1u<<30)|15;run_cpu(1,0);CHECK(!gL3Dcvs069);++checks;
    reset_cpu();args={{"cpufreq",4},{"cpufreq-boost-ms",0},{"cpufreq-frame-ms",0}};sheng_cpufreq_probe();
    sample_valid=false;run_cpu(4,0);CHECK(gDomain[0].votedKHz==1804800);++checks;
}
void test_helpers(){
    Sony069IdleWindow w;CHECK(w.observe(100,10)==1000);CHECK(w.observe(1100,1010)==0);++checks;
    CHECK(w.observe(2100,1510)==500);CHECK(w.observe(3100,2510)==0);++checks;
    CHECK(w.observe(4100,2510)==1000);++checks;
    CHECK(w.observe(5100,2000)==1000); // backwards does not fake idle
    CHECK(w.observe(6100,5000)==1000); // accumulated idle > measured interval
    CHECK(w.observe(6100,5000)==1000);++checks;
    // A per-CPU timestamp accounts for a sampler delayed between remote reads.
    Sony069IdleWindow delayed;delayed.observe(100,0);
    CHECK(delayed.observe(5100,4000)==200);++checks;
    Sony069TouchSample t;CHECK(t.observe(2,0,2)==0 && t.observe(3,1,3)==0 && t.observe(4,1,6)==0);
    CHECK(t.observe(6,1,6)==1 && t.observe(8,0,8)==2 && t.observe(10,0,10)==2);++checks;
    t.seen=UINT32_MAX-1;CHECK(t.observe(0,1,0)==3);++checks;
    Sony069TouchSample first;CHECK(first.observe(10,1,10)==0 && first.observe(12,1,12)==1);++checks;
    // Actual single-start helper called concurrently, not a mock boolean model.
    uint32_t state=0;std::atomic<unsigned> winners{0};std::vector<std::thread> threads;
    for(unsigned i=0;i<32;++i)threads.emplace_back([&]{if(sony069_start_once(&state))++winners;});
    for(auto &thread:threads)thread.join();CHECK(winners==1 && state==1);++checks;
    for(unsigned d=0;d<3;++d){CHECK(sony069_l3_floor(d,0)==307200);CHECK(sony069_l3_floor(d,UINT32_MAX)==1804800);}
    CHECK(sony069_l3_floor(1,2803200)==1689600 && sony069_l3_floor(0,2016000)==1804800);++checks;
}

namespace gpu_test{
uint64_t busy_ticks;bool pending,vote_fail;std::vector<unsigned> votes;
struct Io{void *cookie=nullptr;int read32(void*,unsigned,size_t,uint32_t*p){*p=0;return 0;}
    int write32(void*,unsigned,size_t,uint32_t){return 0;}int barrier(void*){return 0;}};
using ShengGmuIo=Io;struct{Io io;unsigned hfi;}gColdDevice;
constexpr unsigned ShengGmuCore=0,A740_CP_RB_RPTR=1,A740_CP_RB_WPTR=2;
unsigned kGmuReg(unsigned n){return n*4-0x6a000;}
unsigned bootArg(const char*n,unsigned f){PE_parse_boot_argn(n,&f,4);return f;}
uint64_t gpuBusyTicks(){return busy_ticks;}unsigned gpuRd(unsigned n){return n==A740_CP_RB_WPTR && pending?1:0;}
struct AdrenoHfiBcm{unsigned buswidth,fixed,perfmode,perfmode_kbps;};
#include "ShengGmuVotesSource.h"
#include "vote-index069.inc"
unsigned last_bw;int hfiWait(void*){return 0;}
int AdrenoHfiExchange(unsigned*,unsigned opcode,const uint32_t *v,size_t n,unsigned,int(*)(void*),uint32_t*,unsigned,size_t*c,uint32_t*e){
    CHECK(opcode==30 && n==3 && v[0]==1);votes.push_back(v[1]);last_bw=v[2];*c=0;*e=0;return vote_fail?1:0;
}
void gpuPerfTick(uint64_t){}template<class...T>void boot_latency_record(T...){}
uint32_t native_gpu_perf_vote[2]={1,1};
#include "gpu069.inc"
void reset(){args.clear();now_abs=busy_ticks=0;pending=vote_fail=false;votes.clear();native_gpu_perf_vote[0]=8;
    native_gpu_dcvs[2]=native_gpu_dcvs[3]=native_gpu_dcvs[13]=native_gpu_dcvs[14]=0;
    native_touch_seq=native_touch_count=0;gDcvsInit069=0;started_threads=0;
}
void run(unsigned windows,const std::function<void(unsigned)> &change){unsigned tick=0;
    on_sleep=[&]{if(++tick>windows)throw Stop{};change(tick);};
    try{gpuDcvsThread(nullptr,0);}catch(const Stop&){}on_sleep={};
}
void test(){
    reset();args={{"gpu-dcvs-boost-ms",0}};run(8,[](unsigned){});
    CHECK(native_gpu_dcvs[1]==1 && votes.back()==1 && last_bw==1);++checks;
    reset();args={{"gpu-dcvs-boost-ms",0}};native_gpu_perf_vote[0]=4;run(1,[](unsigned){busy_ticks+=307200;});
    CHECK(native_gpu_dcvs[1]==8 && last_bw==3);++checks;
    reset();run(150,[](unsigned){native_touch_seq=native_touch_seq+2;});
    CHECK(native_gpu_dcvs[13]==0 && native_gpu_dcvs[1]==1);++checks;
    reset();run(100,[](unsigned n){if(n==20){native_touch_count=1;native_touch_seq=2;}
                                if(n==21){native_touch_count=0;native_touch_seq=4;}});
    CHECK(native_gpu_dcvs[13]==1 && native_gpu_dcvs[1]==1);++checks;
    reset();args={{"gpu-dcvs-boost-ms",0}};run(10,[](unsigned n){if(n==10){pending=true;busy_ticks+=19200;}});
    CHECK(native_gpu_dcvs[14]==1 && native_gpu_dcvs[1]==8);++checks;
    reset();args={{"gpu-dcvs-boost-ms",0}};native_gpu_perf_vote[0]=4;vote_fail=true;
    run(1,[](unsigned){busy_ticks+=307200;});CHECK(native_gpu_dcvs[3]==1 && native_gpu_dcvs[1]==4);++checks;
    reset();args={{"gpu-dcvs-boost-ms",0},{"gpu-dcvs-idle-min",4}};run(8,[](unsigned){});
    CHECK(native_gpu_dcvs[1]==4 && last_bw==2);++checks;
    reset();args={{"gpu-dcvs-boost-ms",0},{"gpu-dcvs-idle-min",999}};run(8,[](unsigned){});
    CHECK(native_gpu_dcvs[1]==4);++checks;
    reset();args={{"gpu-dcvs-boost-ms",0},{"gpu-dcvs-span",999}};run(24,[](unsigned n){if(n%4==0)busy_ticks+=19200;});
    CHECK(native_gpu_dcvs_windows[7]==8 && native_gpu_dcvs[1]>=1 && native_gpu_dcvs[1]<=8);++checks;
    reset();startGpuDcvs();startGpuDcvs();CHECK(started_threads==1);++checks;
    for(unsigned l=1;l<SHENG_GPU_OPPS;++l){CHECK(gpuVote(l));CHECK(sheng_gpu_bandwidths[last_bw]==sheng_gpu_opps[l].kbps);}++checks;
}
}
int main(){test_helpers();test_cpu();gpu_test::test();
    std::printf("PASS %u exact069 governor, L3, idle snapshot window, boost, HFI bandwidth and concurrent-init checks\n",checks);}
