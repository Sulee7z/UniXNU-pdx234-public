// SPDX-License-Identifier: BSD-2-Clause-Patent
// Verbatim active and069 recount functions with deterministic transition races.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#define CHECK(x) do{if(!(x)){std::fprintf(stderr,"%d %s\n",__LINE__,#x);std::abort();}}while(0)
#define MAX_CPUS 8
#define __assert_only
#define OS_PURE
#define OS_ALWAYS_INLINE
#define relaxed __ATOMIC_RELAXED
#define assert CHECK
struct recount_snap{uint64_t rsn_time_mach;};
struct recount_usage{};
struct recount_processor{uint64_t rpr_idle_time_mach=0,rpr_state_last_abs_time=0,rpr_idle_count=0;unsigned rpr_active=0;};
struct processor{int cpu_id;recount_processor pr_recount;};
using processor_t=processor*;
#define PROCESSOR_NULL nullptr
processor cpus[8];uint64_t now_abs;
uint64_t mach_absolute_time(){return now_abs;}
processor_t cpu_to_processor(int c){return c>=0 && c<8?&cpus[c]:nullptr;}
unsigned recount_processor_plan;
void recount_sum(unsigned*,unsigned*,recount_usage*){}
void _fix_time_precision(recount_usage*){}
void recount_processor_run(recount_processor*,recount_snap*);
bool inject_run;
uint64_t load_state(uint64_t *p){
    if(inject_run){inject_run=false;recount_snap snap{200};recount_processor_run(&cpus[0].pr_recount,&snap);}
    return __atomic_load_n(p,__ATOMIC_RELAXED);
}
#define os_atomic_load_wide(p,order) load_state(p)
#define os_atomic_store_wide(p,v,order) __atomic_store_n(p,v,order)
#define os_atomic_inc(p,order) __atomic_fetch_add(p,1,order)
#include "recount069.inc"
#include "recount-old-usage.inc"
void reset(){
    for(unsigned c=0;c<8;++c){cpus[c]={int(c),{}};sony069_idle_seq[c]=0;}
    now_abs=0;inject_run=false;
}
int main(){unsigned tests=0;uint64_t stamp,idle;
    reset();recount_snap run{1};recount_processor_run(&cpus[0].pr_recount,&run);
    recount_snap start{100};recount_processor_idle(&cpus[0].pr_recount,&start);now_abs=300;
    CHECK(sony069_cpu_idle_sample(0,&stamp,&idle) && stamp==300 && idle==201);++tests;
    recount_snap end{400};recount_processor_run(&cpus[0].pr_recount,&end);now_abs=500;
    CHECK(sony069_cpu_idle_sample(0,&stamp,&idle) && idle==301 && stamp==500);++tests;
    CHECK(sony069_idle_seq[0]==6 && !(sony069_idle_seq[0]&1u));++tests;
    reset();recount_processor_idle(&cpus[0].pr_recount,&start);now_abs=300;inject_run=true;
    recount_usage usage;uint64_t old=999;old_recount_processor_usage(&cpus[0].pr_recount,&usage,&old);
    CHECK(old==0); // actual old body combines OLD sum with NEW running stamp
    CHECK(cpus[0].pr_recount.rpr_idle_time_mach==100);++tests;
    reset();recount_processor_idle(&cpus[0].pr_recount,&start);now_abs=300;inject_run=true;
    CHECK(sony069_cpu_idle_sample(0,&stamp,&idle) && idle==100);++tests;
    sony069_idle_seq[0]|=1;CHECK(!sony069_cpu_idle_sample(0,&stamp,&idle));++tests;
    sony069_idle_seq[0]++;cpus[0].pr_recount.rpr_state_last_abs_time=RCT_PR_IDLING|1000;now_abs=500;
    CHECK(!sony069_cpu_idle_sample(0,&stamp,&idle));++tests;
    CHECK(!sony069_cpu_idle_sample(8,&stamp,&idle) && !sony069_cpu_idle_sample(0,nullptr,&idle));++tests;
    reset();cpus[1].pr_recount.rpr_idle_time_mach=1234;now_abs=600;
    CHECK(sony069_cpu_idle_sample(1,&stamp,&idle) && idle==1234 && sony069_idle_seq[0]==0);++tests;
    std::printf("PASS %u exact recount idle/run/sample checks including old lost-idle negative control\n",tests);
}
