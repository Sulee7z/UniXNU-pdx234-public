"""Narrow, hash-bound corrections over the active006 official CPU/GPU source copies."""
from pathlib import Path
import hashlib

CPU_006='d08f1fe6da9bb5d3f9e6791977c0ac83d221d9c3d47679fccb11860ef71e273f'
GPU_006='47da59b25a55c9de0dc64425f3490079a121bc452069057b89c823fc30ca28d6'


def sha(p):
    with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def once(text,old,new):
    if text.count(old)!=1:raise ValueError('Selected069 source anchor differs: '+old[:100])
    return text.replace(old,new)


def touch_local(text):
    text=once(text,'#include "SonyPerformanceTouch.h"','#include "SonyTouchBoost069.h"')
    text=text.replace('pdx_performance_touch_sequence()','sony069_touch_sequence(touchSample)')
    return once(text,'    uint32_t touches = sony069_touch_sequence(touchSample);',
                '    Sony069TouchSample touchSample;\n    uint32_t touches = sony069_touch_sequence(touchSample);')


def cpu(text):
    if hashlib.sha256(text.encode()).hexdigest()!=CPU_006:raise ValueError('CPU006 copy changed')
    text=touch_local(text)
    text=once(text,'IOLock *gLock;', '''IOLock *gLock;
uint32_t gInit069;
bool gL3Dcvs069;
unsigned gL3Down069;
#include "SonyMemlatMap069.h"
extern "C" bool sony069_cpu_idle_sample(unsigned,uint64_t *,uint64_t *);
extern "C" {volatile uint32_t native_cpufreq069_l3[4],native_cpufreq069_sample[3];}
''')
    # No new PSCI/WFI/suspend operation. A native helper samples the existing
    # recount idle accumulator under its new small per-CPU sequence lock.
    text=once(text,'''    uint64_t lastIdle[kCpus] = {}, lastT = mach_absolute_time();
    for (unsigned c = 0; c < kCpus; ++c) lastIdle[c] = sheng_cpu_idle_mach((int)c);''',
'''    Sony069IdleWindow idleWindows[kCpus];
    uint64_t lastT = mach_absolute_time();
    for (unsigned c=0;c<kCpus;++c) {
        uint64_t idle=0,t=0;
        if(sony069_cpu_idle_sample(c,&t,&idle))idleWindows[c].observe(t,idle);
    }''')
    text=once(text,'''            const uint64_t idle = sheng_cpu_idle_mach((int)c), di = idle - lastIdle[c];
            lastIdle[c] = idle;
            const uint64_t b = di >= dt ? 0 : (dt - di) * 1000 / dt;''',
'''            uint64_t idle=0,sampleT=0;
            const bool valid=sony069_cpu_idle_sample(c,&sampleT,&idle);
            const uint64_t b=valid?idleWindows[c].observe(sampleT,idle):idleWindows[c].busy;
            native_cpufreq069_sample[valid?0:1]=native_cpufreq069_sample[valid?0:1]+1;''')
    # Raise L3 before a CPU vote. Fall back to the already-existing highest vote
    # on unknown table/readback/disabled domain, never create an unvalidated row.
    anchor='void setLevel(unsigned d, unsigned at) {'
    l3='''unsigned l3Level069(uint32_t khz) {
    if(!gL3.va || !(rd32(gL3.va,kRegEnable)&1))return kLutEntries;
    uint32_t prev=0;unsigned selected=kLutEntries;
    for(unsigned i=0;i<kLutEntries;++i) {
        const uint32_t f=lutKHz(rd32(gL3.va,kRegFreqLut+4*i));
        if(!f || (i && f<prev))return kLutEntries;
        if(i && f==prev)return selected;
        if(selected==kLutEntries && f>=khz)selected=i;
        prev=f;
    }
    return kLutEntries;
}
void l3Write069(unsigned at) {
    if(at>=kLutEntries)return;
    wr32(gL3.va,kRegL3Vote,at);
    if(rd32(gL3.va,kRegL3Vote)!=at){gL3Dcvs069=false;voteL3();return;}
    gL3.voted=(int)at;gL3.votedKHz=lutKHz(rd32(gL3.va,kRegFreqLut+4*at));
    native_cpufreq069_l3[0]=gL3.votedKHz;native_cpufreq069_l3[1]=native_cpufreq069_l3[1]+1;
}
void l3Floor069(unsigned d,uint32_t cpuKHz) {
    if(!gL3Dcvs069 || gMode!=4)return;
    const unsigned at=l3Level069(sony069_l3_floor(d,cpuKHz));
    if(at>=kLutEntries){gL3Dcvs069=false;voteL3();return;}
    const uint32_t khz=lutKHz(rd32(gL3.va,kRegFreqLut+4*at));
    if(gL3.voted<0 || khz>gL3.votedKHz){l3Write069(at);gL3Down069=0;}
}
void l3Relax069() {
    if(!gL3Dcvs069 || gMode!=4)return;
    uint32_t khz=0;
    for(unsigned d=0;d<3;++d) {
        if(!gDomain[d].va || gDomain[d].voted<0 || !(rd32(gDomain[d].va,kRegEnable)&1))return;
        const uint32_t need=sony069_l3_floor(d,gDomain[d].votedKHz);
        if(need>khz)khz=need;
    }
    const unsigned at=l3Level069(khz);
    if(at>=kLutEntries){gL3Dcvs069=false;voteL3();return;}
    const uint32_t need=lutKHz(rd32(gL3.va,kRegFreqLut+4*at));
    if(need<gL3.votedKHz){if(++gL3Down069>=4){l3Write069(at);gL3Down069=0;}}
    else {gL3Down069=0;if(need>gL3.votedKHz)l3Write069(at);}
}
'''
    text=once(text,anchor,l3+anchor)
    text=once(text,'''    const uint32_t level = gLevels[d].index[at];
    wr32''','''    const uint32_t level = gLevels[d].index[at];
    l3Floor069(d,gLevels[d].khz[at]);
    wr32''')
    text=once(text,'''        IOLockUnlock(gLock);
        if (native_cpufreq_rec *ring''','''        l3Relax069();
        IOLockUnlock(gLock);
        if (native_cpufreq_rec *ring''')
    # A CAS is before ALL live-global assignments. Release-publish mode only
    # after maps/configuration are complete; poll ignores in-progress setup.
    text=once(text,'''    if (!gMode || !gLock) return;''',
'''    if(__atomic_load_n(&gInit069,__ATOMIC_ACQUIRE)!=2 || !gMode || !gLock)return;''')
    text=once(text,'''extern "C" void sheng_cpufreq_probe(void) {
    unsigned mode''','''extern "C" void sheng_cpufreq_probe(void) {
    if(!sony069_start_once(&gInit069))return;
    unsigned mode''')
    text=once(text,'''    gBoostMs = boostMs;''','''    unsigned l3Dcvs=1;PE_parse_boot_argn("cpufreq-l3-dcvs",&l3Dcvs,sizeof(l3Dcvs));
    gL3Dcvs069=l3Dcvs==1;
    gBoostMs = boostMs;''')
    text=once(text,'''    if (!mode || gLock) return;''','''    if(!mode){__atomic_store_n(&gInit069,3u,__ATOMIC_RELEASE);return;}''')
    text=once(text,'''    if (!gLock) return;''','''    if(!gLock){__atomic_store_n(&gInit069,3u,__ATOMIC_RELEASE);return;}''')
    text=once(text,'''    gMode = mode;
    sheng_cpufreq_poll();''','''    gMode = mode;
    __atomic_store_n(&gInit069,2u,__ATOMIC_RELEASE);
    sheng_cpufreq_poll();''')
    return text


def gpu(text):
    if hashlib.sha256(text.encode()).hexdigest()!=GPU_006:raise ValueError('GPU006 copy changed')
    text=touch_local(text)
    text=once(text,'unsigned span = bootArg("gpu-dcvs-span", 1);','unsigned span = bootArg("gpu-dcvs-span", 3);')
    # Retain active-work 348MHz floor and boost, but do not keep its DDR vote
    # while the existing official 80ms inactivity test already reports rest.
    text=once(text,'    if (floor > kGpuTop) floor = kGpuTop;',
'''    if (floor > kGpuTop) floor = kGpuTop;
    unsigned idleFloor=bootArg("gpu-dcvs-idle-min",1);
    if(idleFloor<1)idleFloor=1;
    if(idleFloor>floor)idleFloor=floor;''')
    text=once(text,'if (quiet >= 80000000ull) {want = floor;reason = 4;rested = true;}',
                'if (quiet >= 80000000ull) {want = idleFloor;reason = 4;rested = true;}')
    text=once(text,'        if (want < floor) {want = floor;reason = 7;}',
'''        const unsigned effectiveFloor=(rested && t>=touchEnd && t>=wakeEnd)?idleFloor:floor;
        if(want<effectiveFloor){want=effectiveFloor;reason=7;}''')
    text=once(text,'''void startGpuDcvs() {
    thread_t thread''','''uint32_t gDcvsInit069;
void startGpuDcvs() {
    if(!sony069_start_once(&gDcvsInit069))return;
    thread_t thread''')
    text=once(text,'''extern "C" void sheng_gpu_power_probe(void) {
    unsigned mode''','''uint32_t gGpuInit069;
extern "C" void sheng_gpu_power_probe(void) {
    if(!sony069_start_once(&gGpuInit069))return;
    unsigned mode''')
    return text


def recount_selected(text):
    # Applied after the existing063 sparse-kind-span repair. No struct layout,
    # exported Apple recount API or idle/run accounting arithmetic is changed.
    text=once(text,'#define RCT_PR_IDLING (0x1ULL << 63)', '''#define RCT_PR_IDLING (0x1ULL << 63)
static uint32_t sony069_idle_seq[MAX_CPUS];
static uint32_t *sony069_sequence(struct recount_processor *pr) {
    processor_t p=(processor_t)((uintptr_t)pr-__builtin_offsetof(struct processor,pr_recount));
    return p->cpu_id>=0 && p->cpu_id<MAX_CPUS?&sony069_idle_seq[p->cpu_id]:NULL;
}
''')
    for name in ('idle','run'):
        anchor='recount_processor_'+name+'(struct recount_processor *pr, struct recount_snap *snap)\n{'
        text=once(text,anchor,anchor+'''
	uint32_t *seq069=sony069_sequence(pr);
	if(seq069)__atomic_fetch_add(seq069,1u,__ATOMIC_ACQ_REL);''')
    text=once(text,'''\tos_atomic_inc(&pr->rpr_idle_count, relaxed);
}''','''\tos_atomic_inc(&pr->rpr_idle_count, relaxed);
	if(seq069)__atomic_fetch_add(seq069,1u,__ATOMIC_RELEASE);
}''')
    text=once(text,'''\tos_atomic_store_wide(&pr->rpr_state_last_abs_time, new_state_stamp,
\t    relaxed);
}

void
recount_processor_online''','''\tos_atomic_store_wide(&pr->rpr_state_last_abs_time, new_state_stamp,
\t    relaxed);
	if(seq069)__atomic_fetch_add(seq069,1u,__ATOMIC_RELEASE);
}

void
recount_processor_online''')
    text+='''
/* Remote governor snapshot: a run transition updates accumulator then state.
 * Without its sequence, a reader can combine the OLD accumulator with the NEW
 * running stamp (lost idle), or the NEW accumulator with OLD idling stamp
 * (double idle). Keep the original public recount ABI/arithmetic untouched. */
bool sony069_cpu_idle_sample(unsigned cpu,uint64_t *stamp,uint64_t *idle);
bool sony069_cpu_idle_sample(unsigned cpu,uint64_t *stamp,uint64_t *idle) {
    if(cpu>=MAX_CPUS || !stamp || !idle)return false;
    processor_t p=cpu_to_processor((int)cpu);
    if(p==PROCESSOR_NULL)return false;
    for(unsigned tries=0;tries<4;++tries) {
        const uint32_t before=__atomic_load_n(&sony069_idle_seq[cpu],__ATOMIC_ACQUIRE);
        if(before&1u)continue;
        uint64_t sum=__atomic_load_n(&p->pr_recount.rpr_idle_time_mach,__ATOMIC_RELAXED);
        const uint64_t state=os_atomic_load_wide(&p->pr_recount.rpr_state_last_abs_time,relaxed);
        const uint64_t now=mach_absolute_time();
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if(before!=__atomic_load_n(&sony069_idle_seq[cpu],__ATOMIC_ACQUIRE))continue;
        if((state&RCT_PR_IDLING) && _state_time(state)>now)return false;
        if(state&RCT_PR_IDLING)sum+=now-_state_time(state);
        *stamp=now;*idle=sum;return true;
    }
    return false;
}
'''
    return text


def adapt_recount(text):
    from recount_cpu_kinds import adapt_source
    return recount_selected(adapt_source(text))


ADAPTERS={'recount-sparse-cpu-kind-span':adapt_recount}
