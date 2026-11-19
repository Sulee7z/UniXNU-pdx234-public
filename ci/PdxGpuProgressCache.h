// SPDX-License-Identifier: MIT
// Nonblocking GPU queries belong to the monitor worker, outside render_busy.
// Each field group is a sequential sample; fence/preemption epochs may differ.
extern bool native_adreno_fences_detail(uint32_t *,uint32_t *,uint32_t *) __attribute__((weak_import));
extern bool native_adreno_preempt_stats(uint32_t *) __attribute__((weak_import));
struct pdx_gpu_progress {uint64_t ns;uint32_t issued,done,rings[3],preempt[26];unsigned fence_ok,preempt_ok;};
static struct pdx_gpu_progress pdx_gpu_progress_cache[3];
static unsigned pdx_gpu_progress_lock,pdx_gpu_progress_count,pdx_gpu_progress_missed;
static uint64_t pdx_gpu_progress_last;
static void pdx_gpu_progress_poll(void) {
  static int enabled=-1;
  if(enabled<0){unsigned value=0;PE_parse_boot_argn("first-frame-diag",&value,sizeof value);enabled=value==1;}
  if(!enabled)return;
  uint64_t now=0;absolutetime_to_nanoseconds(mach_absolute_time(),&now);
  if(pdx_gpu_progress_last && now-pdx_gpu_progress_last<500000000ULL)return;
  pdx_gpu_progress_last=now;
  struct pdx_gpu_progress sample;memset(&sample,0,sizeof sample);sample.ns=now;
  if(native_adreno_fences_detail)sample.fence_ok=native_adreno_fences_detail(&sample.issued,&sample.done,sample.rings);
  if(native_adreno_preempt_stats)sample.preempt_ok=native_adreno_preempt_stats(sample.preempt);
  if(__atomic_exchange_n(&pdx_gpu_progress_lock,1,__ATOMIC_ACQUIRE)){++pdx_gpu_progress_missed;return;}
  pdx_gpu_progress_cache[pdx_gpu_progress_count%3]=sample;++pdx_gpu_progress_count;
  __atomic_store_n(&pdx_gpu_progress_lock,0,__ATOMIC_RELEASE);
}
static int pdx_gpu_progress_rows(char rows[9][48]) {
  if(__atomic_exchange_n(&pdx_gpu_progress_lock,1,__ATOMIC_ACQUIRE))return 0;
  uint64_t now=0;absolutetime_to_nanoseconds(mach_absolute_time(),&now);
  const unsigned count=pdx_gpu_progress_count<3?pdx_gpu_progress_count:3;
  memset(rows,0,9*48);
  for(unsigned i=0;i<count;++i) {
    const struct pdx_gpu_progress *s=&pdx_gpu_progress_cache[(pdx_gpu_progress_count-count+i)%3];
    uint64_t age=now>=s->ns?(now-s->ns)/1000000:0;
    if(age>UINT32_MAX)age=UINT32_MAX;
    snprintf(rows[i*3],48,"G%u age%ums F%u:%u i%x d%x",i,(unsigned)age,s->fence_ok,s->rings[2],s->issued,s->done);
    snprintf(rows[i*3+1],48,"G%u r%x/%x P%u L%u F%u C%x",i,s->rings[0],s->rings[1],s->preempt_ok,s->preempt[7],s->preempt[8],s->preempt[9]);
    snprintf(rows[i*3+2],48,"G%u sw%x/%x err%x dead%x",i,s->preempt[0],s->preempt[1],s->preempt[3],s->preempt[16]);
  }
  if(!count)snprintf(rows[0],48,"GP no worker sample yet");
  __atomic_store_n(&pdx_gpu_progress_lock,0,__ATOMIC_RELEASE);return 1;
}
