// SPDX-License-Identifier: MIT
// Reuse the bounded process sampler's copies. No extra task/VM collection.
extern uint64_t native_gpu_role_thread(uint32_t,uint32_t) __attribute__((weak_import));
struct pdx_render_sample {struct bt_entry entry;uint64_t tid;unsigned slide,state;int priority;};
static struct pdx_render_sample pdx_render_draft[3],pdx_render_published[3];
static void pdx_render_begin(void) {memset(pdx_render_draft,0,sizeof pdx_render_draft);}
static void pdx_render_collect(unsigned role,int pid,unsigned slide,unsigned count) {
  if(role || !native_gpu_role_thread)return;
  for(unsigned r=0;r<3;++r) {
    const uint64_t tid=native_gpu_role_thread((uint32_t)pid,r+1);
    if(!tid)continue;
    for(unsigned i=0;i<count;++i)if(sample_tid[i]==tid) {
      struct pdx_render_sample *out=&pdx_render_draft[r];
      out->entry=samples[i];out->tid=tid;out->slide=slide;
      out->state=sample_state[i];out->priority=sample_pri[i];break;
    }
  }
}
// The caller holds trace_lock, as it does for the ordinary published stacks.
static void pdx_render_publish(void) {memcpy(pdx_render_published,pdx_render_draft,sizeof pdx_render_draft);}
int pdx_render_thread_rows(char rows[9][48]) {
  if(__atomic_exchange_n(&trace_lock,1,__ATOMIC_ACQUIRE))return 0;
  memset(rows,0,9*48);
  for(unsigned r=0;r<3;++r) {
    const struct pdx_render_sample *s=&pdx_render_published[r];
    if(!s->tid) {snprintf(rows[r*3],48,"RT%u target not recorded",r+1);rows[r*3+1][0]=rows[r*3+2][0]=0;continue;}
    snprintf(rows[r*3],48,"RT%u tid=%llx st=%x pri=%d",r+1,(unsigned long long)s->tid,s->state,s->priority);
    snprintf(rows[r*3+1],48,"RT%u pc=%llx cache+=%x",r+1,(unsigned long long)s->entry.pc,s->slide);
    snprintf(rows[r*3+2],48,"RT%u lr=%llx f1=%llx",r+1,(unsigned long long)s->entry.lr,(unsigned long long)s->entry.frames[0]);
  }
  __atomic_store_n(&trace_lock,0,__ATOMIC_RELEASE);return 1;
}
