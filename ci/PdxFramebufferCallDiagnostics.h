// SPDX-License-Identifier: MIT
// Source-level call boundary; no vtable interposition or user-memory traversal.
// Buffers passed by the native IOUserClient dispatcher are kernel buffers.
extern volatile uint64_t native_legacy_object __attribute__((weak_import));
enum {PDX_MFB_CALLS=64,PDX_MFB_SELECTORS=101};
struct pdx_mfb_call {
  uint64_t token,us,client,provider,input[3],output[2],in_bytes,out_bytes;
  uint32_t pid,selector,in_count,out_count,requested,powered;
  int32_t status;unsigned ended,state_valid;
};
static struct pdx_mfb_call pdx_mfb_calls[PDX_MFB_CALLS],pdx_mfb_first_failure,pdx_mfb_first_submit;
static struct {uint32_t calls,failures,status;} pdx_mfb_selectors[PDX_MFB_SELECTORS];
static uint64_t pdx_mfb_issued,pdx_mfb_ended,pdx_mfb_failed;
static unsigned pdx_mfb_lock,pdx_mfb_dropped;
static void pdx_mfb_state(struct pdx_mfb_call *call) {
  call->state_valid=0;
  if(&native_legacy_object && native_legacy_object && call->provider==native_legacy_object) {
    const unsigned char *object=(const unsigned char *)(uintptr_t)call->provider;
    memcpy(&call->requested,object+7180,4);memcpy(&call->powered,object+7184,4);call->state_valid=1;
  }
}
uint64_t pdx_framebuffer_call_begin(const void *client,const void *provider,uint32_t selector,
    uint32_t scalar_count,const uint64_t *scalars,uint64_t input_bytes,uint64_t output_bytes,uint32_t output_count) {
  if(__atomic_exchange_n(&pdx_mfb_lock,1,__ATOMIC_ACQUIRE)){__atomic_fetch_add(&pdx_mfb_dropped,1,__ATOMIC_RELAXED);return 0;}
  const uint64_t token=++pdx_mfb_issued;struct pdx_mfb_call *call=&pdx_mfb_calls[(token-1)%PDX_MFB_CALLS];
  memset(call,0,sizeof(*call));call->token=token;call->client=(uint64_t)(uintptr_t)client;call->provider=(uint64_t)(uintptr_t)provider;
  uint64_t ns=0;absolutetime_to_nanoseconds(mach_absolute_time(),&ns);call->us=ns/1000;
  call->pid=(uint32_t)proc_selfpid();call->selector=selector;call->in_count=scalar_count;call->out_count=output_count;
  call->in_bytes=input_bytes;call->out_bytes=output_bytes;call->status=-1;
  if(scalars)for(unsigned i=0;i<3 && i<scalar_count;++i)call->input[i]=scalars[i];
  pdx_mfb_state(call);
  if(selector<PDX_MFB_SELECTORS)++pdx_mfb_selectors[selector].calls;
  if(selector==5 && !pdx_mfb_first_submit.token)pdx_mfb_first_submit=*call;
  __atomic_store_n(&pdx_mfb_lock,0,__ATOMIC_RELEASE);return token;
}
void pdx_framebuffer_call_end(uint64_t token,int32_t status,uint32_t output_count,const uint64_t *outputs,uint64_t output_bytes) {
  if(!token)return;
  if(__atomic_exchange_n(&pdx_mfb_lock,1,__ATOMIC_ACQUIRE)){__atomic_fetch_add(&pdx_mfb_dropped,1,__ATOMIC_RELAXED);return;}
  struct pdx_mfb_call *call=&pdx_mfb_calls[(token-1)%PDX_MFB_CALLS];
  if(call->token!=token || call->ended){__atomic_fetch_add(&pdx_mfb_dropped,1,__ATOMIC_RELAXED);__atomic_store_n(&pdx_mfb_lock,0,__ATOMIC_RELEASE);return;}
  call->status=status;call->ended=1;call->out_count=output_count;call->out_bytes=output_bytes;
  if(!status && outputs)for(unsigned i=0;i<2 && i<output_count;++i)call->output[i]=outputs[i];
  ++pdx_mfb_ended;if(status)++pdx_mfb_failed;
  if(call->selector<PDX_MFB_SELECTORS) {
    pdx_mfb_selectors[call->selector].status=(uint32_t)status;
    if(status)++pdx_mfb_selectors[call->selector].failures;
  }
  if(status && !pdx_mfb_first_failure.token)pdx_mfb_first_failure=*call;
  if(token==pdx_mfb_first_submit.token)pdx_mfb_first_submit=*call;
  __atomic_store_n(&pdx_mfb_lock,0,__ATOMIC_RELEASE);
}
static int pdx_framebuffer_call_rows(unsigned now,char rows[9][48]) {
  if(__atomic_exchange_n(&pdx_mfb_lock,1,__ATOMIC_ACQUIRE))return 0;
  struct pdx_mfb_call call={0};unsigned kind=(now/24)%3;
  if(kind==0)call=pdx_mfb_first_failure;
  else if(kind==1)call=pdx_mfb_first_submit;
  else if(pdx_mfb_issued)call=pdx_mfb_calls[(pdx_mfb_issued-1)%PDX_MFB_CALLS];
  const uint64_t issued=pdx_mfb_issued,ended=pdx_mfb_ended,failed=pdx_mfb_failed;
  const unsigned dropped=__atomic_load_n(&pdx_mfb_dropped,__ATOMIC_RELAXED);
  uint32_t calls[5],failures[5];const unsigned selectors[5]={3,5,6,72,74};
  for(unsigned i=0;i<5;++i){calls[i]=pdx_mfb_selectors[selectors[i]].calls;failures[i]=pdx_mfb_selectors[selectors[i]].failures;}
  __atomic_store_n(&pdx_mfb_lock,0,__ATOMIC_RELEASE);
  memset(rows,0,9*48);
  snprintf(rows[0],48,"FB hex calls=%llx done=%llx fail=%llx",(unsigned long long)issued,(unsigned long long)ended,(unsigned long long)failed);
  snprintf(rows[1],48,"FB3 %x/%x 5 %x/%x 6 %x/%x",calls[0],failures[0],calls[1],failures[1],calls[2],failures[2]);
  snprintf(rows[2],48,"FB72 %x/%x 74 %x/%x drop=%u",calls[3],failures[3],calls[4],failures[4],dropped);
  if(!call.token){snprintf(rows[3],48,"FB %s not recorded",kind==0?"first failure":kind==1?"first submit":"last call");return 1;}
  snprintf(rows[3],48,"FB%s id=%llx pid=%u s=%u",kind==0?"FAIL":kind==1?"SUB":"LAST",(unsigned long long)call.token,call.pid,call.selector);
  snprintf(rows[4],48,"FB ended=%u st=%x state%u req%x pwr%x",call.ended,(unsigned)call.status,call.state_valid,call.requested,call.powered);
  snprintf(rows[5],48,"FB hex input=%llx output=%llx",(unsigned long long)call.in_bytes,(unsigned long long)call.out_bytes);
  snprintf(rows[6],48,"FB scalars %u/%u x0=%llx",call.in_count,call.out_count,(unsigned long long)call.input[0]);
  snprintf(rows[7],48,"FB x1=%llx x2=%llx",(unsigned long long)call.input[1],(unsigned long long)call.input[2]);
  snprintf(rows[8],48,"FB y0=%llx y1=%llx",(unsigned long long)call.output[0],(unsigned long long)call.output[1]);return 1;
}
