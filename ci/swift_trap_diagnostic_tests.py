#!/usr/bin/env python3
"""Exercise the exact Swift collector and adapted exit functions under ASan/UBSan.

No native kernel build or device action. The host reader models bounded copyin;
the return-address callback models normalization and does not execute ARM PAC.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
import swift_trap_diagnostic as overlay


PRELUDE = r'''
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
'''

FIXTURE = r'''
enum {STACK_BYTES=2048,MAX_QUERIES=16};
static const char fatal_prefix[]="Can't create CHSIntentReference from ";
static const uint64_t code_address=UINT64_C(0x184516f54),stack_address=UINT64_C(0x100800000);
static const uint64_t heap_address=UINT64_C(0x120000000),signed_return=UINT64_C(0xacbd00a18e3b0b14);
struct query {uint64_t address;size_t bytes;};
struct fixture {
  struct pdx_swift_snapshot snapshot;
  unsigned char code[4],stack[STACK_BYTES],*heap;
  size_t heap_bytes;
  unsigned reads,strips,fail_read,partial_fail;
  size_t copied,max_read;
  struct query queries[MAX_QUERIES];
};
static unsigned cases;
static void put_word(struct fixture *f,uint64_t address,uint64_t value) {
  assert(address>=stack_address && address-stack_address<=STACK_BYTES-8);
  memcpy(f->stack+(size_t)(address-stack_address),&value,8);
}
static void fixture_init(struct fixture *f,unsigned bytes) {
  memset(f,0,sizeof(*f));
  f->snapshot.valid=1;f->snapshot.signal=5;f->snapshot.ordinary_exit=1;
  f->snapshot.pid=f->snapshot.exit_pid=f->snapshot.current_pid=56;
  f->snapshot.thread_id=f->snapshot.current_thread_id=UINT64_C(0x123456789);
  f->snapshot.slide=UINT64_C(0x263c000);f->snapshot.pc=code_address;
  f->snapshot.sp=stack_address+0xe0;f->snapshot.fp=stack_address+0x100;
  f->snapshot.esr=PDX_SWIFT_TRAP_ESR;f->snapshot.x20=stack_address+0x280-0x68;
  f->snapshot.x21=UINT64_C(0x133445560);f->snapshot.user_limit=UINT64_C(0x100000000000000);
  uint32_t instruction=UINT32_C(0xd4200020);memcpy(f->code,&instruction,4);
  put_word(f,f->snapshot.fp,stack_address+0x280);
  put_word(f,f->snapshot.fp+8,signed_return);put_word(f,f->snapshot.fp+16,58);
  // Only the low 32 bits of flags are supplied by the original caller.
  put_word(f,f->snapshot.fp+24,UINT64_C(0xaabbccdd00000000));
  put_word(f,stack_address+0x280,stack_address+0x380);
  put_word(f,stack_address+0x288,UINT64_C(0xddeeff018e3d0e7c));
  put_word(f,stack_address+0x210,f->snapshot.x21);
  put_word(f,stack_address+0x218,UINT64_C(0xf000000000000000)|bytes);
  put_word(f,stack_address+0x220,heap_address);
  f->heap_bytes=32+(size_t)bytes;
  f->heap=(unsigned char *)malloc(f->heap_bytes);assert(f->heap);
  memset(f->heap,0xcc,32);memset(f->heap+32,'x',bytes);
  if(bytes>=sizeof(fatal_prefix)-1)memcpy(f->heap+32,fatal_prefix,sizeof(fatal_prefix)-1);
}
static void fixture_destroy(struct fixture *f) {free(f->heap);f->heap=NULL;}
static int copy_model(void *context,uint64_t address,void *out,size_t bytes) {
  struct fixture *f=(struct fixture *)context;
  // The collector must never hold the RAM cache guard during copyin.
  assert(!__atomic_load_n(&pdx_swift_cache_lock,__ATOMIC_RELAXED));
  assert(f->reads<MAX_QUERIES && bytes<=PDX_SWIFT_MESSAGE_BYTES);
  f->queries[f->reads].address=address;f->queries[f->reads].bytes=bytes;
  ++f->reads;f->copied+=bytes;if(bytes>f->max_read)f->max_read=bytes;
  if(f->reads==f->fail_read) {
    if(f->partial_fail && bytes)memset(out,'!',bytes/2);
    return 14;
  }
  const unsigned char *data=NULL;size_t length=0;uint64_t start=0;
  if(address>=code_address && address-code_address<sizeof(f->code)){data=f->code;length=sizeof(f->code);start=code_address;}
  else if(address>=stack_address && address-stack_address<sizeof(f->stack)){data=f->stack;length=sizeof(f->stack);start=stack_address;}
  else if(address>=heap_address && address-heap_address<f->heap_bytes){data=f->heap;length=f->heap_bytes;start=heap_address;}
  if(!data || bytes>length-(size_t)(address-start))return 14;
  memcpy(out,data+(size_t)(address-start),bytes);return 0;
}
static uint64_t strip_model(void *context,uint64_t value) {
  struct fixture *f=(struct fixture *)context;++f->strips;
  if(value==signed_return)return f->snapshot.slide+PDX_SWIFT_CALLER_PC;
  return value;
}
static struct pdx_swift_reader fixture_reader(struct fixture *f) {
  struct pdx_swift_reader reader={f,copy_model,strip_model};return reader;
}
static void cache_reset(void) {
  pdx_swift_cache_lock=pdx_swift_cache_length=pdx_swift_cache_dropped=0;
  memset(pdx_swift_cached_report,0,sizeof(pdx_swift_cached_report));
  struct pdx_swift_result empty={0};pdx_swift_cached_result=empty;
}
static struct pdx_swift_result collect(struct fixture *f,enum pdx_swift_status expected) {
  struct pdx_swift_result result;struct pdx_swift_reader reader=fixture_reader(f);
  int candidate=pdx_swift_trap_collect(&f->snapshot,&reader,&result);
  assert(candidate==(expected!=PDX_SWIFT_UNRELATED));
  if(result.status!=expected){fprintf(stderr,"got %s wanted %s\n",pdx_swift_status_name(result.status),pdx_swift_status_name(expected));abort();}
  assert(f->reads<=6 && f->copied<=844 && f->max_read<=768);
  if(expected!=PDX_SWIFT_OK)assert(!result.head_bytes && !result.tail_bytes);
  ++cases;return result;
}
'''

CORE_TESTS = r'''
static void success_tests(void) {
  static const unsigned lengths[]={37,40,128,767,768,769,1024,4096,65536};
  for(unsigned k=0;k<sizeof(lengths)/sizeof(lengths[0]);++k) {
    struct fixture f;fixture_init(&f,lengths[k]);
    const char suffix[]=" ERROR domain=Example code=42";
    if(lengths[k]>128)memcpy(f.heap+f.heap_bytes-(sizeof(suffix)-1),suffix,sizeof(suffix)-1);
    struct pdx_swift_result r=collect(&f,PDX_SWIFT_OK);
    assert(r.total_bytes==lengths[k]);
    unsigned head=lengths[k]<=768?lengths[k]:256,tail=lengths[k]<=768?0:512;
    assert(r.head_bytes==head && r.tail_bytes==tail);
    assert(!memcmp(r.message,f.heap+32,head));
    if(tail)assert(!memcmp(r.message+head,f.heap+f.heap_bytes-tail,tail));
    assert(f.reads==(tail?6u:5u) && f.strips==2 && r.message[head+tail]==0);
    char report[PDX_SWIFT_REPORT_BYTES];unsigned n=pdx_swift_trap_format(&r,report,sizeof report);
    assert(n==strlen(report) && n<sizeof(report)-1 && strstr(report,"status=captured"));
    assert(strstr(report,fatal_prefix));
    if(lengths[k]>128)assert(strstr(report,suffix));
    if(tail)assert(strstr(report,"MSG head: ") && strstr(report,"MSG tail: "));
    fixture_destroy(&f);
  }
  // Native immortal bias uses the same address rule; retain no user pointer.
  struct fixture f;fixture_init(&f,200);put_word(&f,stack_address+0x220,UINT64_C(0x8000000000000000)|heap_address);
  struct pdx_swift_result r=collect(&f,PDX_SWIFT_OK);cache_reset();assert(pdx_swift_trap_publish(&r));
  char before[2048],after[2048];assert(pdx_swift_trap_text(before,sizeof before));
  unsigned reads=f.reads;memset(f.heap,0, f.heap_bytes);fixture_destroy(&f);
  memset(&r,0,sizeof r);assert(pdx_swift_trap_text(after,sizeof after));assert(!strcmp(before,after) && f.reads==reads);
  ++cases;
}
static void guard_tests(void) {
  struct fixture f;
  for(unsigned i=0;i<7;++i) {
    fixture_init(&f,128);
    switch(i){case 0:f.snapshot.valid=0;break;case 1:f.snapshot.signal=6;break;
      case 2:f.snapshot.esr^=1;break;case 3:f.snapshot.pc+=4;break;
      case 4:f.snapshot.pc=0;break;case 5:f.snapshot.slide=UINT64_MAX;break;case 6:f.snapshot.signal=9;break;}
    collect(&f,PDX_SWIFT_UNRELATED);assert(!f.reads && !f.strips);fixture_destroy(&f);
  }
  for(unsigned i=0;i<6;++i) {
    fixture_init(&f,128);
    switch(i){case 0:f.snapshot.pid++;break;case 1:f.snapshot.exit_pid++;break;
      case 2:f.snapshot.current_pid++;break;case 3:f.snapshot.thread_id=0;break;
      case 4:f.snapshot.current_thread_id++;break;case 5:f.snapshot.pid=f.snapshot.current_pid=f.snapshot.exit_pid=0;break;}
    collect(&f,PDX_SWIFT_UNAVAILABLE_CORRELATION);assert(!f.reads && !f.strips);fixture_destroy(&f);
  }
  fixture_init(&f,128);f.snapshot.ordinary_exit=0;collect(&f,PDX_SWIFT_UNAVAILABLE_CONTEXT);assert(!f.reads);fixture_destroy(&f);
  fixture_init(&f,128);struct pdx_swift_reader reader=fixture_reader(&f);struct pdx_swift_result r;
  reader.strip_return=NULL;assert(pdx_swift_trap_collect(&f.snapshot,&reader,&r) && r.status==PDX_SWIFT_READER_UNAVAILABLE && !f.reads);
  reader=fixture_reader(&f);reader.read=NULL;assert(pdx_swift_trap_collect(&f.snapshot,&reader,&r) && !f.reads);
  assert(pdx_swift_trap_collect(&f.snapshot,NULL,&r) && !f.reads);
  assert(!pdx_swift_trap_collect(NULL,&reader,&r));assert(!pdx_swift_trap_collect(&f.snapshot,&reader,NULL));fixture_destroy(&f);++cases;
  fixture_init(&f,128);f.code[0]=0;collect(&f,PDX_SWIFT_INSTRUCTION);assert(f.reads==1);fixture_destroy(&f);
  for(unsigned i=0;i<5;++i) {
    fixture_init(&f,128);
    switch(i){case 0:f.snapshot.sp++;break;case 1:f.snapshot.fp++;break;
      case 2:f.snapshot.fp+=16;break;case 3:f.snapshot.sp=0;break;case 4:f.snapshot.sp=UINT64_MAX-15;break;}
    collect(&f,PDX_SWIFT_FRAME);assert(f.reads==1);fixture_destroy(&f);
  }
  const uint64_t callers[]={0,stack_address+0x281,stack_address+0x100,stack_address+0x180,stack_address+0x100+UINT64_C(1048592)};
  for(unsigned i=0;i<sizeof(callers)/sizeof(callers[0]);++i) {
    fixture_init(&f,128);put_word(&f,f.snapshot.fp,callers[i]);collect(&f,PDX_SWIFT_CALLER);assert(f.reads==2);fixture_destroy(&f);
  }
  fixture_init(&f,128);put_word(&f,f.snapshot.fp+8,PDX_SWIFT_CALLER_PC+4);collect(&f,PDX_SWIFT_CALLER);fixture_destroy(&f);
  for(unsigned i=0;i<3;++i) {
    fixture_init(&f,128);
    if(i==0)put_word(&f,f.snapshot.fp+16,59);
    if(i==1)put_word(&f,f.snapshot.fp+24,1);
    if(i==2)f.snapshot.x20+=8;
    collect(&f,PDX_SWIFT_ARGUMENTS);assert(f.reads==2);fixture_destroy(&f);
  }
  fixture_init(&f,128);f.snapshot.x21++;collect(&f,PDX_SWIFT_ERROR);assert(f.reads==4);fixture_destroy(&f);
  fixture_init(&f,128);f.snapshot.x21=0;put_word(&f,stack_address+0x210,0);collect(&f,PDX_SWIFT_ERROR);fixture_destroy(&f);
  for(unsigned i=0;i<3;++i) {
    fixture_init(&f,128);
    if(i==0)put_word(&f,stack_address+0x220,UINT64_C(0xe000000000000000));
    if(i==1)put_word(&f,stack_address+0x220,UINT64_C(0x1000000000000000)|heap_address);
    if(i==2)put_word(&f,stack_address+0x218,128);
    r=collect(&f,PDX_SWIFT_LAYOUT);assert(f.reads==4);
    char report[2048];pdx_swift_trap_format(&r,report,sizeof report);
    assert(strstr(report,"unsupported-string-layout") && !strstr(report,"MSG:"));fixture_destroy(&f);
  }
  for(unsigned i=0;i<4;++i) {
    fixture_init(&f,128);uint64_t length=i==0?0:i==1?36:i==2?65537:UINT64_C(0x0000ffffffffffff);
    put_word(&f,stack_address+0x218,UINT64_C(0xf000000000000000)|length);
    collect(&f,PDX_SWIFT_LENGTH);assert(f.reads==4);fixture_destroy(&f);
  }
  fixture_init(&f,128);f.heap[32]='!';r=collect(&f,PDX_SWIFT_PREFIX);
  for(unsigned i=0;i<sizeof r.message;++i)assert(!r.message[i]);fixture_destroy(&f);
  // Overflow and map boundaries are rejected before a reader gets a range.
  fixture_init(&f,128);f.snapshot.user_limit=code_address+3;collect(&f,PDX_SWIFT_ADDRESS);assert(!f.reads);fixture_destroy(&f);
  fixture_init(&f,128);put_word(&f,stack_address+0x220,UINT64_C(0x0ffffffffffffff0));
  collect(&f,PDX_SWIFT_ADDRESS);assert(f.reads==4);fixture_destroy(&f);
  fixture_init(&f,128);put_word(&f,stack_address+0x220,code_address+0x10000);
  f.snapshot.user_limit=code_address+0x10000+32+127;
  collect(&f,PDX_SWIFT_ADDRESS);assert(f.reads==4);fixture_destroy(&f);
}
static void failure_tests(void) {
  const enum pdx_swift_status statuses[]={PDX_SWIFT_COPY_INSTRUCTION,PDX_SWIFT_COPY_FRAME,PDX_SWIFT_COPY_CALLER,
    PDX_SWIFT_COPY_STRING,PDX_SWIFT_COPY_HEAD,PDX_SWIFT_COPY_TAIL};
  for(unsigned partial=0;partial<2;++partial)for(unsigned i=0;i<6;++i) {
    struct fixture f;fixture_init(&f,1024);f.fail_read=i+1;f.partial_fail=partial;
    struct pdx_swift_result r=collect(&f,statuses[i]);assert(r.copy_error==14 && f.reads==i+1);
    char report[2048];pdx_swift_trap_format(&r,report,sizeof report);
    assert(strstr(report,"copy=14") && !strstr(report,"MSG head:") && !strstr(report,"MSG:"));
    if(i>=4)for(unsigned j=0;j<sizeof r.message;++j)assert(!r.message[j]);
    fixture_destroy(&f);
  }
}
static void formatting_tests(void) {
  struct fixture f;fixture_init(&f,1024);f.heap[32+100]=0;f.heap[32+101]=0xff;
  struct pdx_swift_result r=collect(&f,PDX_SWIFT_OK);
  unsigned char *guard=(unsigned char *)malloc(2050);assert(guard);
  for(unsigned cap=0;cap<=2048;++cap) {
    memset(guard,0xa5,2050);unsigned n=pdx_swift_trap_format(&r,(char *)guard+1,cap);
    assert(guard[0]==0xa5 && guard[cap+1]==0xa5);
    if(cap)assert(n<cap && guard[1+n]==0 && memchr(guard+1,0,cap));else assert(!n);
    for(unsigned i=0;i<n;++i)assert(guard[1+i]=='\n' || (guard[1+i]>=32 && guard[1+i]<=126));
  }
  char full[2048];pdx_swift_trap_format(&r,full,sizeof full);assert(strstr(full,"??"));
  assert(pdx_swift_trap_format(NULL,full,sizeof full)==0 && !full[0]);
  assert(!pdx_swift_trap_format(&r,NULL,2048));
  cache_reset();assert(pdx_swift_trap_publish(&r));
  assert(pdx_swift_cached_result.message[100]==0 && pdx_swift_cached_result.message[101]==0xff);
  assert(pdx_swift_cached_result.head_bytes==256 && pdx_swift_cached_result.tail_bytes==512);
  for(unsigned cap=0;cap<=2048;++cap) {
    memset(guard,0xa5,2050);unsigned n=pdx_swift_trap_text((char *)guard+1,cap);
    assert(guard[0]==0xa5 && guard[cap+1]==0xa5);
    if(cap)assert(n<cap && guard[1+n]==0);else assert(!n);
  }
  unsigned reads=f.reads;pdx_swift_cache_lock=1;full[0]='!';assert(!pdx_swift_trap_text(full,sizeof full) && !full[0]);
  assert(!pdx_swift_trap_publish(&r) && pdx_swift_cache_dropped==1);pdx_swift_cache_lock=0;
  assert(pdx_swift_trap_text(full,sizeof full) && f.reads==reads);
  memset(&r,0,sizeof r);assert(!pdx_swift_trap_publish(&r));assert(pdx_swift_trap_text(full,sizeof full));
  // A later qualified failure must replace the previous text with status only.
  r.status=PDX_SWIFT_LAYOUT;r.pid=99;assert(pdx_swift_trap_publish(&r));
  assert(pdx_swift_trap_text(full,sizeof full) && strstr(full,"pid=99") && !strstr(full,fatal_prefix));
  free(guard);fixture_destroy(&f);cases+=3;
}
static void *publisher(void *arg) {
  unsigned which=(unsigned)(uintptr_t)arg;
  struct pdx_swift_result result;memset(&result,0,sizeof result);result.status=PDX_SWIFT_OK;
  result.pid=which?202:101;result.head_bytes=which?700:400;result.total_bytes=result.head_bytes;
  memset(result.message,which?'B':'A',result.head_bytes);
  for(unsigned i=0;i<10000;++i)(void)pdx_swift_trap_publish(&result);
  return NULL;
}
static void concurrency_test(void) {
  cache_reset();pthread_t a,b;assert(!pthread_create(&a,NULL,publisher,(void *)(uintptr_t)0));
  assert(!pthread_create(&b,NULL,publisher,(void *)(uintptr_t)1));
  for(unsigned n=0;n<20000;++n) {
    char text[2048];if(!pdx_swift_trap_text(text,sizeof text))continue;
    const char *body=strstr(text,"MSG: ");assert(body);body+=5;
    int first=strstr(text,"pid=101 ")!=NULL;assert(first || strstr(text,"pid=202 "));
    unsigned count=first?400:700;assert(strlen(body)==count);
    for(unsigned j=0;j<count;++j)assert(body[j]==(first?'A':'B'));
  }
  assert(!pthread_join(a,NULL) && !pthread_join(b,NULL));++cases;
}
static void fuzz_test(void) {
  uint32_t random=UINT32_C(0x234d2701);
  for(unsigned i=0;i<2000;++i) {
    struct fixture f;fixture_init(&f,1024);random=random*1664525u+1013904223u;
    switch(random%6) {
      case 0:f.snapshot.fp^=(uint64_t)(random|1);break;
      case 1:put_word(&f,f.snapshot.fp,(uint64_t)random<<32);break;
      case 2:put_word(&f,stack_address+0x218,(uint64_t)random<<32|random);break;
      case 3:put_word(&f,stack_address+0x220,(uint64_t)random<<32|random);break;
      case 4:f.fail_read=1+(random%6);f.partial_fail=1;break;
      default:f.snapshot.current_thread_id^=(uint64_t)random|1;break;
    }
    struct pdx_swift_result r;struct pdx_swift_reader reader=fixture_reader(&f);
    assert(pdx_swift_trap_collect(&f.snapshot,&reader,&r));
    assert(f.reads<=6 && f.copied<=844);
    char text[2048];unsigned n=pdx_swift_trap_format(&r,text,sizeof text);assert(n && n<sizeof text && text[n]==0);
    fixture_destroy(&f);
  }
  cases+=2000;
}
int main(void) {
  success_tests();guard_tests();failure_tests();formatting_tests();concurrency_test();fuzz_test();
  printf("PASS core: %u cases; precise guards, partial-copy failures, 768-byte head/tail, owned cache, concurrent snapshots\n",cases);
  return 0;
}
'''

KERNEL_FIXTURES = r'''
// Preserve Darwin's printf uint64_t ABI after parsing host headers.
#define uint64_t unsigned long long
#define KERNEL 1
typedef uint64_t user_addr_t;
typedef struct {uint64_t pc,lr,sp,fp,x[29];unsigned is64;} arm_saved_state_t;
static struct {uint64_t thread_id;} host_thread={UINT64_C(0x123456789)};
static struct {uint64_t task_shared_region_slide;} host_task={UINT64_C(0x263c000)};
static struct {uint64_t max_offset;} host_map={UINT64_C(0x100000000000000)};
static arm_saved_state_t host_state;
static int host_pid=56,host_interrupt,host_fallback;
static unsigned host_copy_calls,host_strip_calls;
static int host_user_read(uint64_t,void *,size_t);
static void *host_ptrauth_strip(void *,int);
static int copyin(user_addr_t address,void *out,size_t bytes){++host_copy_calls;return host_user_read(address,out,bytes);}
static int proc_selfpid(void){return host_pid;}
static void proc_selfname(char *name,int capacity){if(capacity>0)snprintf(name,(size_t)capacity,"WorldClockWidget");}
#define current_thread() (&host_thread)
#define current_task() (&host_task)
#define current_map() (&host_map)
#define vm_map_max(map) ((map)->max_offset)
static int ml_at_interrupt_context(void){return host_interrupt;}
static uint64_t get_saved_state_pc(arm_saved_state_t *s){return s->pc;}
static uint64_t get_saved_state_lr(arm_saved_state_t *s){return s->lr;}
static uint64_t get_saved_state_sp(arm_saved_state_t *s){return s->sp;}
static uint64_t get_saved_state_fp(arm_saved_state_t *s){return s->fp;}
static uint64_t get_saved_state_reg(arm_saved_state_t *s,unsigned i){assert(i<29);return s->x[i];}
static arm_saved_state_t *find_user_regs(void *thread){(void)thread;return host_fallback?&host_state:NULL;}
static int is_saved_state64(arm_saved_state_t *s){return s->is64;}
static void *host_ptrauth_strip(void *pointer,int key){
  assert(key==11);++host_strip_calls;uint64_t raw=(uint64_t)(uintptr_t)pointer;
  return (void *)(uintptr_t)(raw==UINT64_C(0xacbd00a18e3b0b14)?UINT64_C(0x18e3b0b14):raw);
}
'''

ADAPTER_TESTS = r'''
static struct fixture *active;
static int host_user_read(uint64_t address,void *out,size_t bytes){return copy_model(active,address,out,bytes);}
static void integration_reset(struct fixture *f) {
  cache_reset();memset(faults,0,sizeof faults);fault_lock=fault_count=0;
  fixture_init(f,1024);active=f;host_pid=56;host_interrupt=host_fallback=0;
  host_copy_calls=host_strip_calls=0;host_thread.thread_id=f->snapshot.thread_id;
  memset(&host_state,0,sizeof host_state);host_state.pc=f->snapshot.pc;
  host_state.sp=f->snapshot.sp;host_state.fp=f->snapshot.fp;host_state.x[20]=f->snapshot.x20;
  host_state.x[21]=f->snapshot.x21;host_state.is64=1;
  host_task.task_shared_region_slide=f->snapshot.slide;
}
static void breakpoint_record(void) {
  boot_progress_user_breakpoint(&host_state,(unsigned)PDX_SWIFT_TRAP_ESR);
  assert(!host_copy_calls && !pdx_swift_cache_length);
}
static void exit_text(char *report) {
  char ordinary[400]={0};boot_progress_exit_fault(host_pid,5,ordinary,sizeof ordinary);
  assert(pdx_swift_trap_text(report,2048));
}
int main(void) {
  struct fixture f;char report[2048];
  integration_reset(&f);breakpoint_record();assert(faults[0].thread_id==host_thread.thread_id);
  exit_text(report);assert(strstr(report,"status=captured") && strstr(report,fatal_prefix));
  unsigned copies=host_copy_calls;fixture_destroy(&f);active=NULL;
  memset(report,0xcc,sizeof report);assert(pdx_swift_trap_text(report,sizeof report));assert(host_copy_calls==copies);
  // A newer record from another thread must not shadow the exiting thread.
  integration_reset(&f);breakpoint_record();host_thread.thread_id++;
  boot_progress_user_breakpoint(&host_state,(unsigned)PDX_SWIFT_TRAP_ESR);host_thread.thread_id--;
  exit_text(report);assert(strstr(report,"status=captured"));fixture_destroy(&f);
  // PID reused / wrong exiting thread: unavailable report, zero user reads.
  integration_reset(&f);breakpoint_record();host_thread.thread_id+=10;
  exit_text(report);assert(strstr(report,"unavailable-pid-thread") && !host_copy_calls);fixture_destroy(&f);
  // No fault-lock spin, and no snapshot publication from an unrelated signal.
  integration_reset(&f);breakpoint_record();char ordinary[400]={0};fault_lock=1;
  boot_progress_exit_fault(host_pid,5,ordinary,sizeof ordinary);assert(!host_copy_calls && !pdx_swift_cache_length);
  fault_lock=0;boot_progress_exit_fault(host_pid,6,ordinary,sizeof ordinary);
  assert(!pdx_swift_cache_length);fixture_destroy(&f);
  // Verify retained status for unsupported representations / failed copy.
  integration_reset(&f);put_word(&f,stack_address+0x220,UINT64_C(0x1000000000000000)|heap_address);
  breakpoint_record();exit_text(report);assert(strstr(report,"unsupported-string-layout") && !strstr(report,"MSG head:"));fixture_destroy(&f);
  integration_reset(&f);f.fail_read=6;f.partial_fail=1;breakpoint_record();exit_text(report);
  assert(strstr(report,"copy-message-tail") && strstr(report,"copy=14") && !strstr(report,"MSG head:"));fixture_destroy(&f);
  // Missing hardware exception must never promote fallback registers to this site.
  integration_reset(&f);host_fallback=1;boot_progress_exit_fault(host_pid,5,ordinary,sizeof ordinary);
  assert(!pdx_swift_cache_length);fixture_destroy(&f);
  // The callback adapter rejects interrupt context before copyin.
  integration_reset(&f);breakpoint_record();host_interrupt=1;
  pdx_swift_fault_record(&faults[0],56,5);assert(!host_copy_calls);
  assert(pdx_swift_trap_text(report,sizeof report) && strstr(report,"unavailable-exit-context"));fixture_destroy(&f);
  // Same numeric PID is insufficient when the actual current task differs.
  integration_reset(&f);breakpoint_record();host_pid=57;
  pdx_swift_fault_record(&faults[0],56,5);assert(!host_copy_calls);
  assert(pdx_swift_trap_text(report,sizeof report) && strstr(report,"unavailable-pid-thread"));fixture_destroy(&f);
  puts("PASS adapter: actual capture + ordinary exit functions; thread correlation, unavailable status, zero trap/painter reads");
  return 0;
}
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def rejection(function, source):
    try:
        function(source)
    except ValueError:
        return
    raise AssertionError('Unqualified/duplicate source accepted')


def source_checks(original, out):
    adapted = overlay.adapt_fault(original)
    rejection(overlay.adapt_fault, original+'\n')
    rejection(overlay.adapt_fault, adapted)
    # Exercise anchor validation separately from the whole-source hash gate.
    anchors = [' uint64_t pc,lr,sp,fp,esr,far,slide,x[29];',
               'static unsigned fault_lock,fault_count;',
               ' f->valid=0;f->pid=proc_selfpid();proc_selfname(f->name,sizeof(f->name));',
               '  if(candidate->valid && candidate->pid==pid){f=*candidate;break;}']
    original_sha = overlay.FAULT_SHA256
    rejects = 2
    try:
        for anchor in anchors:
            for replacement in ('', anchor+'\n'+anchor):
                changed = original.replace(anchor, replacement, 1)
                overlay.FAULT_SHA256 = sha(changed.encode())
                rejection(overlay.adapt_fault, changed)
                rejects += 1
    finally:
        overlay.FAULT_SHA256 = original_sha
    start = adapted.index('static void capture_exception(')
    end = adapted.index('void boot_progress_user_breakpoint', start)
    capture = adapted[start:end]
    assert 'f->thread_id=current_thread()->thread_id' in capture
    assert 'copyin' not in capture and 'pdx_swift_fault_record' not in capture
    start = adapted.index('void boot_progress_exit_fault(')
    end = adapted.index('// Called on the ordinary exit path before coredump/sync,', start)
    exit_function = adapted[start:end]
    assert exit_function.index('__atomic_store_n(&fault_lock,0') < exit_function.index('pdx_swift_fault_record(')
    assert 'candidate->thread_id==exiting_thread_id' in exit_function
    assert 'f.thread_id==exiting_thread_id' in exit_function
    assert adapted[adapted.index('// REASON-SCAN'):]==original[original.index('// REASON-SCAN'):]
    staging = out/'stage';staging.mkdir()
    staged = overlay.stage_header(staging)
    assert overlay.stage_header(staging) == staged
    target = staging/overlay.HEADER
    target.write_text('unrelated staged user work\n')
    try:
        overlay.stage_header(staging)
    except ValueError:
        pass
    else:
        raise AssertionError('Overwrote a different staged header')
    assert target.read_text() == 'unrelated staged user work\n'
    return adapted, dict(source_rejections=rejects, original_source_sha256=sha(original.encode()),
                         adapted_source_sha256=sha(adapted.encode()), staged_header_sha256=staged['sha256'],
                         trap_user_reads=False, reason_scan_unchanged=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fault', type=Path, default=Path('/mnt/e/UniXNU-sheng27-sony-20261113/boot-screen-007/BootFaultProbe.c'))
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--cc', default='clang')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    out = args.out.resolve()
    original = args.fault.read_bytes()
    assert sha(original) == overlay.FAULT_SHA256
    adapted, checks = source_checks(original.decode(), out)
    (out/'BootFaultProbe.adapted.c').write_text(adapted)
    header = Path(__file__).with_name(overlay.HEADER)
    (out/overlay.HEADER).write_bytes(header.read_bytes())
    (out/'ptrauth.h').write_text('#define ptrauth_key_return_address 11\n#define ptrauth_strip(pointer,key) host_ptrauth_strip((pointer),(key))\n')
    prefix = adapted[adapted.index('struct boot_fault_record {'):adapted.index('// Called on the ordinary exit path before coredump/sync,')]
    sources = {
        'core': PRELUDE+'\n#include "PdxSwiftTrapDiagnostic.h"\n'+FIXTURE+CORE_TESTS,
        'adapter': PRELUDE+KERNEL_FIXTURES+prefix+FIXTURE+ADAPTER_TESTS,
    }
    compiler = shutil.which(args.cc)
    if not compiler:
        raise RuntimeError(f'Compiler unavailable: {args.cc}')
    runs = []
    for name, code in sources.items():
        source = out/(name+'.c');source.write_text(code)
        command = [compiler, '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                   '-Wno-unused-function', '-Wno-unused-parameter', '-fsanitize=address,undefined',
                   '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-pthread', '-I'+str(out),
                   str(source), '-o', str(out/name)]
        (out/(name+'-command.json')).write_text(json.dumps(command, indent=2)+'\n')
        build = subprocess.run(command, capture_output=True, text=True, timeout=120)
        (out/(name+'-build.log')).write_text(build.stdout+build.stderr)
        if build.returncode:
            raise RuntimeError(build.stdout+build.stderr)
        environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                           UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        run = subprocess.run([str(out/name)], env=environment, capture_output=True, text=True, timeout=60)
        (out/(name+'.log')).write_text(run.stdout+run.stderr)
        if run.returncode:
            raise RuntimeError(run.stdout+run.stderr)
        runs.append(dict(name=name, command=command, output=run.stdout.strip(),
                         generated_source_sha256=sha(code.encode()), binary_sha256=sha((out/name).read_bytes())))
    receipt = dict(passed=True, hardware_verified=False, sanitizers=['address','undefined'], suites=runs, source_checks=checks,
                   fault_source_sha256=sha(original),
                   header_sha256=sha(header.read_bytes()), overlay_sha256=sha(Path(overlay.__file__).read_bytes()),
                   tests_sha256=sha(Path(__file__).read_bytes()), compiler=compiler,
                   host_ptrauth_executed=False, native_kernel_build=False, device_operations=False,
                   original_cache_export=False)
    (out/'result.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
