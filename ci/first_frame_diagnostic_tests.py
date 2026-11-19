#!/usr/bin/env python3
"""Run the actual first-frame headers and retained painters under ASan/UBSan.

Run in WSL, for example:
  python3 -B ci/first_frame_diagnostic_tests.py --out /mnt/e/UniXNU-sheng27-sony-20261113/first-frame-tests-001
Add --built <fresh boot-screen directory> to check its native compile provenance.
The fixtures supply recorded RAM data and kernel service boundaries, not a GPU.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import boot_screen_cached_overlay as overlay


HEADERS = ('PdxFirstFrameDiagnostics.h', 'PdxRenderThreadDiagnostics.h',
           'PdxBootCachedDiagnostics.h', 'PdxGpuProgressCache.h', 'PdxProcessChurnDiagnostics.h',
           'PdxFramebufferCallDiagnostics.h')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def method(text, name):
    """Extract a complete, uniquely named production function, including its body."""
    assert text.count(name) == 1, name
    start = text.index(name)
    brace = text.index('{', start)
    depth, end = 1, brace + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


def reject(function, text):
    try:
        function(text)
    except ValueError:
        return
    raise AssertionError(f'{function.__name__} accepted an unreviewed source/anchor')


def source_checks(package):
    progress = (package/'BootProgress.c').read_text()
    trace = (package/'BootUiTraceProbe.c').read_text()
    details = (package/'BootUiTraceDetails.h').read_text()
    adapted = overlay.apply_first_frame_progress(overlay.apply_usb(overlay.apply_progress(progress)))
    traced = overlay.apply_first_frame_trace(trace)
    formatted = overlay.apply_trace_details(details)
    for function, original in ((overlay.apply_progress, progress),
                               (overlay.apply_first_frame_trace, trace),
                               (overlay.apply_trace_details, details)):
        reject(function, original+'\n')
        reject(function, function(original))
    anchor = '#include "PdxBootCachedDiagnostics.h"'
    cached = overlay.apply_progress(progress)
    reject(overlay.apply_first_frame_progress, cached.replace(anchor, ''))
    reject(overlay.apply_first_frame_progress, cached.replace(anchor, anchor+'\n'+anchor))
    for before, after in (('void boot_ui_trace_begin(void) {', 'void changed_begin(void) {'),
                          ('  bt_add(&draft,&samples[i]);\n }\n {', '  changed_collection();\n }\n {'),
                          ('  published=draft;memcpy(published_main', '  changed_publish();memcpy(published_main')):
        reject(overlay.apply_first_frame_trace, trace.replace(before, after))
    for anchor_text in ('static unsigned seconds(void);', 'display.scale=w>=2160 && h>=1400?3:1;',
                        '    touch_overlay();\n    uint64_t f,t0,t1;',
                        '  if(!enabled || !take())return;\n  char stamped[BP_COLS];unsigned now=seconds();',
                        '  census_note(name,1);', 'if(!strncmp(text,"exec process signature",22))census_note(name,0);'):
        reject(overlay.apply_first_frame_progress, cached.replace(anchor_text, anchor_text+'\n'+anchor_text))
        reject(overlay.apply_first_frame_progress, cached.replace(anchor_text, ''))
    begin = method(traced, 'void boot_ui_trace_begin(void)')
    publish = method(traced, 'void boot_ui_trace_publish(void)')
    task = method(traced, 'void boot_ui_trace_task(')
    assert begin.count('pdx_render_begin();') == 1
    assert task.count('pdx_render_collect(role,pid,slide,count);') == 1
    assert task.index('bt_walk(&samples[i]') < task.index('pdx_render_collect(') < task.index('vm_map_deallocate(map)')
    assert 'unsigned role=index-1;' in task
    assert publish.index('__atomic_exchange_n(&trace_lock') < publish.index('pdx_render_publish();')
    assert publish.index('pdx_render_publish();') < publish.index('__atomic_store_n(&trace_lock,0,__ATOMIC_RELEASE)')
    assert adapted.count('#include "PdxFirstFrameDiagnostics.h"') == 1
    assert adapted.index('#include "PdxFirstFrameDiagnostics.h"') < adapted.index(anchor)
    assert adapted.index('#include "PdxGpuProgressCache.h"') < adapted.index('#include "PdxFirstFrameDiagnostics.h"')
    assert adapted.index('#include "PdxFramebufferCallDiagnostics.h"') < adapted.index('#include "PdxFirstFrameDiagnostics.h"')
    assert adapted.index('#include "PdxProcessChurnDiagnostics.h"') < adapted.index('#include "PdxFirstFrameDiagnostics.h"')
    monitor = method(adapted, 'static void touch_monitor(')
    assert 'touch_overlay();\n    pdx_gpu_progress_poll();' in monitor
    process = method(adapted, 'void boot_progress_process_stage(')
    assert process.index('pdx_churn_exec(') < process.index('!take()')
    assert 'if(!strcmp(text,"exec process signature enter"))census_note(name,0);' in process
    binding = method(adapted, 'void boot_progress_bind(')
    assert 'if(diag==1)display.scale=1;' in binding
    exited = method(adapted, 'void boot_progress_exit(')
    assert 'if(!enabled)return;\n  pdx_churn_exit(pid,name,status,ns,code);' in exited
    assert exited.index('pdx_churn_exit(') < exited.index('__atomic_exchange_n(&exit_lock')
    assert '#define BT_USER_ADDRESS_BITS 47' in trace
    assert '#define BT_STRIP_USER_PC(value) ((uint64_t)ptrauth_strip(' in trace
    assert 'e->pc=BT_STRIP_USER_PC(' in task and 'e->lr=BT_STRIP_USER_PC(' in task
    assert 'trap=%llx x1=%llx remote=' in formatted and 'trap=%llx opt=%llx remote=' not in formatted
    return adapted, traced, formatted, dict(
        original_progress_sha256=sha(progress.encode()), original_trace_sha256=sha(trace.encode()),
        original_details_sha256=sha(details.encode()), adapted_progress_sha256=sha(adapted.encode()),
        adapted_trace_sha256=sha(traced.encode()), source_and_anchor_rejections=23,
        arm64e_47_bit_and_ptrauth_source_checked=True, host_ptrauth_executed=False)


PRELUDE = r'''
#include <cassert>
#include <atomic>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <utility>
#include <vector>
// Match Darwin's uint64_t printf ABI. System headers have already been parsed.
#define uint64_t unsigned long long
#define BT_USER_ADDRESS_BITS 47
#include "BootProgressCore.h"
#include "BootProgressDisplay.h"
#include "BootProgressPulse.h"
#include "BootProgressLifecycle.h"
#include "BootUiTraceCore.h"
#include "BootUiTraceDetails.h"
'''


FIXTURES = r'''
static unsigned render_busy;
static uint64_t clock_ns=1000000000ULL;
static uint64_t mach_absolute_time(void){return clock_ns;}
static void absolutetime_to_nanoseconds(uint64_t t,uint64_t *ns){*ns=t;}
static int PE_parse_boot_argn(const char *,void *,unsigned);
static thread_local unsigned caller_pid=42;
static int proc_selfpid(void){return (int)caller_pid;}
#include "PdxGpuProgressCache.h"
#include "PdxProcessChurnDiagnostics.h"
#include "PdxFramebufferCallDiagnostics.h"
#include "PdxFirstFrameDiagnostics.h"
volatile uint64_t native_legacy_object;
struct pdx_frame_client native_adreno_client_log[8];
struct pdx_frame_text native_adreno_client_text[8];
volatile uint32_t native_adreno_fence_wait[8],native_adreno_submit_ibs[4],native_adreno_recovery[8];
volatile uint32_t native_adreno_mount_fail[4],native_adreno_bo_memory[8],native_adreno_stall_ring[10];
volatile uint32_t native_adreno_client_stats[5][6],native_legacy_swapstat[16];
static unsigned trace_calls,report_calls,state_calls,clients_calls,role_calls;
static unsigned swift_calls,swift_write_length,swift_reply;
static char swift_payload[1536];
static unsigned trace_option=7,recorded_pid=90,requested_roles[3];
static uint64_t recorded_tid[3]={0x100001,0x200002,0x300003};
static char report_payload[512],state_payload[128],clients_payload[128];
static unsigned report_length=512,state_length=128,clients_length=128;
static unsigned fence_calls,preempt_calls,fence_result=1,preempt_result=1;
static uint32_t fence_issued=0x11,fence_done=0x22,fence_rings[3]={0x33,0x44,0x55},preempt_values[26];
bool native_adreno_fences_detail(uint32_t *issued,uint32_t *done,uint32_t *rings){
  assert(!render_busy);++fence_calls;*issued=fence_issued;*done=fence_done;memcpy(rings,fence_rings,sizeof fence_rings);return fence_result;
}
bool native_adreno_preempt_stats(uint32_t *data){assert(!render_busy);++preempt_calls;memcpy(data,preempt_values,sizeof preempt_values);return preempt_result;}
int native_gpu_trace_enabled(void){++trace_calls;return (int)trace_option;}
unsigned pdx_swift_trap_text(char *out,unsigned cap){
  ++swift_calls;assert(cap==sizeof swift_payload);
  unsigned n=swift_write_length<cap?swift_write_length:cap;memcpy(out,swift_payload,n);return swift_reply;
}
unsigned native_legacy_prepare_report(char *out,unsigned cap){
  ++report_calls;unsigned n=report_length<cap?report_length:cap;memcpy(out,report_payload,n);return n;
}
unsigned native_legacy_state_words(char *out,unsigned cap){
  ++state_calls;unsigned n=state_length<cap?state_length:cap;memcpy(out,state_payload,n);return n;
}
unsigned native_legacy_clients_dump(char *out,unsigned cap){
  ++clients_calls;unsigned n=clients_length<cap?clients_length:cap;memcpy(out,clients_payload,n);return n;
}
uint64_t native_gpu_role_thread(uint32_t pid,uint32_t role){
  ++role_calls;assert(role>=1 && role<=3);++requested_roles[role-1];
  return pid==recorded_pid?recorded_tid[role-1]:0;
}
'''


SCREEN_GLOBALS = r'''
static bp_display display;
static char boot_progress_ext[8][48],boot_progress_ext_wide[2][112];
static unsigned now_value,data_calls,option_value=1,option_present=1,option_calls;
static unsigned seconds(void){return now_value;}
static void ext_data_rows(void){++data_calls;}
static int PE_parse_boot_argn(const char *name,void *out,unsigned size){
  assert(size==sizeof(unsigned));
  if(!strcmp(name,"first-frame-diag")){++option_calls;if(option_present)*(unsigned*)out=option_value;return option_present;}
  assert(!strcmp(name,"banner"));*(unsigned*)out=0;return 1;
}
#include "PdxBootCachedDiagnostics.h"
static unsigned enabled=1,resume_after=10,boot_progress_display_owned,last_scanout_at,started=1;
static bp_core state,render_snapshot;
static bool recorder_available=true;
static unsigned draws,banners,touch_passes,native_touch_stage_req,line_calls;
static bp_pulse pulse;
static int take(void){return recorder_available;}
static void release(void){}
static void draw(unsigned){++draws;}
static void line(unsigned row,const char *text,uint32_t color){++line_calls;bp_line(&display,row,text,color);}
static void crash_banner(unsigned){++banners;}
static void touch_overlay_locked(void){}
static unsigned census_starts,census_exits;
static void census_note(const char *,int exited){if(exited)++census_exits;else ++census_starts;}
static bp_exits exit_records;
static unsigned exit_lock,exit_dropped;
static void xpc_fail_note(int,unsigned,uint64_t){}
static void (*boot_progress_exit_fault)(int,unsigned,char *,unsigned long);
static void (*boot_progress_exit_reason)(int,unsigned,char *,unsigned long);
static char *boot_progress_throw_text;
'''


ACTUAL_TESTS = r'''
static void bounded(const char *rows,unsigned count){
  for(unsigned i=0;i<count;++i)assert(memchr(rows+i*48,0,48));
}
static std::string joined(const char rows[][48],unsigned first,unsigned count){
  std::string text;for(unsigned i=0;i<count;++i)text+=rows[first+i];return text;
}
static void fill_data(void){
  memset(native_adreno_client_log,0,sizeof native_adreno_client_log);
  memset(native_adreno_client_text,0,sizeof native_adreno_client_text);
  for(unsigned i=0;i<8;++i){
    auto &c=native_adreno_client_log[i];snprintf(c.name,sizeof c.name,"client%u",i);
    c.opens=0x11+i;c.refused=0x21+i;c.closes=0x31+i;c.slot=i==7?UINT32_MAX:i%5;c.peak_mib=0x41+i;
    auto &t=native_adreno_client_text[i];snprintf(t.name,sizeof t.name,"problem%u",i);
    for(unsigned n=0;n<64;++n)t.text[n]=(char)('A'+(n+i)%26);
  }
  for(unsigned i=0;i<5;++i)native_adreno_client_stats[i][2]=0xb0+i;
  for(unsigned i=0;i<8;++i)native_adreno_fence_wait[i]=111*(i+1);
  for(unsigned i=0;i<4;++i){native_adreno_submit_ibs[i]=0x10+i;native_adreno_mount_fail[i]=0x20+i;}
  for(unsigned i=0;i<8;++i){native_adreno_recovery[i]=0x30+i;native_adreno_bo_memory[i]=0x40+i;}
  for(unsigned i=0;i<10;++i)native_adreno_stall_ring[i]=0x50+i;
  for(unsigned i=0;i<16;++i)native_legacy_swapstat[i]=0x60+i;
  for(unsigned i=0;i<512;++i)report_payload[i]=(char)('a'+i%26);
  for(unsigned i=0;i<128;++i){state_payload[i]=(char)('A'+i%26);clients_payload[i]=(char)('a'+i%26);}
  report_length=512;state_length=clients_length=128;
}
static void framebuffer_reset(void){
  memset(pdx_mfb_calls,0,sizeof pdx_mfb_calls);memset(pdx_mfb_selectors,0,sizeof pdx_mfb_selectors);
  pdx_mfb_first_failure={};pdx_mfb_first_submit={};pdx_mfb_issued=pdx_mfb_ended=pdx_mfb_failed=0;
  pdx_mfb_lock=pdx_mfb_dropped=0;native_legacy_object=0;caller_pid=42;
}
static void framebuffer_tests(void){
  framebuffer_reset();assert(PDX_MFB_CALLS==64 && PDX_MFB_SELECTORS==101);
  alignas(16) unsigned char object[7188];memset(object,0xa5,sizeof object);
  uint32_t requested=2,powered=1;memcpy(object+7180,&requested,4);memcpy(object+7184,&powered,4);
  native_legacy_object=(uint64_t)(uintptr_t)object;
  uint64_t input[3]={0x1111222233334444ULL,0x5555666677778888ULL,0x9999aaaabbbbccccULL};
  uint64_t output[2]={0x123456789abcdef0ULL,0xfedcba9876543210ULL};
  const void *client=(const void *)(uintptr_t)0x12345678, *wrong_provider=(const void *)(uintptr_t)1;
  clock_ns=123456789000ULL;caller_pid=123;
  auto begin=[&](unsigned selector,const void *provider= nullptr){return pdx_framebuffer_call_begin(client,provider?provider:object,selector,UINT32_MAX,input,0x100000002ULL,0x300000004ULL,UINT32_MAX);};
  const uint64_t first=begin(3),submit=begin(5),failure=begin(6);
  assert(first==1 && submit==2 && failure==3 && pdx_mfb_issued==3 && !pdx_mfb_ended);
  for(unsigned i=0;i<3;++i){const auto &c=pdx_mfb_calls[i];
    assert(c.token==i+1 && c.client==(uint64_t)(uintptr_t)client && c.provider==native_legacy_object);
    assert(c.us==123456789 && c.pid==123 && c.in_count==UINT32_MAX && c.out_count==UINT32_MAX);
    assert(c.in_bytes==0x100000002ULL && c.out_bytes==0x300000004ULL && c.status==-1 && !c.ended);
    assert(c.state_valid==1 && c.requested==2 && c.powered==1 && !memcmp(c.input,input,sizeof input));
    assert(!c.output[0] && !c.output[1]);
  }
  assert(pdx_mfb_first_submit.token==submit && pdx_mfb_first_submit.status==-1 && !pdx_mfb_first_submit.ended);
  assert(!pdx_mfb_first_failure.token);
  // Complete out of order. A failed return must not read an output pointer.
  const int32_t status=(int32_t)0xe00002c2u;
  pdx_framebuffer_call_end(failure,status,UINT32_MAX,(const uint64_t *)(uintptr_t)1,0xdead);
  assert(pdx_mfb_first_failure.token==failure && pdx_mfb_first_failure.status==status && pdx_mfb_first_failure.ended);
  pdx_framebuffer_call_end(first,0,UINT32_MAX,output,0x500000006ULL);
  requested=9;powered=8;memcpy(object+7180,&requested,4);memcpy(object+7184,&powered,4);
  pdx_framebuffer_call_end(submit,0,2,output,0x700000008ULL);
  assert(pdx_mfb_first_submit.ended && !pdx_mfb_first_submit.status && pdx_mfb_first_submit.requested==2 && pdx_mfb_first_submit.powered==1);
  assert(!memcmp(pdx_mfb_first_submit.output,output,sizeof output));
  const auto retained_failure=pdx_mfb_first_failure,retained_submit=pdx_mfb_first_submit;
  uint64_t sel72=begin(72);assert(pdx_mfb_calls[sel72-1].requested==9 && pdx_mfb_calls[sel72-1].powered==8);
  pdx_framebuffer_call_end(sel72,-72,1,nullptr,72);
  uint64_t sel74=begin(74,wrong_provider);assert(!pdx_mfb_calls[sel74-1].state_valid && !pdx_mfb_calls[sel74-1].requested && !pdx_mfb_calls[sel74-1].powered);
  pdx_framebuffer_call_end(sel74,0,UINT32_MAX,nullptr,74);
  assert(!memcmp(&retained_failure,&pdx_mfb_first_failure,sizeof retained_failure));
  assert(!memcmp(&retained_submit,&pdx_mfb_first_submit,sizeof retained_submit));
  char rows[9][48];memset(rows,0xa5,sizeof rows);assert(pdx_framebuffer_call_rows(8,rows));bounded(&rows[0][0],9);
  assert(!strcmp(rows[0],"FB hex calls=5 done=5 fail=2"));
  assert(!strcmp(rows[1],"FB3 1/0 5 1/0 6 1/1") && !strcmp(rows[2],"FB72 1/1 74 1/0 drop=0"));
  assert(!strcmp(rows[3],"FBFAIL id=3 pid=123 s=6") && strstr(rows[4],"ended=1 st=e00002c2 state1 req2 pwr1"));
  assert(pdx_framebuffer_call_rows(32,rows) && !strcmp(rows[3],"FBSUB id=2 pid=123 s=5"));
  assert(pdx_framebuffer_call_rows(56,rows) && !strcmp(rows[3],"FBLAST id=5 pid=123 s=74"));
  char snapshot[PDX_FIRST_FRAME_ROWS][48],render_rows[9][48];
  assert(pdx_render_thread_rows(render_rows));pdx_first_frame_snapshot(0,snapshot);
  assert(!memcmp(&snapshot[13],render_rows,sizeof render_rows));
  for(unsigned now: {8u,32u,56u}){assert(pdx_framebuffer_call_rows(now,rows));pdx_first_frame_snapshot(now,snapshot);
    assert(!memcmp(&snapshot[13],rows,sizeof rows));}
  // The number of copied scalar words is bounded independently of the count.
  for(unsigned n=0;n<=3;++n){
    std::vector<uint64_t> exact_input(n,0x1122334455667788ULL),exact_output(n<2?n:2,0x8877665544332211ULL);
    uint64_t token=pdx_framebuffer_call_begin(client,wrong_provider,100,n,n?exact_input.data():nullptr,n,n,n);
    auto &c=pdx_mfb_calls[(token-1)%64];
    for(unsigned i=0;i<3;++i)assert(c.input[i]==(i<n?exact_input[i]:0));
    pdx_framebuffer_call_end(token,0,n,n?exact_output.data():nullptr,100+n);
    for(unsigned i=0;i<2;++i)assert(c.output[i]==(i<n?exact_output[i]:0));
    assert(c.in_count==n && c.out_count==n && c.out_bytes==100+n);
  }
  auto selector100=pdx_mfb_selectors[100];
  for(unsigned selector: {101u,UINT32_MAX}){
    uint64_t token=pdx_framebuffer_call_begin(client,wrong_provider,selector,UINT32_MAX,nullptr,0,0,UINT32_MAX);
    pdx_framebuffer_call_end(token,-1,UINT32_MAX,nullptr,0);
  }
  assert(!memcmp(&selector100,&pdx_mfb_selectors[100],sizeof selector100));
  // Ring replacement, invalid tokens and repeated ends preserve the newest owner.
  framebuffer_reset();uint64_t first_submit=pdx_framebuffer_call_begin(client,wrong_provider,5,0,nullptr,0,0,0);
  pdx_framebuffer_call_end(first_submit,-5,0,nullptr,0);
  const auto pinned_failure=pdx_mfb_first_failure,pinned_submit=pdx_mfb_first_submit;
  uint64_t overwritten=pdx_framebuffer_call_begin(client,wrong_provider,3,0,nullptr,0,0,0),last=0;
  for(unsigned i=0;i<64;++i){last=pdx_framebuffer_call_begin(client,wrong_provider,74,0,nullptr,0,0,0);pdx_framebuffer_call_end(last,0,0,nullptr,i);}
  auto newest=pdx_mfb_calls[(last-1)%64];uint64_t ended=pdx_mfb_ended;
  pdx_framebuffer_call_end(overwritten,-3,0,nullptr,0);pdx_framebuffer_call_end(last,-74,0,nullptr,0);
  assert(pdx_mfb_dropped==2 && pdx_mfb_ended==ended && !memcmp(&newest,&pdx_mfb_calls[(last-1)%64],sizeof newest));
  pdx_framebuffer_call_end(last+64,-99,0,nullptr,0);assert(pdx_mfb_dropped==3);
  assert(!memcmp(&pinned_failure,&pdx_mfb_first_failure,sizeof pinned_failure) && !memcmp(&pinned_submit,&pdx_mfb_first_submit,sizeof pinned_submit));
  pdx_mfb_lock=1;unsigned drops=pdx_mfb_dropped;uint64_t issued=pdx_mfb_issued;
  assert(!pdx_framebuffer_call_begin(client,wrong_provider,3,0,nullptr,0,0,0));
  pdx_framebuffer_call_end(last,-1,0,nullptr,0);pdx_framebuffer_call_end(0,-1,0,nullptr,0);
  assert(pdx_mfb_dropped==drops+2 && pdx_mfb_issued==issued && pdx_mfb_lock==1);
  memset(rows,0x7c,sizeof rows);char unchanged[9][48];memcpy(unchanged,rows,sizeof rows);
  assert(!pdx_framebuffer_call_rows(8,rows) && !memcmp(rows,unchanged,sizeof rows) && pdx_mfb_lock==1);
  pdx_first_frame_snapshot(8,snapshot);assert(!strcmp(snapshot[13],"FB publication busy") && pdx_mfb_lock==1);pdx_mfb_lock=0;
  // Concurrent starts copy per-caller data; each successful start has a unique
  // pending token. At most 64 starts exist, so this phase cannot replace a slot.
  framebuffer_reset();uint64_t tokens[4][16]={};unsigned selectors[5]={3,5,6,72,74};
  std::atomic<unsigned> ready{0};std::atomic<bool> go{false};std::vector<std::thread> workers;
  for(unsigned t=0;t<4;++t)workers.emplace_back([&,t]{caller_pid=100+t;ready.fetch_add(1);while(!go.load())std::this_thread::yield();
    for(unsigned n=0;n<16;++n){uint64_t words[3]={t,n,0xfeed};
      do{tokens[t][n]=pdx_framebuffer_call_begin((const void *)(uintptr_t)(0x1000+t),wrong_provider,selectors[n%5],3,words,t,n,2);
        if(!tokens[t][n])std::this_thread::yield();}while(!tokens[t][n]);}});
  while(ready.load()!=4)std::this_thread::yield();go.store(true);for(auto &worker:workers)worker.join();workers.clear();
  assert(pdx_mfb_issued==64 && !pdx_mfb_ended);bool seen[64]={};
  for(unsigned t=0;t<4;++t)for(unsigned n=0;n<16;++n){uint64_t token=tokens[t][n];assert(token>=1 && token<=64 && !seen[token-1]);seen[token-1]=true;
    const auto &c=pdx_mfb_calls[token-1];assert(c.token==token && c.status==-1 && !c.ended && c.pid==100+t && c.client==0x1000+t);
    assert(c.input[0]==t && c.input[1]==n && c.input[2]==0xfeed && c.selector==selectors[n%5] && !c.state_valid);}
  // Try-lock end losses are observable. Retry any unended records after joining
  // and require each selector's totals to reflect exactly one completed end.
  for(unsigned t=0;t<4;++t)workers.emplace_back([&,t]{for(unsigned n=16;n-->0;)pdx_framebuffer_call_end(tokens[t][n],n&1?-(int32_t)(100+t):0,2,output,n);});
  for(auto &worker:workers)worker.join();
  for(unsigned t=0;t<4;++t)for(unsigned n=0;n<16;++n){uint64_t token=tokens[t][n];if(!pdx_mfb_calls[token-1].ended)pdx_framebuffer_call_end(token,n&1?-(int32_t)(100+t):0,2,output,n);
    const auto &c=pdx_mfb_calls[token-1];assert(c.ended && c.status==(n&1?-(int32_t)(100+t):0));
    assert(c.output[0]==(n&1?0:output[0]) && c.output[1]==(n&1?0:output[1]));}
  assert(pdx_mfb_ended==64 && pdx_mfb_failed==32 && !pdx_mfb_lock);
  for(unsigned s=0;s<5;++s){unsigned calls=0,failures=0;for(unsigned n=0;n<16;++n)if(n%5==s){calls+=4;if(n&1)failures+=4;}
    assert(pdx_mfb_selectors[selectors[s]].calls==calls && pdx_mfb_selectors[selectors[s]].failures==failures);}
  assert(pdx_mfb_first_submit.token && pdx_mfb_first_submit.ended && pdx_mfb_first_failure.token);
  framebuffer_reset();clock_ns=1000000000ULL;
  puts("PASS framebuffer boundaries: client/provider identity, exact D27 state, bounded 3/2 scalars, selectors 3/5/6/72/74, first failure/submit, interleaved pending/end status, ring mismatch/double end/drop, concurrent tokens, RT/FB alternation");
}
static void swift_snapshot_tests(void){
  struct Guarded{uint64_t before;char rows[PDX_FIRST_FRAME_ROWS][48];uint64_t after;} g;
  auto capture=[&](unsigned now){memset(&g,0xa5,sizeof g);g.before=0x123456789abcdef0ULL;g.after=~g.before;
    pdx_first_frame_snapshot(now,g.rows);assert(g.before==0x123456789abcdef0ULL && g.after==~g.before);
    bounded(&g.rows[0][0],PDX_FIRST_FRAME_ROWS);};
  auto verify=[&](unsigned now,unsigned length){
    unsigned pages=(length+375)/376;if(!pages)pages=1;unsigned page=(now/24)%pages;char title[48];
    snprintf(title,48,"SWIFT qualified trap text part %u/%u",page+1,pages);assert(!strcmp(g.rows[13],title));
    for(unsigned i=0;i<8;++i){unsigned at=page*376+i*47;std::string expected=at<length?std::string(swift_payload+at,length-at<47?length-at:47):"";
      assert(g.rows[14+i]==expected);}
  };
  // Every payload length, including all page boundaries, is copied through the
  // actual optional-RAM API. Raw newlines survive snapshotting for the painter.
  swift_reply=1;unsigned before=swift_calls;
  for(unsigned length=1;length<=1535;++length){
    memset(swift_payload,'Z',sizeof swift_payload);
    for(unsigned n=0;n<length;++n)swift_payload[n]=n%61==17?'\n':(char)('A'+n%26);
    swift_write_length=length;unsigned pages=(length+375)/376;std::string reconstructed;
    for(unsigned page=0;page<pages;++page){unsigned now=16+page*24;capture(now);verify(now,length);
      reconstructed+=joined(g.rows,14,8);}
    assert(reconstructed==std::string(swift_payload,length));
  }
  assert(swift_calls>before);
  // A fully unterminated copy is clipped to 1535 bytes by the actual header.
  memset(swift_payload,'Q',sizeof swift_payload);swift_write_length=sizeof swift_payload;
  capture(112);verify(112,1535);assert(pdx_swift_trap_snapshot[1535]==0);
  // Early NUL over a dirty copied suffix, then an empty present report and a
  // busy/no-message return, must erase every old Swift tail row.
  for(unsigned length: {0u,1u,46u,47u,48u,375u,376u,377u,752u,1128u,1534u}){
    memset(swift_payload,'S',sizeof swift_payload);swift_payload[length]=0;
    capture(16);verify(16,length);assert(joined(g.rows,14,8)==std::string(swift_payload,length<376?length:376));
  }
  swift_reply=0;memset(swift_payload,'B',sizeof swift_payload);capture(16);
  assert(!strcmp(g.rows[13],"SWIFT no qualified message or capture busy"));
  for(unsigned i=14;i<22;++i)for(char c:g.rows[i])assert(!c);
  // Visible phases 0..143 contain six RT cycles, all three FB kinds twice and
  // the complete five-page Swift payload followed by the first page again.
  framebuffer_reset();const void *ptr=(const void *)(uintptr_t)1;
  uint64_t token=pdx_framebuffer_call_begin(ptr,ptr,3,0,nullptr,0,0,0);pdx_framebuffer_call_end(token,-3,0,nullptr,0);
  token=pdx_framebuffer_call_begin(ptr,ptr,5,0,nullptr,0,0,0);pdx_framebuffer_call_end(token,0,0,nullptr,0);
  token=pdx_framebuffer_call_begin(ptr,ptr,74,0,nullptr,0,0,0);pdx_framebuffer_call_end(token,-74,0,nullptr,0);
  swift_reply=1;swift_write_length=1535;for(unsigned i=0;i<1535;++i)swift_payload[i]=(char)('a'+i%26);
  unsigned fb_kinds=0,swift_pages=0;char detail[9][48];
  for(unsigned now=0;now<144;++now){unsigned calls=swift_calls;capture(now);unsigned phase=(now/8)%3;
    assert(swift_calls==calls+(phase==2));
    if(phase==0){assert(pdx_render_thread_rows(detail));assert(!memcmp(&g.rows[13],detail,sizeof detail));}
    else if(phase==1){assert(pdx_framebuffer_call_rows(now,detail));assert(!memcmp(&g.rows[13],detail,sizeof detail));
      unsigned kind=(now/24)%3;fb_kinds|=1u<<kind;
      assert(strstr(g.rows[16],kind==0?"FBFAIL id=1":kind==1?"FBSUB id=2":"FBLAST id=3"));}
    else {verify(now,1535);swift_pages|=1u<<((now/24)%5);}
  }
  assert(fb_kinds==7 && swift_pages==31);
  capture(UINT_MAX);bounded(&g.rows[0][0],PDX_FIRST_FRAME_ROWS);
  framebuffer_reset();swift_write_length=swift_reply=0;
  puts("PASS Swift RAM snapshot: every 1..1535-byte payload, five pages/24s cadence, raw newlines, clipped unterminated data, early NUL/empty/busy erase, RT/FB/Swift phases 0..143, all FB kinds visible");
}
static void failure_phase_tests(void){
  fill_data();boot_ui_trace_begin();pdx_render_collect(0,90,0x1114000,64);boot_ui_trace_publish();
  char rows[PDX_FIRST_FRAME_ROWS][48];memset(rows,0xa5,sizeof rows);
  pdx_first_frame_snapshot(0,rows);assert(strstr(rows[13],"RT1 tid=") && rows[14][0] && rows[21][0]);
  // The busy RT formatter exchanges any nonzero lock value to 1. Using a
  // distinctive held value observes whether the actual function was called,
  // without wrapping or modifying its implementation.
  trace_lock=0x51;unsigned calls=swift_calls;pdx_first_frame_snapshot(0,rows);
  assert(!strcmp(rows[13],"RT sample unavailable or publication busy") && trace_lock==1 && swift_calls==calls);
  for(unsigned i=14;i<22;++i)for(char c:rows[i])assert(!c);
  trace_lock=0;pdx_first_frame_snapshot(0,rows);assert(rows[14][0] && rows[21][0]);
  // PROC shares GC/GT's five rows. Busy publication must erase all four
  // detail rows even when the RAM GPU client and problem text are populated.
  assert(strstr(rows[8],"GC client0") && rows[9][0] && rows[10][0] && rows[11][0] && rows[12][0]);
  pdx_churn_lock=1;pdx_mfb_lock=1;trace_lock=0x52;
  pdx_first_frame_snapshot(8,rows);
  assert(!strcmp(rows[8],"PROC publication busy") && pdx_churn_lock==1);
  for(unsigned i=9;i<13;++i)for(char c:rows[i])assert(!c);
  assert(!strcmp(rows[13],"FB publication busy") && pdx_mfb_lock==1 && trace_lock==0x52);
  for(unsigned i=14;i<22;++i)for(char c:rows[i])assert(!c);
  pdx_churn_lock=pdx_mfb_lock=trace_lock=0;
  // Both non-RT phases must avoid the actual RT provider, including when it
  // could publish a valid nonempty stack and the selected provider is busy.
  for(unsigned now: {8u,32u,56u}){
    pdx_first_frame_snapshot(0,rows);assert(rows[14][0] && rows[21][0]);
    pdx_mfb_lock=1;trace_lock=0x53;calls=swift_calls;pdx_first_frame_snapshot(now,rows);
    assert(!strcmp(rows[13],"FB publication busy") && trace_lock==0x53 && pdx_mfb_lock==1 && swift_calls==calls);
    for(unsigned i=14;i<22;++i)for(char c:rows[i])assert(!c);
    pdx_mfb_lock=trace_lock=0;
  }
  swift_reply=1;swift_write_length=1535;memset(swift_payload,'S',sizeof swift_payload);
  pdx_first_frame_snapshot(16,rows);for(unsigned i=14;i<22;++i)assert(rows[i][0]);
  swift_reply=0;
  for(unsigned now: {16u,40u,64u}){
    trace_lock=0x54;calls=swift_calls;pdx_first_frame_snapshot(now,rows);
    assert(!strcmp(rows[13],"SWIFT no qualified message or capture busy") && trace_lock==0x54 && swift_calls==calls+1);
    for(unsigned i=14;i<22;++i)for(char c:rows[i])assert(!c);
    trace_lock=0;
  }
  // Independent progress-cache contention also leaves only its busy label.
  pdx_gpu_progress_lock=1;pdx_first_frame_snapshot(0,rows);
  assert(!strcmp(rows[25],"GP publication busy") && pdx_gpu_progress_lock==1);
  for(unsigned i=26;i<34;++i)for(char c:rows[i])assert(!c);
  pdx_gpu_progress_lock=0;swift_reply=swift_write_length=0;boot_ui_trace_begin();boot_ui_trace_publish();
  puts("PASS failed phases: PROC clears GC/GT, FB clears RT, RT/Swift/progress details blank on busy; actual RT provider reached only in RT phase");
}
static void trace_tests(void){
  // These are copied, already stripped user addresses, including addresses above 39 bits.
  memset(samples,0,sizeof samples);memset(sample_tid,0,sizeof sample_tid);
  const unsigned locations[3]={63,7,31};
  for(unsigned r=0;r<3;++r){
    unsigned i=locations[r];sample_tid[i]=recorded_tid[r];sample_state[i]=0x11+r;sample_pri[i]=40+(int)r;
    samples[i].pc=0x400123456780ULL+r*0x100;samples[i].lr=0x7ffffffffe00ULL+r*0x10;
    samples[i].frames[0]=0x600000000000ULL+r*0x100;
  }
  boot_ui_trace_begin();
  for(unsigned role: {1u,2u,3u,4u,UINT_MAX})pdx_render_collect(role,90,0x1114000,64);
  assert(!role_calls);
  pdx_render_collect(0,30,0x1114000,64);assert(role_calls==3);
  for(const auto &r:pdx_render_draft)assert(!r.tid);
  pdx_render_collect(0,90,0x1114000,64);assert(role_calls==6);
  for(unsigned r=0;r<3;++r){
    assert(requested_roles[r]==2 && pdx_render_draft[r].tid==recorded_tid[r]);
    assert(pdx_render_draft[r].entry.pc==samples[locations[r]].pc);
    assert(pdx_render_draft[r].entry.lr==samples[locations[r]].lr);
    assert(pdx_render_draft[r].entry.frames[0]==samples[locations[r]].frames[0]);
    assert(pdx_render_draft[r].slide==0x1114000 && pdx_render_draft[r].state==0x11+r);
    assert(pdx_render_draft[r].priority==40+(int)r);
  }
  // Publishing is the actual retained trace function, including its lock boundary.
  boot_ui_trace_publish();char rows[9][48];memset(rows,0xa5,sizeof rows);
  assert(pdx_render_thread_rows(rows));bounded(&rows[0][0],9);assert(!trace_lock);
  for(unsigned r=0;r<3;++r){
    char expected[48];snprintf(expected,48,"RT%u tid=%llx st=%x pri=%d",r+1,recorded_tid[r],0x11+r,40+(int)r);
    assert(!strcmp(rows[3*r],expected));
    snprintf(expected,48,"RT%u pc=%llx cache+=1114000",r+1,samples[locations[r]].pc);
    assert(!strcmp(rows[3*r+1],expected));
    snprintf(expected,48,"RT%u lr=%llx f1=%llx",r+1,samples[locations[r]].lr,samples[locations[r]].frames[0]);
    assert(!strcmp(rows[3*r+2],expected));
  }
  char published_rows[9][48];memcpy(published_rows,rows,sizeof rows);
  samples[63].pc=0x9999;pdx_render_collect(0,90,0x2222,64);
  assert(pdx_render_thread_rows(rows) && !memcmp(rows,published_rows,sizeof rows));
  trace_lock=1;memset(rows,0x7c,sizeof rows);char unchanged[9][48];memcpy(unchanged,rows,sizeof rows);
  assert(!pdx_render_thread_rows(rows) && trace_lock==1 && !memcmp(rows,unchanged,sizeof rows));
  boot_ui_trace_publish();assert(trace_lock==1);trace_lock=0;
  assert(pdx_render_thread_rows(rows) && !memcmp(rows,published_rows,sizeof rows));
  // Each capture clears roles that disappear; count excludes stale slots beyond its bound.
  boot_ui_trace_begin();pdx_render_collect(0,90,0x3333,8);boot_ui_trace_publish();
  assert(pdx_render_thread_rows(rows));
  assert(!strcmp(rows[0],"RT1 target not recorded") && !rows[1][0] && !rows[2][0]);
  assert(strstr(rows[3],"RT2 tid=200002") && !strcmp(rows[6],"RT3 target not recorded"));
  boot_ui_trace_begin();pdx_render_collect(0,90,0x4444,0);boot_ui_trace_publish();
  assert(pdx_render_thread_rows(rows));
  for(unsigned r=0;r<3;++r)assert(strstr(rows[r*3],"target not recorded") && !rows[r*3+1][0] && !rows[r*3+2][0]);
  assert(bt_user((1ULL<<47)-4,4) && !bt_user((1ULL<<47)-3,4) && !bt_user(1ULL<<47,1));
  puts("PASS render roles: recorded pid/tids and r1/r2/r3, role0 only, bounded count, capture clear, published copy, contention");
}
static void snapshot_tests(void){
  fill_data();
  struct Guarded{uint64_t before;char rows[PDX_FIRST_FRAME_ROWS][48];uint64_t after;} g;
  auto snapshot=[&](unsigned now){memset(&g,0xa5,sizeof g);g.before=0x123456789abcdef0ULL;g.after=~g.before;
    pdx_first_frame_snapshot(now,g.rows);assert(g.before==0x123456789abcdef0ULL && g.after==~g.before);bounded(&g.rows[0][0],PDX_FIRST_FRAME_ROWS);};
  unsigned seen_clients=0,seen_texts=0;
  for(unsigned turn=0;turn<8;++turn){
    snapshot(turn*16);char expected[48];unsigned i=99,j=99;
    assert(sscanf(g.rows[8],"GC client%u ",&i)==1 && i<8);seen_clients|=1u<<i;
    assert(i==turn);
    snprintf(expected,48,"GC client%u s%x p%xM",i,i==7?UINT32_MAX:i%5,0x41+i);assert(!strcmp(g.rows[8],expected));
    assert(sscanf(g.rows[10],"GT problem%u ",&j)==1 && j<8);seen_texts|=1u<<j;
    assert(j==turn);
    snprintf(expected,48,"GT problem%u part 1/2 below",j);assert(!strcmp(g.rows[10],expected));
    assert(joined(g.rows,11,2)==std::string(native_adreno_client_text[j].text,63));
    unsigned refused=i==7?0:0xb0+i%5;
    snprintf(expected,48,"GC hex o%x f%x c%x BOno%x",0x11+i,0x21+i,0x31+i,refused);assert(!strcmp(g.rows[9],expected));
  }
  if(seen_clients!=255 || seen_texts!=255){fprintf(stderr,"GPU rotation missed slots: client-mask=%02x text-mask=%02x expected=ff\n",seen_clients,seen_texts);abort();}
  for(unsigned now=0;now<128;++now){snapshot(now);
    if((now/8)&1)assert(!strncmp(g.rows[8],"PROC ",5));
    else {char expected[48];snprintf(expected,48,"GC client%u ",now/16);assert(strstr(g.rows[8],expected));}}
  snapshot(128);assert(strstr(g.rows[8],"GC client0 "));
  snapshot(UINT_MAX-8);bounded(&g.rows[0][0],PDX_FIRST_FRAME_ROWS);
  for(unsigned i=0;i<8;++i){if(i!=1 && i!=4 && i!=7)native_adreno_client_log[i].name[0]=0;
    if(i!=0 && i!=2 && i!=5 && i!=7)native_adreno_client_text[i].text[0]=0;}
  seen_clients=seen_texts=0;
  for(unsigned turn=0;turn<48;++turn){snapshot(turn*16);unsigned i=99,j=99;
    assert(sscanf(g.rows[8],"GC client%u ",&i)==1 && (i==1 || i==4 || i==7));seen_clients|=1u<<i;
    assert(sscanf(g.rows[10],"GT problem%u ",&j)==1 && (j==0 || j==2 || j==5 || j==7));seen_texts|=1u<<j;}
  assert(seen_clients==((1u<<1)|(1u<<4)|(1u<<7)) && seen_texts==((1u<<0)|(1u<<2)|(1u<<5)|(1u<<7)));
  memset(native_adreno_client_log,0,sizeof native_adreno_client_log);
  memset(native_adreno_client_text,0,sizeof native_adreno_client_text);
  snapshot(0);assert(!strcmp(g.rows[8],"GC no recorded GPU clients") && !g.rows[9][0]);
  assert(!strcmp(g.rows[10],"GT no client problem text recorded") && !g.rows[11][0] && !g.rows[12][0]);
  memset(native_adreno_client_log[0].name,'N',20);native_adreno_client_log[0].slot=UINT32_MAX;
  memset(native_adreno_client_text[0].name,'T',20);
  // Every length crosses the 47-column split, including all 63 producer payload bytes and early NULs over dirty suffixes.
  for(unsigned length=1;length<=64;++length){
    auto &t=native_adreno_client_text[0];memset(t.text,'Z',64);
    for(unsigned n=0;n<length;++n)t.text[n]=(char)('a'+n%26);
    if(length<64)t.text[length]=0;snapshot(0);
    const unsigned visible=length<63?length:63;
    assert(joined(g.rows,11,2)==std::string(t.text,visible));
    if(visible<=47)assert(!g.rows[12][0]);
    assert(strstr(g.rows[8],"GC NNNNNNNNNNNNNNNNNNN sffffffff"));
  }
  snapshot(0);
  assert(!strcmp(g.rows[1],"GF waits=111 timeouts=222"));
  assert(!strcmp(g.rows[2],"GF last timeout fence=333 saw=444"));
  assert(!strcmp(g.rows[3],"GF at timeout issued=555 done=666"));
  assert(!strcmp(g.rows[4],"GS hex submits=10 IBs=11 max=12"));
  assert(!strcmp(g.rows[5],"GR hex h30 r31 f32 s34"));
  assert(!strcmp(g.rows[6],"GM hex fails=23 step=20 st=21"));
  assert(!strcmp(g.rows[7],"GM hex BOno=42 st=43 live=44M"));
  assert(!strcmp(g.rows[34],"DS hex valid=60 kick=61 flight=62"));
  assert(!strcmp(g.rows[35],"DS hex ready-no=63 head-no=64 done=6b"));
  assert(!strcmp(g.rows[36],"GP hex stall=50 wait=51 ring=52/53"));
  std::string report;
  for(unsigned page=0;page<6;++page){snapshot(page*8);char expected[48];
    snprintf(expected,48,"DP prepare/vsync part %u/6",page+1);assert(!strcmp(g.rows[22],expected));
    report+=joined(g.rows,23,2);}
  assert(report==std::string(report_payload,511));
  for(unsigned length: {0u,1u,46u,47u,48u,93u,94u,95u,188u,510u,511u}){
    fill_data();report_payload[length]=0;report_length=length+1;
    unsigned pages=(length+93)/94;if(!pages)pages=1;report.clear();
    for(unsigned page=0;page<pages;++page){snapshot(page*8);char expected[48];
      snprintf(expected,48,"DP prepare/vsync part %u/%u",page+1,pages);assert(!strcmp(g.rows[22],expected));
      report+=joined(g.rows,23,2);}
    assert(report==std::string(report_payload,length));
  }
  // No later sample may retain a prior report's tail, even if the producer writes an empty report.
  report_payload[0]=0;report_length=1;snapshot(0);assert(!strcmp(g.rows[22],"DP prepare/vsync part 1/1"));
  assert(!g.rows[23][0] && !g.rows[24][0]);
  trace_lock=1;snapshot(0);assert(!strcmp(g.rows[13],"RT sample unavailable or publication busy"));
  for(unsigned r=14;r<22;++r)assert(!g.rows[r][0]);assert(trace_lock==1);trace_lock=0;
  puts("PASS snapshots: all eight slots/holes/wrap/UINT32_MAX, 1..63 text bytes, early NUL, timeout labels, 511-byte report, stale reset");
}
static void progress_tests(void){
  pdx_gpu_progress_last=pdx_gpu_progress_count=pdx_gpu_progress_missed=0;
  memset(pdx_gpu_progress_cache,0,sizeof pdx_gpu_progress_cache);fence_calls=preempt_calls=0;
  for(unsigned i=0;i<26;++i)preempt_values[i]=0x70+i;
  char rows[9][48];memset(rows,0xa5,sizeof rows);assert(pdx_gpu_progress_rows(rows));
  assert(!strcmp(rows[0],"GP no worker sample yet"));for(unsigned i=1;i<9;++i)for(char c:rows[i])assert(!c);
  pdx_gpu_progress_poll();assert(fence_calls==1 && preempt_calls==1 && pdx_gpu_progress_count==1);
  clock_ns+=499999999;pdx_gpu_progress_poll();assert(fence_calls==1 && preempt_calls==1);
  ++clock_ns;fence_issued=0xaa;fence_done=0xbb;fence_result=preempt_result=0;
  pdx_gpu_progress_poll();assert(fence_calls==2 && preempt_calls==2 && pdx_gpu_progress_count==2);
  render_busy=1;assert(pdx_gpu_progress_rows(rows));render_busy=0;
  assert(strstr(rows[0],"age500ms F1:85 i11 d22") && strstr(rows[3],"age0ms F0:85 iaa dbb"));
  assert(strstr(rows[4],"P0 L119 F120 C79"));
  assert(fence_calls==2 && preempt_calls==2); // Formatting reads cached data, never hooks.
  clock_ns+=500000000;fence_result=preempt_result=1;fence_issued=0xcc;pdx_gpu_progress_poll();
  clock_ns+=500000000;fence_issued=0xdd;pdx_gpu_progress_poll();
  assert(pdx_gpu_progress_count==4 && pdx_gpu_progress_rows(rows));
  assert(strstr(rows[0],"iaa dbb") && strstr(rows[3],"icc dbb") && strstr(rows[6],"idd dbb"));
  char before[9][48];memset(rows,0x6a,sizeof rows);memcpy(before,rows,sizeof rows);
  pdx_gpu_progress_lock=1;assert(!pdx_gpu_progress_rows(rows) && !memcmp(before,rows,sizeof rows) && pdx_gpu_progress_lock==1);
  auto cache_before=std::vector<unsigned char>((unsigned char*)pdx_gpu_progress_cache,(unsigned char*)pdx_gpu_progress_cache+sizeof pdx_gpu_progress_cache);
  clock_ns+=500000000;pdx_gpu_progress_poll();assert(pdx_gpu_progress_count==4 && pdx_gpu_progress_missed==1 && pdx_gpu_progress_lock==1);
  assert(!memcmp(cache_before.data(),pdx_gpu_progress_cache,sizeof pdx_gpu_progress_cache));pdx_gpu_progress_lock=0;
  clock_ns=UINT64_MAX;assert(pdx_gpu_progress_rows(rows));assert(strstr(rows[0],"age4294967295ms"));
  clock_ns=1;assert(pdx_gpu_progress_rows(rows));assert(strstr(rows[0],"age0ms"));
  clock_ns=1000000000ULL;pdx_gpu_progress_last=pdx_gpu_progress_count=pdx_gpu_progress_missed=0;
  memset(pdx_gpu_progress_cache,0,sizeof pdx_gpu_progress_cache);
  puts("PASS progress: 500ms cadence, three chronological samples, F0/P0 failure flags, ages/clamp, busy rows preserve bytes and poll skips publication, formatter makes no query");
}
static void churn_tests(void){
  for(auto &r:pdx_churn){r.enter=r.accepted=r.refused=r.exits=r.pid=r.ns=0;r.status=0;r.code=0;}
  pdx_churn_lock=pdx_churn_drops=0;census_starts=census_exits=0;
  boot_progress_process_stage(41,"bluetoothd","exec process signature enter");
  boot_progress_process_stage(41,"bluetoothd","exec process signature accepted");
  assert(pdx_churn[0].enter==1 && pdx_churn[0].accepted==1 && !pdx_churn[0].refused && census_starts==1);
  boot_progress_process_stage(43,"bluetoothd","exec process signature REFUSED");
  assert(pdx_churn[0].refused==1 && census_starts==1);
  recorder_available=false;boot_progress_process_stage(44,"bluetoothd","exec process signature enter");recorder_available=true;
  assert(pdx_churn[0].enter==2 && pdx_churn[0].pid==44 && census_starts==1);
  // Actual exit callback runs before the independently held general exit lock.
  exit_lock=1;boot_progress_exit(44,"bluetoothd",5,11,0x123456789abcdef0ULL);assert(exit_dropped==1);exit_lock=0;
  assert(pdx_churn[0].exits==1 && pdx_churn[0].status==5 && pdx_churn[0].ns==11 && pdx_churn[0].code==0x123456789abcdef0ULL);
  char rows[5][48];assert(pdx_churn_rows(8,rows));
  assert(!strcmp(rows[1],"enter=2 accepted=1 refused=1") && !strcmp(rows[2],"exits=1 rawst=5 namespace=11"));
  assert(strstr(rows[3],"code=123456789abcdef0 sig=5 exitcode=0"));
  boot_progress_exit(45,"aonsensed",0,17,0xff00);assert(pdx_churn_rows(24,rows));
  assert(!strcmp(rows[2],"exits=1 rawst=0 namespace=17") && strstr(rows[3],"sig=0 exitcode=0"));
  boot_progress_process_stage(50,"xpcproxy","exec process signature enter");boot_progress_process_stage(51,"xpcproxy","exec process signature enter");
  assert(pdx_churn[6].enter==2 && pdx_churn[6].pid==51);
  assert(pdx_churn_rows(104,rows) && strstr(rows[4],"name aggregates jobs"));
  pdx_churn_exec(55,"Apple.data.longjob","exec process signature accepted");assert(pdx_churn[7].accepted==1);
  assert(pdx_churn_name("LauncherControlExtension")==8 && pdx_churn_name("LauncherControlExten")==8);
  pdx_churn_exit(57,"LauncherControlExtension",5,11,0xfeed);assert(pdx_churn[8].exits==1 && pdx_churn[8].status==5);
  pdx_churn_exec(56,"unlisted","exec process signature enter");assert(pdx_churn_name(nullptr)==-1 && pdx_churn_name("unlisted")==-1);
  for(unsigned i=0;i<PDX_CHURN_CAP;++i){assert(pdx_churn_rows(i*16+8,rows));char expected[48];
    snprintf(expected,48,"PROC %.23s pid=%u",pdx_churn[i].name,pdx_churn[i].pid);assert(!strcmp(rows[0],expected));}
  auto prior=pdx_churn[0];pdx_churn_lock=1;memset(rows,0x7c,sizeof rows);char untouched[5][48];memcpy(untouched,rows,sizeof rows);
  assert(!pdx_churn_rows(8,rows) && !memcmp(rows,untouched,sizeof rows) && pdx_churn_lock==1);
  pdx_churn_exec(90,"bluetoothd","exec process signature accepted");pdx_churn_exit(90,"bluetoothd",5,11,9);
  assert(pdx_churn_drops==2 && !memcmp(&prior,&pdx_churn[0],sizeof prior));pdx_churn_lock=0;
  assert(pdx_churn_rows(8,rows) && strstr(rows[4],"drops=2"));
  char first[PDX_FIRST_FRAME_ROWS][48];pdx_first_frame_snapshot(8,first);
  for(unsigned i=0;i<5;++i)assert(!strcmp(rows[i],first[8+i]));
  pdx_first_frame_snapshot(0,first);assert(!strncmp(first[8],"GC ",3));
  // Snapshot retries start from cleared rows even when a publication was busy.
  pdx_churn_lock=1;pdx_first_frame_snapshot(8,first);assert(!strcmp(first[8],"PROC publication busy"));
  assert(pdx_churn_lock==1);pdx_churn_lock=0;
  puts("PASS churn: actual hooks before recorder/exit locks, enter+accepted counted separately once, REFUSED, raw SIGTRAP/ns/code, namespace-only exit, 12-name rotation/aggregate labels, trylock drops");
}
struct ExpectedRow{std::string text;uint32_t color;};
static std::string limited(const char *p,unsigned cap){return std::string(p,strnlen(p,cap-1));}
static void expect_wrap(std::vector<ExpectedRow> &rows,const char *text,unsigned cap,unsigned cols,uint32_t color){
  std::string value=limited(text,cap);for(char &c:value)if(c=='\n')c=' ';
  for(unsigned at=0;at<cap-1;at+=cols)rows.push_back({at<value.size()?value.substr(at,cols):"",color});
}
static std::vector<ExpectedRow> expected_rows(unsigned cols,const char first[][48],bool diagnostic){
  std::vector<ExpectedRow> rows;
  for(unsigned i=0;i<8;++i)rows.push_back({limited(boot_progress_ext[i],48).substr(0,cols),i<4?0xff80ffffu:0xffffa0ffu});
  for(unsigned i=0;i<2;++i)expect_wrap(rows,boot_progress_ext_wide[i],112,cols,0xffffa0ff);
  expect_wrap(rows,state_payload,128,cols,0xffffff00);expect_wrap(rows,clients_payload,128,cols,0xffffff00);
  if(diagnostic)for(unsigned i=0;i<PDX_FIRST_FRAME_ROWS;++i)expect_wrap(rows,first[i],48,cols,0xffaaffff);
  return rows;
}
static constexpr uint32_t untouched=0x12345678;
static uint32_t glyph_pixel(const std::string &text,unsigned col,unsigned dy,unsigned dx,uint32_t color){
  unsigned c=col<text.size()?(unsigned char)text[col]:' ';if(c<32 || c>126)c='?';
  uint64_t glyph=font[c-32];unsigned bits=dy<6?(unsigned)(glyph>>(32+dy*5)):dy<12?(unsigned)(glyph>>((dy-6)*5)):0;
  return dx<5 && ((bits>>dx)&1)?color:0;
}
static void verify_pixels(const std::vector<uint32_t> &pixels,unsigned w,unsigned h,unsigned stride,unsigned scale,
                          const std::vector<ExpectedRow> &rows){
  unsigned cols=rows.empty()?0:(w-(BP_COLS*6*scale+8)-8)/(6*scale);if(cols>47)cols=47;
  unsigned x0=BP_COLS*6*scale+8,top=13*14*scale;
  for(unsigned y=0;y<h;++y)for(unsigned x=0;x<stride/4;++x){
    uint32_t expected=untouched;
    if(!rows.empty() && y>=top && y<top+rows.size()*14*scale && x>=x0 && x<x0+cols*6*scale){
      unsigned row=(y-top)/(14*scale),col=(x-x0)/(6*scale),dy=((y-top)/scale)%14,dx=((x-x0)/scale)%6;
      expected=glyph_pixel(rows[row].text,col,dy,dx,rows[row].color);
    }
    if(pixels[16+(size_t)y*(stride/4)+x]!=expected){
      fprintf(stderr,"pixel %ux%u scale%u at %u,%u got=%x expected=%x rows=%zu\n",w,h,scale,x,y,pixels[16+(size_t)y*(stride/4)+x],expected,rows.size());abort();
    }
  }
  for(unsigned i=0;i<16;++i)assert(pixels[i]==untouched && pixels[pixels.size()-1-i]==untouched);
}
static void reset_cache(void){
  pdx_cached_invalidate();memset(pdx_cached_drawn,0,sizeof pdx_cached_drawn);
  pdx_cached_sampled=pdx_cached_second=0;pdx_cached_first_frame_on=-1;
  state_calls=clients_calls=report_calls=trace_calls=data_calls=option_calls=0;
}
static void bind_pixels(std::vector<uint32_t> &pixels,unsigned w,unsigned h,unsigned stride,unsigned scale){
  display={};display.frame=(uintptr_t)(pixels.data()+16);display.width=w;display.height=h;
  display.stride=stride;display.scale=scale;display.bound=1;
}
static void screen_data(void){
  fill_data();now_value=0;
  for(unsigned i=0;i<8;++i){for(unsigned n=0;n<48;++n)boot_progress_ext[i][n]=(char)('A'+(n+i)%26);}
  boot_progress_ext[0][3]=1;boot_progress_ext[0][4]=(char)0x80;
  for(unsigned i=0;i<2;++i)for(unsigned n=0;n<112;++n)boot_progress_ext_wide[i][n]=(char)('a'+(n+i)%26);
  boot_progress_ext_wide[0][17]='\n';memcpy(boot_progress_ext_wide[1]+91,"VISIBLE-FAILURE-TAIL",20);
}
static void geometry_tests(void){
  assert(PDX_FIRST_FRAME_ROWS==38 && PDX_CACHED_ROWS==64 && 38+26<=PDX_CACHED_ROWS);
  for(auto size: {std::pair<unsigned,unsigned>{1096,2560},{1644,3840},{2560,1096},{3840,1644}})
    assert(diagnostic_scale(size.first,size.second)==1);
  struct Geometry{unsigned w,h,scale;bool fits;} geometries[]={
    {1096,2560,1,true},{1644,3840,1,true},{2560,1096,1,true},
    {3840,1644,3,false}, // Painter's failure gate at the legacy scale; diagnostic bind forces 1.
    {3840,1644,1,true},{3100,3840,3,true}, // Diagnostic geometry and independent scaled painter.
    {1018,994,1,true},{1018,993,1,false},{1017,2560,1,false},
    {900,2560,1,false},{736,2560,1,false},{720,2560,1,false},{1096,2560,0,false}};
  for(auto g:geometries){
    screen_data();char first[PDX_FIRST_FRAME_ROWS][48];pdx_first_frame_snapshot(now_value,first);reset_cache();
    unsigned stride=g.w*4+64;std::vector<uint32_t> pixels((size_t)(stride/4)*g.h+32,untouched);
    bind_pixels(pixels,g.w,g.h,stride,g.scale);render_busy=1;ext_overlay_locked();render_busy=0;
    std::vector<ExpectedRow> rows;
    if(g.fits){unsigned cols=(g.w-(BP_COLS*6*g.scale+8)-8)/(6*g.scale);if(cols>47)cols=47;
      rows=expected_rows(cols,first,true);assert(rows.size()<=64);
      for(unsigned i=0;i<rows.size();++i)assert(pdx_cached_valid[i] && rows[i].text==pdx_cached_drawn[i]);
      for(unsigned i=(unsigned)rows.size();i<64;++i)assert(!pdx_cached_valid[i]);
      assert(state_calls==1 && clients_calls==1 && report_calls==1 && trace_calls==1);
      assert(joined(pdx_cached_drawn,20+11,2)==std::string(native_adreno_client_text[0].text,63));
      assert(joined(pdx_cached_drawn,11,3).find("VISIBLE-FAILURE-TAIL")!=std::string::npos);
    }else assert(!state_calls && !clients_calls && !report_calls && !trace_calls && !data_calls);
    verify_pixels(pixels,g.w,g.h,stride,g.scale,rows);
    auto before=pixels;ext_overlay_locked();assert(pixels==before);
    if(g.fits)assert(state_calls==1 && clients_calls==1 && report_calls==1 && trace_calls==1 && option_calls==1);
    printf("PASS geometry %ux%u scale=%u rows=%zu fits=%d\n",g.w,g.h,g.scale,rows.size(),g.fits);
  }
}
static void cache_tests(void){
  screen_data();reset_cache();unsigned w=1096,h=2560,stride=w*4+64;
  std::vector<uint32_t> pixels((size_t)(stride/4)*h+32,untouched);bind_pixels(pixels,w,h,stride,1);
  ext_overlay_locked();auto before=pixels;
  strcpy(native_adreno_client_text[0].text,"short");memset(native_adreno_client_text[0].text+6,'Z',58);
  report_payload[0]=state_payload[0]=clients_payload[0]=0;
  report_length=state_length=clients_length=1;
  ext_overlay_locked();assert(pixels==before && state_calls==1 && clients_calls==1 && trace_calls==1 && report_calls==1);
  ++now_value;char first[PDX_FIRST_FRAME_ROWS][48];pdx_first_frame_snapshot(now_value,first);
  unsigned prior=report_calls;ext_overlay_locked();assert(report_calls==prior+1 && state_calls==2 && clients_calls==2);
  // Empty state reports use the actual painter's explicit unavailable default.
  strcpy(state_payload,"D27 state unavailable");strcpy(clients_payload,"");
  auto expected=expected_rows(47,first,true);verify_pixels(pixels,w,h,stride,1,expected);
  assert(!strcmp(pdx_cached_drawn[31],"short") && !pdx_cached_drawn[32][0]);
  assert(!pdx_cached_drawn[43][0] && !pdx_cached_drawn[44][0]);
  // A same-second pass performs no stores; invalidation repaints from the cached sample.
  size_t marked=16+(size_t)13*14*(stride/4)+728;pixels[marked]=0x9abcdef0;before=pixels;
  prior=report_calls;ext_overlay_locked();assert(pixels==before && report_calls==prior);
  pdx_cached_invalidate();ext_overlay_locked();assert(pixels[marked]!=0x9abcdef0 && report_calls==prior);
  verify_pixels(pixels,w,h,stride,1,expected);
  for(unsigned condition=0;condition<5;++condition){
    before=pixels;unsigned calls=state_calls;auto saved=display;
    if(condition==0)display.bound=0;if(condition==1)display.yield_requested=1;
    if(condition==2)display.frame=0;if(condition==3)display.scale=0;if(condition==4)display.stride=w*4-4;
    ext_overlay_locked();assert(pixels==before && state_calls==calls);display=saved;
  }
  puts("PASS cache: once per second, unchanged rows make no stores, cached repaint, early-NUL/report stale erase, bound/yield/frame/scale/stride gates");
}
static void swift_painter_tests(void){
  screen_data();reset_cache();unsigned w=1096,h=2560,stride=w*4+64;
  std::vector<uint32_t> pixels((size_t)(stride/4)*h+32,untouched);bind_pixels(pixels,w,h,stride,1);
  swift_reply=1;swift_write_length=1535;
  for(unsigned i=0;i<sizeof swift_payload;++i)swift_payload[i]=i%41==17?'\n':(char)('A'+i%26);
  auto paint=[&](unsigned now){now_value=now;char first[PDX_FIRST_FRAME_ROWS][48];pdx_first_frame_snapshot(now,first);
    render_busy=1;ext_overlay_locked();render_busy=0;auto expected=expected_rows(47,first,true);
    verify_pixels(pixels,w,h,stride,1,expected);
    for(unsigned i=0;i<expected.size();++i)assert(expected[i].text==pdx_cached_drawn[i]);};
  // The real cached wrapper converts raw newlines to spaces, including across
  // Swift's 47-byte rows, and draws the last 31 bytes on its fifth page.
  for(unsigned page=0;page<6;++page){paint(16+page*24);std::string expected;
    unsigned at=(page%5)*376,length=1535-at<376?1535-at:376;
    expected.assign(swift_payload+at,length);for(char &c:expected)if(c=='\n')c=' ';
    assert(joined(pdx_cached_drawn,34,8)==expected);
  }
  swift_payload[1]=0;swift_write_length=1536;paint(160);assert(!strcmp(pdx_cached_drawn[34],"A"));
  for(unsigned i=35;i<42;++i)assert(!pdx_cached_drawn[i][0]);
  swift_reply=0;paint(184);for(unsigned i=34;i<42;++i)assert(!pdx_cached_drawn[i][0]);
  swift_reply=swift_write_length=0;
  puts("PASS Swift painter: all five pages and wrap, exact pixels/newline-to-space, early-NUL/busy stale erasure, full framebuffer bounds");
}
static void handoff_tests(void){
  screen_data();reset_cache();unsigned w=1096,h=2560,stride=w*4+64;
  std::vector<uint32_t> pixels((size_t)(stride/4)*h+32,untouched);bind_pixels(pixels,w,h,stride,1);
  pulse={};assert(bp_pulse_register(&pulse,display.frame,(uint64_t)stride*h,w,h,stride));
  assert(pulse.ready && pulse.screen.bound && pulse.screen.frame==display.frame+(uintptr_t)(h-32)*stride);
  ext_overlay_locked();auto before=pixels;render_busy=1;
  touch_overlay();assert(pixels==before && render_busy==1);
  assert(!boot_progress_prepare_scanout() && display.bound && display.yield_requested && !boot_progress_display_owned);
  assert(pixels==before);boot_progress_cancel_scanout();assert(!display.yield_requested);render_busy=0;
  pulse.busy=1;assert(!boot_progress_prepare_scanout() && display.bound && display.yield_requested && !render_busy);
  assert(pixels==before);boot_progress_cancel_scanout();pulse.busy=0;
  now_value=100;assert(boot_progress_prepare_scanout());
  assert(!display.bound && boot_progress_display_owned && !render_busy && !display.yield_requested);
  assert(pulse.closed && !pulse.ready && !pulse.screen.bound && !pulse.busy && last_scanout_at==100);
  assert(line_calls==1);
  const std::string handoff="DISPLAY HANDOFF: CPU scanout copy pending; diagnostic renderer yielding";
  for(unsigned y=0;y<h;++y)for(unsigned x=0;x<stride/4;++x){size_t at=16+(size_t)y*(stride/4)+x;
    assert(pixels[at]==(y<14 && x<119*6?glyph_pixel(handoff,x/6,y,x%6,0xffffff00):before[at]));}
  before=pixels;ext_overlay_locked();touch_overlay();assert(pixels==before && !banners);
  now_value=109;refresh(now_value);assert(!display.bound && pixels==before);
  now_value=110;refresh(now_value);assert(display.bound && !render_busy);
  for(unsigned i=0;i<64;++i)assert(!pdx_cached_valid[i]);
  for(unsigned y=0;y<h;++y)for(unsigned x=0;x<stride/4;++x)assert(pixels[16+(size_t)y*(stride/4)+x]==(x<w?0u:untouched));
  touch_overlay();assert(pdx_cached_valid[57] && !banners);
  before=pixels;now_value=120;assert(boot_progress_prepare_scanout() && pixels==before && line_calls==1);
  assert(last_scanout_at==120 && !bp_pulse_register(&pulse,display.frame,(uint64_t)stride*h,w,h,stride));
  touch_overlay();assert(pixels==before && !banners);
  enabled=0;assert(boot_progress_prepare_scanout() && !display.yield_requested && pixels==before);enabled=1;
  puts("PASS handoff: actual pulse lock, render ownership/yield/cancel, permanent pulse close, retained mapping/resume invalidation, banner=0");
}
static void option_tests(unsigned option){
  screen_data();reset_cache();option_value=option;option_present=option!=9;
  unsigned w=1096,h=2560,stride=w*4+64;std::vector<uint32_t> pixels((size_t)(stride/4)*h+32,untouched);
  bind_pixels(pixels,w,h,stride,1);ext_overlay_locked();
  char first[PDX_FIRST_FRAME_ROWS][48]={};auto rows=expected_rows(47,first,false);verify_pixels(pixels,w,h,stride,1,rows);
  assert(rows.size()==20 && !pdx_cached_valid[20] && !trace_calls && !report_calls && option_calls==1);
  option_value=1;ext_overlay_locked();assert(!trace_calls && !report_calls && option_calls==1);
  option_value=option;pdx_gpu_progress_poll();assert(!fence_calls && !preempt_calls && !pdx_gpu_progress_count);
  option_value=1;pdx_gpu_progress_poll();assert(!fence_calls && !preempt_calls); // worker also caches the boot option.
  option_value=option;assert(diagnostic_scale(3840,1644)==3);
  printf("PASS opt-in option=%u: legacy panel only, boot argument cached\n",option);
}
int main(int argc,char **argv){
  setvbuf(stdout,nullptr,_IONBF,0);assert(argc==2);unsigned option=(unsigned)atoi(argv[1]);
  if(option!=1){option_tests(option);return 0;}
  trace_tests();framebuffer_tests();swift_snapshot_tests();failure_phase_tests();progress_tests();churn_tests();geometry_tests();cache_tests();swift_painter_tests();handoff_tests();snapshot_tests();
  puts("PASS actual diagnostic headers and framebuffer; no GPU/device behavior modeled");
}
'''


MISSING_SCREEN = r'''
static uint64_t mach_absolute_time(void){return 1000000000ULL;}
static void absolutetime_to_nanoseconds(uint64_t t,uint64_t *ns){*ns=t;}
static int PE_parse_boot_argn(const char *,void *,unsigned);
static int proc_selfpid(void){return 42;}
#include "PdxGpuProgressCache.h"
#include "PdxProcessChurnDiagnostics.h"
#include "PdxFramebufferCallDiagnostics.h"
#include "PdxFirstFrameDiagnostics.h"
static bp_display display;
static char boot_progress_ext[8][48],boot_progress_ext_wide[2][112];
static unsigned seconds(void){return 7;}
static void ext_data_rows(void){}
static int PE_parse_boot_argn(const char *,void *out,unsigned){*(unsigned*)out=1;return 1;}
#include "PdxBootCachedDiagnostics.h"
int main(void){
  char rows[PDX_FIRST_FRAME_ROWS][48];memset(rows,0xa5,sizeof rows);pdx_first_frame_snapshot(7,rows);
  assert(!strcmp(rows[0],"FIRSTFRAME 7s trace=-1"));
  assert(!strcmp(rows[1],"GF wait diagnostics unavailable"));
  assert(!strcmp(rows[13],"RT sample unavailable or publication busy"));
  assert(!strcmp(rows[25],"GP no worker sample yet") && !strcmp(rows[37],"GP samples=0 skipped=0"));
  for(unsigned i=0;i<PDX_FIRST_FRAME_ROWS;++i)if(i!=0 && i!=1 && i!=13 && i!=25 && i!=37)for(char c:rows[i])assert(!c);
  memset(rows,0x5a,sizeof rows);pdx_first_frame_snapshot(16,rows);
  for(unsigned i=0;i<PDX_FIRST_FRAME_ROWS;++i)assert(memchr(rows[i],0,48));
  assert(!strcmp(rows[13],"SWIFT no qualified message or capture busy"));
  for(unsigned i=14;i<22;++i)for(char c:rows[i])assert(!c);
  pdx_gpu_progress_poll();assert(pdx_gpu_progress_count==1 && !pdx_gpu_progress_cache[0].fence_ok && !pdx_gpu_progress_cache[0].preempt_ok);
  uint64_t token=pdx_framebuffer_call_begin((const void *)(uintptr_t)1,(const void *)(uintptr_t)1,3,0,nullptr,0,0,0);
  assert(token==1 && !pdx_mfb_calls[0].state_valid);pdx_framebuffer_call_end(token,0,0,nullptr,0);
  memset(rows,0x5a,sizeof rows);pdx_first_frame_snapshot(8,rows);
  assert(!strcmp(rows[13],"FB hex calls=1 done=1 fail=0"));
  assert(!strcmp(rows[16],"FB first failure not recorded"));
  for(unsigned i=17;i<22;++i)for(char c:rows[i])assert(!c);
  unsigned w=1096,h=2560,stride=w*4+64;std::vector<uint32_t> pixels((size_t)(stride/4)*h+32,0x12345678);
  display.frame=(uintptr_t)(pixels.data()+16);display.width=w;display.height=h;display.stride=stride;display.scale=display.bound=1;
  ext_overlay_locked();assert(!strcmp(pdx_cached_state,"D27 state unavailable") && !strcmp(pdx_cached_clients,"opens unavailable"));
  assert(pdx_cached_valid[57]);
  for(unsigned y=0;y<h;++y)for(unsigned x=0;x<stride/4;++x)
    if(y<182 || y>=994 || x<728 || x>=1010)assert(pixels[16+(size_t)y*(stride/4)+x]==0x12345678);
  for(unsigned i=0;i<16;++i)assert(pixels[i]==0x12345678 && pixels[pixels.size()-1-i]==0x12345678);
  puts("PASS absent optional symbols: dirty rows reset, explicit unavailable text, cached painter defaults/bounds");
}
'''


MISSING_RENDER = r'''
static bt_entry samples[BT_MAX_THREADS];
static uint64_t sample_tid[BT_MAX_THREADS];
static unsigned sample_state[BT_MAX_THREADS],trace_lock;
static int sample_pri[BT_MAX_THREADS];
#include "PdxRenderThreadDiagnostics.h"
int main(void){
  memset(pdx_render_draft,0x5a,sizeof pdx_render_draft);pdx_render_begin();
  pdx_render_collect(0,90,0x1114000,64);pdx_render_publish();char rows[9][48];memset(rows,0xa5,sizeof rows);
  assert(pdx_render_thread_rows(rows));
  for(unsigned r=0;r<3;++r){char expected[48];snprintf(expected,48,"RT%u target not recorded",r+1);
    assert(!strcmp(rows[r*3],expected) && !rows[r*3+1][0] && !rows[r*3+2][0]);}
  puts("PASS absent recorded-role provider: no stale roles and no invented target");
}
'''


def trace_storage(traced):
    macros = '\n'.join(re.findall(r'^#define BT_(?:HOT|HOT_MIN_RATE|HOT_FRAMES|KFRAMES|CPU|TRAPPED) .*$', traced, re.M))
    types = '\n'.join(re.findall(r'^struct bt_(?:prev|hotrow) \{[^\n]+', traced, re.M))
    start = traced.index('#define BT_ROLES 4\n')
    end = traced.index('#include "PdxRenderThreadDiagnostics.h"')
    storage = traced[start:end]
    assert storage.count('static unsigned trace_lock;') == 1
    samples = '''static struct bt_entry samples[BT_MAX_THREADS];
static uint64_t sample_tid[BT_MAX_THREADS];
static unsigned sample_state[BT_MAX_THREADS];static int sample_pri[BT_MAX_THREADS];
'''
    return macros+'\n'+types+'\n'+samples+storage


def run_logged(command, log, *, env=None):
    run = subprocess.run(command, capture_output=True, text=True, env=env)
    log.write_text(run.stdout+run.stderr)
    if run.returncode:
        raise RuntimeError(f'{log.name}: exit {run.returncode}\n{run.stdout}{run.stderr}')
    return run.stdout


def verify_build(built, staged, adapted, traced, details):
    import swift_trap_diagnostic as swift_overlay

    ci = Path(__file__).resolve().parent
    result = json.loads((built/'result.json').read_text())
    assert result['first_frame_diagnostics'] is True
    archive = built/'libPdxBootScreen.a'
    assert sha(archive.read_bytes()) == result['sha256']
    headers = {}
    for name in (*HEADERS, 'BootUiTraceDetails.h'):
        assert (built/name).read_bytes() == (staged/name).read_bytes(), f'Stale compiled header: {name}'
        headers[name] = sha((built/name).read_bytes())
        recorded = result['diagnostic_headers'] if name in ('PdxBootCachedDiagnostics.h','BootUiTraceDetails.h') else result['first_frame_headers']
        assert recorded[name] == headers[name]
    objects = []
    for name in ('BootProgress','BootFaultProbe','BootProcessProbe','BootUiTraceProbe'):
        source = built/(name+'.c')
        entry = next(item for item in result['sources'] if Path(item['source']).name == source.name)
        assert sha(source.read_bytes()) == entry['sha256']
        assert sha(Path(entry['original']).read_bytes()) == entry['original_sha256']
        cmd = json.loads((built/(name+'.command.json')).read_text())
        assert '-fptrauth-function-pointer-type-discrimination' in cmd
        assert '--target=arm64e-apple-ios27.0.0' in cmd and '-mgeneral-regs-only' in cmd
        assert str(source) in cmd
        identity = subprocess.check_output(['file',str(built/(name+'.o'))],text=True).strip()
        assert 'arm64e' in identity
        objects.append(dict(name=name,sha256=sha((built/(name+'.o')).read_bytes()),identity=identity))
    compiled_progress = (built/'BootProgress.c').read_text()
    compiled_trace = (built/'BootUiTraceProbe.c').read_text()
    for name in ('static void refresh(unsigned now)', 'int boot_progress_prepare_scanout(void)',
                 'void boot_progress_cancel_scanout(void)', 'void boot_progress_process_stage(',
                 'void boot_progress_exit(', 'void boot_progress_bind('):
        assert method(compiled_progress,name) == method(adapted,name)
    for name in ('void boot_ui_trace_begin(void)', 'void boot_ui_trace_publish(void)', 'void boot_ui_trace_task('):
        assert method(compiled_trace,name) == method(traced,name)
    assert compiled_progress.count('#include "PdxFirstFrameDiagnostics.h"') == 1
    assert compiled_progress.count('#include "PdxBootCachedDiagnostics.h"') == 1
    assert (built/'BootUiTraceDetails.h').read_text() == details
    swift = result['swift_trap_diagnostic']
    assert swift['verified'] is True
    swift_header = swift_overlay.HEADER
    local_header = (ci/swift_header).read_bytes()
    assert (built/swift_header).read_bytes() == local_header, 'Stale compiled Swift collector header'
    assert sha(local_header) == swift['header_sha256']
    assert sha(Path(swift_overlay.__file__).read_bytes()) == swift['overlay_sha256']
    swift_receipt_path = Path(swift['tests_receipt'])
    swift_receipt_bytes = swift_receipt_path.read_bytes()
    assert sha(swift_receipt_bytes) == swift['tests_sha256']
    swift_receipt = json.loads(swift_receipt_bytes)
    assert swift_receipt['passed'] is True and swift_receipt['hardware_verified'] is False
    assert swift_receipt['header_sha256'] == swift['header_sha256']
    assert swift_receipt['overlay_sha256'] == swift['overlay_sha256']
    assert swift_receipt['tests_sha256'] == sha((ci/'swift_trap_diagnostic_tests.py').read_bytes())
    fault_entry = next(item for item in result['sources'] if Path(item['source']).name == 'BootFaultProbe.c')
    original_fault = Path(fault_entry['original']).read_text()
    fault = swift_overlay.adapt_fault(original_fault)
    assert (built/'BootFaultProbe.c').read_text() == fault, 'Compiled fault source differs from actual Swift overlay'
    assert swift_receipt['fault_source_sha256'] == fault_entry['original_sha256'] == swift_overlay.FAULT_SHA256
    assert swift_receipt['source_checks']['original_source_sha256'] == fault_entry['original_sha256']
    assert swift_receipt['source_checks']['adapted_source_sha256'] == sha(fault.encode())
    assert swift_receipt['source_checks']['staged_header_sha256'] == swift['header_sha256']
    assert swift_receipt['source_checks']['trap_user_reads'] is False
    assert swift_receipt['source_checks']['reason_scan_unchanged'] is True
    for obj, names in (('BootProgress',tuple(name for name in HEADERS if name!='PdxRenderThreadDiagnostics.h')),
                       ('BootUiTraceProbe',(HEADERS[1],'BootUiTraceDetails.h')),
                       ('BootFaultProbe',(swift_header,))):
        deps = (built/(obj+'.o.d')).read_text()
        for name in names:assert str(built/name) in deps, f'Missing compiler dependency: {name}'
    members = subprocess.check_output(['llvm-ar','t',str(archive)],text=True).splitlines()
    assert sorted(members) == sorted(item['name']+'.o' for item in objects)
    return dict(archive=str(archive),sha256=result['sha256'],headers=headers,objects=objects,
                swift_trap_diagnostic=dict(verified=True,header_sha256=swift['header_sha256'],
                    overlay_sha256=swift['overlay_sha256'],tests_receipt=str(swift_receipt_path),
                    tests_sha256=swift['tests_sha256'],fault_source_sha256=sha(fault.encode()),
                    exact_fault_overlay_and_header_dependency_verified=True,
                    hardware_verified=False),
                source_hooks_and_dependency_provenance_verified=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base',type=Path,default=Path('/mnt/e/UniXNU-sheng27-sony-20261113'))
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--built',type=Path,help='Fresh --first-frame native build; stale headers are rejected')
    args = parser.parse_args()
    if not __debug__:raise RuntimeError('Run without Python -O: assertions are test checks')
    if shutil.disk_usage('/mnt/g').free < 8*1024**3:raise RuntimeError('G: free space below 8 GiB')
    out = args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    ci = Path(__file__).resolve().parent;package=args.base/'sources/sheng/package'
    overlay_hash=sha(Path(overlay.__file__).read_bytes())
    probe=args.base/'display-source-009/kits/sheng/LegacyDisplayProbe.cpp'
    overlay.qualify(probe.read_text(),overlay.DISPLAY_PROBE_SHA256)
    inputs = {name:(ci/name).read_bytes() for name in HEADERS}
    input_hashes = {name:sha(data) for name,data in inputs.items()}
    adapted,traced,details,checks = source_checks(package)
    checks['display_probe_sha256']=sha(probe.read_bytes())
    checks['overlay_sha256']=overlay_hash
    for name,data in inputs.items():(out/name).write_bytes(data)
    (out/'BootUiTraceDetails.h').write_text(details)
    (out/'adapted-BootProgress.c').write_text(adapted)
    (out/'adapted-BootUiTraceProbe.c').write_text(traced)
    lifecycle = '\n'.join(method(adapted,name) for name in (
        'static void refresh(unsigned now)', 'int boot_progress_prepare_scanout(void)',
        'void boot_progress_cancel_scanout(void)', 'static void touch_overlay(void)',
        'void boot_progress_process_stage(', 'void boot_progress_exit('))
    assert lifecycle.count('__asm__ volatile("dsb sy" ::: "memory");') == 1
    lifecycle = lifecycle.replace('__asm__ volatile("dsb sy" ::: "memory");','__atomic_thread_fence(__ATOMIC_SEQ_CST);')
    code = PRELUDE+FIXTURES+trace_storage(traced)+'\n#include "PdxRenderThreadDiagnostics.h"\n'
    code += method(traced,'void boot_ui_trace_begin(void)')+'\n'+method(traced,'void boot_ui_trace_publish(void)')
    binding=method(adapted,'void boot_progress_bind(')
    scale_fragment=binding[binding.index('display.scale=w>=2160'):binding.index('\n    memset(display.previous')]
    scale_function='static unsigned diagnostic_scale(unsigned w,unsigned h){bp_display display={};'+scale_fragment+'return display.scale;}\n'
    code += '\n'+SCREEN_GLOBALS+lifecycle+'\n'+scale_function+ACTUAL_TESTS
    font = ci.parents[1]/'uefi-pdx234/Silicon/Silicium/SiliciumPkg/Library/FrameBufferSerialPortLib'
    command = ['clang++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror',
               '-Wno-ignored-attributes','-Wno-pointer-bool-conversion','-Wno-unused-function',
               '-Wno-unused-variable','-Wno-missing-field-initializers','-fsanitize=address,undefined','-fno-sanitize-recover=all',
               '-fno-omit-frame-pointer','-pthread','-I'+str(out),'-I'+str(package),'-I'+str(font)]
    environment = dict(os.environ,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    results=[]
    for name,source,options in (('actual-first-frame',code,('1','0','2','9')),):
        (out/(name+'.cpp')).write_text(source)
        cmd = command+[str(out/(name+'.cpp')),'-o',str(out/name)]
        run_logged(cmd,out/(name+'-compile.log'))
        for option in options:
            invocation=[str(out/name),option]
            output=run_logged(invocation,out/(name+'-'+option+'.log'),env=environment)
            results.append(dict(command=invocation,output=output))
    # Clang's Mach-O weak_import is not a portable ELF linker contract. First try
    # it unchanged; only when needed add explicit ELF weak pragmas in the fixture.
    # The production header bytes are unchanged in both attempts.
    weak_results=[]
    for name,body,headers in (('missing-screen',MISSING_SCREEN,tuple(h for h in HEADERS if h!='PdxRenderThreadDiagnostics.h')),
                              ('missing-render',MISSING_RENDER,(HEADERS[1],))):
        symbols=[]
        for header in headers:
            symbols += re.findall(r'^extern .*?\b(native_[A-Za-z0-9_]+|pdx_render_thread_rows|pdx_swift_trap_text)(?:\[|\(| __attribute__)',inputs[header].decode(),re.M)
        path=out/(name+'.cpp');path.write_text(PRELUDE+body)
        cmd=command+[str(path),'-o',str(out/name)]
        compile_run=subprocess.run(cmd,capture_output=True,text=True)
        (out/(name+'-native-weak-compile.log')).write_text(compile_run.stdout+compile_run.stderr)
        bridge=compile_run.returncode!=0
        if bridge:
            assert 'undefined reference' in compile_run.stderr, compile_run.stderr
            path.write_text(PRELUDE+'\n'.join('#pragma weak '+symbol for symbol in sorted(set(symbols)))+'\n'+body)
            run_logged(cmd,out/(name+'-elf-weak-compile.log'))
        output=run_logged([str(out/name)],out/(name+'.log'),env=environment)
        undefined=subprocess.check_output(['nm','-u','-C',str(out/name)],text=True)
        (out/(name+'-undefined.txt')).write_text(undefined)
        for symbol in symbols:
            lines=[line for line in undefined.splitlines() if symbol in line]
            assert lines and all(re.match(r'\s+[wv] ',line) for line in lines), f'Provider was not weak/absent: {symbol}'
        weak_results.append(dict(name=name,elf_weak_pragma_bridge=bridge,optional_symbols=sorted(set(symbols)),output=output))
    build=verify_build(args.built.resolve(),out,adapted,traced,details) if args.built else None
    for name,data in inputs.items():assert (ci/name).read_bytes()==data, f'{name} changed while tests ran; rerun against current headers'
    assert sha(Path(overlay.__file__).read_bytes()) == overlay_hash, 'Overlay changed while tests ran; rerun'
    receipt=dict(passed=True,compiler=subprocess.check_output(['clang++','--version'],text=True).splitlines()[0],
                 compile_flags=command,headers=input_hashes,source_checks=checks,
                 harness_sha256=sha(code.encode()),test_script_sha256=sha(Path(__file__).read_bytes()),
                 results=results,missing_symbols=weak_results,native_build=build,
                 substitutions=['ARM dsb sy -> host sequentially consistent fence only in extracted lifecycle'],
                 fixtures='Recorded RAM arrays/strings/tids; recorder availability and draw/optional touch/banner service boundaries',
                 actual_code='Six byte-identical headers, BootProgress core/display/pulse/lifecycle, extracted refresh/handoff/cancel/touch/process-stage/exit, trace begin/publish',
                 gpu_behavior_modeled=False,device_operations=False,hardware_verified=False,
                 native_compile_provenance_verified=build is not None)
    (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt,indent=2))


if __name__=='__main__':
    main()
