// SPDX-License-Identifier: MIT
// Best-effort copies of existing RAM diagnostics, once per displayed second.
// Never call a GPU/query method here: the bound painter holds render_busy.
#ifndef PDX_FIRST_FRAME_DIAGNOSTICS_H
#define PDX_FIRST_FRAME_DIAGNOSTICS_H
enum {PDX_FIRST_FRAME_ROWS=38,PDX_FIRST_FRAME_COLS=48};
struct pdx_frame_client {char name[20];uint32_t opens,refused,closes,slot,peak_mib,last_refusal;};
struct pdx_frame_text {char name[20];char text[64];};
extern struct pdx_frame_client native_adreno_client_log[8] __attribute__((weak_import));
extern struct pdx_frame_text native_adreno_client_text[8] __attribute__((weak_import));
extern volatile uint32_t native_adreno_fence_wait[8] __attribute__((weak_import));
extern volatile uint32_t native_adreno_submit_ibs[4] __attribute__((weak_import));
extern volatile uint32_t native_adreno_recovery[8] __attribute__((weak_import));
extern volatile uint32_t native_adreno_mount_fail[4] __attribute__((weak_import));
extern volatile uint32_t native_adreno_bo_memory[8] __attribute__((weak_import));
extern volatile uint32_t native_adreno_stall_ring[10] __attribute__((weak_import));
extern volatile uint32_t native_adreno_client_stats[5][6] __attribute__((weak_import));
extern volatile uint32_t native_legacy_swapstat[16] __attribute__((weak_import));
extern unsigned native_legacy_prepare_report(char *,unsigned) __attribute__((weak_import));
extern int native_gpu_trace_enabled(void) __attribute__((weak_import));
extern int pdx_render_thread_rows(char [9][48]) __attribute__((weak_import));
extern unsigned pdx_swift_trap_text(char *,unsigned) __attribute__((weak_import));
static char pdx_swift_trap_snapshot[1536];

static void pdx_first_frame_snapshot(unsigned now,char rows[PDX_FIRST_FRAME_ROWS][PDX_FIRST_FRAME_COLS]) {
  memset(rows,0,PDX_FIRST_FRAME_ROWS*PDX_FIRST_FRAME_COLS);
  snprintf(rows[0],48,"FIRSTFRAME %us trace=%d",now,native_gpu_trace_enabled?native_gpu_trace_enabled():-1);
  if(&native_adreno_fence_wait) {
    const volatile uint32_t *v=native_adreno_fence_wait;
    snprintf(rows[1],48,"GF waits=%u timeouts=%u",v[0],v[1]);
    snprintf(rows[2],48,"GF last timeout fence=%u saw=%u",v[2],v[3]);
    snprintf(rows[3],48,"GF at timeout issued=%u done=%u",v[4],v[5]);
  } else snprintf(rows[1],48,"GF wait diagnostics unavailable");
  if(&native_adreno_submit_ibs)
    snprintf(rows[4],48,"GS hex submits=%x IBs=%x max=%x",native_adreno_submit_ibs[0],native_adreno_submit_ibs[1],native_adreno_submit_ibs[2]);
  if(&native_adreno_recovery)
    snprintf(rows[5],48,"GR hex h%x r%x f%x s%x",native_adreno_recovery[0],native_adreno_recovery[1],native_adreno_recovery[2],native_adreno_recovery[4]);
  if(&native_adreno_mount_fail)
    snprintf(rows[6],48,"GM hex fails=%x step=%x st=%x",native_adreno_mount_fail[3],native_adreno_mount_fail[0],native_adreno_mount_fail[1]);
  if(&native_adreno_bo_memory)
    snprintf(rows[7],48,"GM hex BOno=%x st=%x live=%xM",native_adreno_bo_memory[2],native_adreno_bo_memory[3],native_adreno_bo_memory[4]);
  if(&native_adreno_client_log) {
    unsigned used=0;for(unsigned i=0;i<8;++i)if(native_adreno_client_log[i].name[0])++used;
    if(used) {
      unsigned pick=(now/16)%used;
      for(unsigned i=0;i<8;++i)if(native_adreno_client_log[i].name[0] && !pick--) {
        struct pdx_frame_client c;memcpy(&c,&native_adreno_client_log[i],sizeof c);c.name[19]=0;
        snprintf(rows[8],48,"GC %.19s s%x p%xM",c.name,c.slot,c.peak_mib);
        const unsigned refused=&native_adreno_client_stats && c.slot<5?native_adreno_client_stats[c.slot][2]:0;
        snprintf(rows[9],48,"GC hex o%x f%x c%x BOno%x",c.opens,c.refused,c.closes,refused);
        break;
      }
    } else snprintf(rows[8],48,"GC no recorded GPU clients");
  }
  if(&native_adreno_client_text) {
    unsigned used=0;for(unsigned i=0;i<8;++i)if(native_adreno_client_text[i].text[0])++used;
    if(used) {
      unsigned pick=(now/16)%used;
      for(unsigned i=0;i<8;++i)if(native_adreno_client_text[i].text[0] && !pick--) {
        struct pdx_frame_text t;memcpy(&t,&native_adreno_client_text[i],sizeof t);t.name[19]=0;t.text[63]=0;
        snprintf(rows[10],48,"GT %.19s part 1/2 below",t.name);
        memcpy(rows[11],t.text,47);rows[11][47]=0;
        if(strnlen(t.text,sizeof t.text)>47)snprintf(rows[12],48,"%s",t.text+47);
        break;
      }
    } else snprintf(rows[10],48,"GT no client problem text recorded");
  }
  if((now/8)&1) {
    memset(&rows[8],0,5*48);
    if(!pdx_churn_rows(now,&rows[8]))snprintf(rows[8],48,"PROC publication busy");
  }
  if((now/8)%3==0) {
    if(!pdx_render_thread_rows || !pdx_render_thread_rows(&rows[13]))
      snprintf(rows[13],48,"RT sample unavailable or publication busy");
  } else if((now/8)%3==1) {
    if(!pdx_framebuffer_call_rows(now,&rows[13]))snprintf(rows[13],48,"FB publication busy");
  } else if((now/8)%3==2) {
    memset(&rows[13],0,9*48);memset(pdx_swift_trap_snapshot,0,sizeof pdx_swift_trap_snapshot);
    const unsigned present=pdx_swift_trap_text?pdx_swift_trap_text(pdx_swift_trap_snapshot,sizeof pdx_swift_trap_snapshot):0;
    pdx_swift_trap_snapshot[sizeof pdx_swift_trap_snapshot-1]=0;
    if(present) {
      const unsigned length=(unsigned)strnlen(pdx_swift_trap_snapshot,sizeof pdx_swift_trap_snapshot);
      const unsigned pages=(length+375)/376,page=pages?(now/24)%pages:0;
      snprintf(rows[13],48,"SWIFT qualified trap text part %u/%u",page+1,pages?pages:1);
      for(unsigned i=0;i<8;++i) {
        const unsigned at=page*376+i*47;
        if(at<length)snprintf(rows[14+i],48,"%.47s",pdx_swift_trap_snapshot+at);
      }
    } else snprintf(rows[13],48,"SWIFT no qualified message or capture busy");
  }
  if(native_legacy_prepare_report) {
    char text[512];memset(text,0,sizeof text);
    (void)native_legacy_prepare_report(text,sizeof text);text[511]=0;
    const size_t length=strnlen(text,sizeof text);
    const unsigned pages=(unsigned)((length+93)/94),page=pages?(now/8)%pages:0;
    snprintf(rows[22],48,"DP prepare/vsync part %u/%u",page+1,pages?pages:1);
    for(unsigned part=0;part<2;++part) {
      const unsigned start=page*94+part*47;
      if(start<length)snprintf(rows[23+part],48,"%.47s",text+start);
    }
  }
  if(!pdx_gpu_progress_rows(&rows[25]))snprintf(rows[25],48,"GP publication busy");
  if(&native_legacy_swapstat) {
    const volatile uint32_t *v=native_legacy_swapstat;
    snprintf(rows[34],48,"DS hex valid=%x kick=%x flight=%x",v[0],v[1],v[2]);
    snprintf(rows[35],48,"DS hex ready-no=%x head-no=%x done=%x",v[3],v[4],v[11]);
  }
  if(&native_adreno_stall_ring) {
    const volatile uint32_t *v=native_adreno_stall_ring;
    snprintf(rows[36],48,"GP hex stall=%x wait=%x ring=%x/%x",v[0],v[1],v[2],v[3]);
  }
  snprintf(rows[37],48,"GP samples=%u skipped=%u",pdx_gpu_progress_count,pdx_gpu_progress_missed);
}
#endif
