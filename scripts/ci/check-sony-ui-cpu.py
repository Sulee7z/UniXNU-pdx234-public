#!/usr/bin/env python3
"""Test actual063 display handoff functions and the new per-core observer boundaries."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def body(text,signature):
    at=text.index(signature);brace=text.index('{',at);end=brace+1;depth=1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return text[at:end]


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True)
    a=parser.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    source=BASE/'native-sony-touch-062-002/BootProgress.c'
    text=source.read_text()
    methods='\n'.join(body(text,signature) for signature in ('static void refresh(unsigned now)',
        'int boot_progress_prepare_scanout(void)','void boot_progress_cancel_scanout(void)','static void touch_overlay(void)'))
    methods=methods.replace('__asm__ volatile("dsb sy" ::: "memory");','__atomic_thread_fence(__ATOMIC_SEQ_CST);')
    fixture=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define BP_COLS 120
static struct {unsigned bound,yield_requested,scale;uintptr_t frame;char previous[48][120];unsigned colors[48][2];} display;
static unsigned render_busy,resume_after,boot_progress_display_owned,last_scanout_at,enabled=1;
static unsigned now_value,pixels,clears,banners,touch_passes;
static int state,render_snapshot;
static struct {int closed;} pulse;
static int take(void){return 1;}static void release(void){}
static unsigned seconds(void){return now_value;}
static void draw(unsigned now){(void)now;if(display.bound && !display.yield_requested)++pixels;}
static void bp_clear(void *p){(void)p;++pixels;++clears;}
static void pdx_cached_invalidate(void){}
static int bp_pulse_enter(void *p){(void)p;return 1;}
static void bp_pulse_close(void *p){(void)p;pulse.closed=1;}
static void bp_pulse_leave(void *p){(void)p;}
static void line(unsigned row,const char *text,unsigned color){(void)row;(void)text;(void)color;++pixels;}
static int PE_parse_boot_argn(const char *key,void *out,unsigned size){assert(!strcmp(key,"banner") && size==4);*(unsigned *)out=0;return 1;}
static void ext_overlay_locked(void){if(display.bound)++pixels;}
static void crash_banner(unsigned now){(void)now;++banners;++pixels;}
static void touch_overlay_locked(void){}
''' + methods + r'''
int main(void){
    display.bound=1;display.frame=0x1000;display.scale=1;
    refresh(1);assert(pixels==1);touch_overlay();assert(pixels==2 && !banners);
    assert(boot_progress_prepare_scanout());assert(boot_progress_display_owned && !display.bound && pulse.closed);
    unsigned before=pixels;
    for(unsigned now=1;now<=4000;now+=7){now_value=now;refresh(now);touch_overlay();}
    assert(pixels==before && !display.bound && !banners && !clears);
    // Control: the prior resume=10 does take the UI back despite banner=0.
    resume_after=10;now_value=5000;refresh(now_value);
    assert(display.bound && clears==1 && pixels>before);
    puts("PASS actual display handoff: banner=0 plus resume=0 writes no UI pixels through4000s; oldresume10 control reclaims/clears the display");
}
'''
    c=a.out/'actual-ui-policy.c';c.write_text(fixture)
    command=['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(c),'-o',str(a.out/'ui-policy')]
    subprocess.run(command,check=True)
    ui=subprocess.run([str(a.out/'ui-policy')],capture_output=True,text=True,check=True,timeout=15)
    include=a.out/'include';(include/'kern').mkdir(parents=True);(include/'arm').mkdir()
    (include/'kern/processor.h').write_text('''#define MAX_CPUS 8
enum {PROCESSOR_OFF_LINE=0,PROCESSOR_START=2,PROCESSOR_IDLE=4,PROCESSOR_DISPATCHING=5,PROCESSOR_RUNNING=6};
typedef struct {unsigned state;} *processor_t;
extern processor_t processor_array[MAX_CPUS];extern unsigned processor_count;
''')
    (include/'arm/cpu_data_internal.h').write_text('''typedef struct {unsigned char cpu_running;} cpu_data_t;
typedef struct {void *cpu_data_paddr;cpu_data_t *cpu_data_vaddr;} cpu_data_entry_t;
extern cpu_data_entry_t CpuDataEntries[8];
''')
    cpu_fixture=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <kern/processor.h>
#include <arm/cpu_data_internal.h>
processor_t processor_array[8];unsigned processor_count=8;
cpu_data_entry_t CpuDataEntries[8];
volatile uint32_t armcpu_smp_requested=7,armcpu_smp_running=7,armcpu_smp_step[8],armcpu_smp_fail[8];
volatile int32_t armcpu_smp_psci_rc[8];
volatile uint32_t armcpu_core_timer[8],armcpu_core_sgi[8];
extern volatile uint32_t native_sony_cpu_present_mask,native_sony_cpu_running_mask,native_sony_cpu_schedulable_mask;
void native_sony_cpu_snapshot(void);
char logs[8192];unsigned used;
void IOLog(const char *format,...){va_list args;va_start(args,format);int n=vsnprintf(logs+used,sizeof(logs)-used,format,args);va_end(args);assert(n>=0 && (unsigned)n<sizeof(logs)-used);used+=(unsigned)n;}
int main(void){
    cpu_data_t data[8];struct {unsigned state;} processor[8];
    for(unsigned i=0;i<8;++i){data[i].cpu_running=1;processor[i].state=i%2?PROCESSOR_IDLE:PROCESSOR_RUNNING;
        CpuDataEntries[i].cpu_data_vaddr=&data[i];processor_array[i]=(processor_t)&processor[i];armcpu_smp_step[i]=i?7:0;
        armcpu_core_timer[i]=100+i;armcpu_core_sgi[i]=200+i;}
    native_sony_cpu_snapshot();assert(native_sony_cpu_present_mask==255 && native_sony_cpu_running_mask==255 && native_sony_cpu_schedulable_mask==255);
    assert(strstr(logs,"core=7 present=1 running=1 state=4 step=7") && strstr(logs,"timer=107 delta=107 ipi=207 delta=207"));
    used=0;logs[0]=0;data[3].cpu_running=0;processor[3].state=PROCESSOR_START;CpuDataEntries[6].cpu_data_vaddr=0;processor_array[6]=0;
    for(unsigned i=0;i<8;++i){armcpu_core_timer[i]+=10;armcpu_core_sgi[i]+=3;}
    native_sony_cpu_snapshot();assert(native_sony_cpu_present_mask==0xbf && native_sony_cpu_running_mask==0xb7 && native_sony_cpu_schedulable_mask==0xb7);
    assert(strstr(logs,"timer=117 delta=10 ipi=210 delta=3") && strstr(logs,"core=6 present=0 running=0"));
    puts("PASS actual per-core recorder: eight running/idle CPUs, absent CPU, startingCPU notonline, independent32-bit timer/IPI deltas");
}
'''
    cp=a.out/'cpu-fixture.c';cp.write_text(cpu_fixture);cpu_source=ROOT/'drivers/SonyLxsTouch/CpuRuntimeProbe.c'
    subprocess.run(['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(include),
                    str(cp),str(cpu_source),'-o',str(a.out/'cpu-recorder')],check=True)
    cpu=subprocess.run([str(a.out/'cpu-recorder')],capture_output=True,text=True,check=True,timeout=15)
    result=dict(passed=True,ui_source=str(source),ui_source_sha256=sha(source),cpu_source=str(cpu_source),cpu_source_sha256=sha(cpu_source),
        no_post_handoff_pixels=True,timed_takeover_control_reproduced=True,all_eight_cpu_state_cases=True,
        sanitizers=['address','undefined'],output=ui.stdout+cpu.stdout,phone_cpu_online_verified=False,phone_touch_verified=False)
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(result['output'],end='')


if __name__=='__main__':main()
