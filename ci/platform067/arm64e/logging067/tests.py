#!/usr/bin/env python3
"""Actual logging body tests; modeled kernel/UFS callbacks, ASan+UBSan, no device I/O."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from audit import BASE, REPO, sha, load
sys.path.insert(0, str(HERE))
import source as overlay

PREAMBLE = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned print_count, write_count, sync_count, flush_count, read_regs, locks;
static char printed[8192], written[4096];
static int enabled=1, parse_present=1, current_pid=1, interrupt_context, write_ok=1;
static uint64_t written_slot;
static size_t printed_bytes;
typedef struct {unsigned held;} IOLock;
static IOLock lock_object;
static int test_printf(const char *format,...) {
 va_list args;va_start(args,format);++print_count;
 int n=vsnprintf(printed,sizeof printed,format,args);va_end(args);
 printed_bytes=n>0?(size_t)n:0;return n;
}
#define printf test_printf
static int PE_parse_boot_argn(const char *name,void *out,int bytes) {
 if(!strcmp(name,"storage-probe")) {
  if(!parse_present)return 0;assert(bytes==4);*(uint32_t *)out=(uint32_t)enabled;return 1;
 }
 if(!strcmp(name,"build-tag")){snprintf(out,(size_t)bytes,"PDX067");return 1;}
 return 0;
}
static int fake_log_write(uint64_t slot,uint32_t n,const void *data) {
 ++write_count;written_slot=slot;assert(n==1);memcpy(written,data,sizeof written);return write_ok;
}
static int fake_log_sync(void){++sync_count;return 1;}
static int (*native_ufs_log_write)(uint64_t,uint32_t,const void *)=fake_log_write;
static int (*native_ufs_log_sync)(void)=fake_log_sync;
static uint64_t fake_reg(const char *name){(void)name;++read_regs;return 0x1234;}
static uint64_t mach_absolute_time(void){return 0x8888;}
static int proc_selfpid(void){return current_pid;}
static void *current_thread(void){return &lock_object;}
static uint64_t thread_tid(void *thread){(void)thread;return 0x7777;}
static int ml_at_interrupt_context(void){return interrupt_context;}
static void IOLockLock(IOLock *lock){assert(!lock->held);lock->held=1;++locks;}
static void IOLockUnlock(IOLock *lock){assert(lock->held);lock->held=0;--locks;}
static uint32_t boot_log_state=2;
struct {unsigned char before[16];char text[2048];unsigned char after[16];} panic_buffer;
#define boot_progress_panic_text (panic_buffer.text)
static void boot_log_panic_flush(void){++flush_count;}
'''

TESTS = r'''
static void reset_test(void) {
 print_count=write_count=sync_count=flush_count=read_regs=locks=0;printed[0]=written[0]=0;
 printed_bytes=0;written_slot=0;enabled=parse_present=write_ok=1;current_pid=1;interrupt_context=0;
 boot_log_state=2;checkpoint_lock=&lock_object;lock_object.held=0;
 checkpoint_sequence=0;checkpoint_role_sequence[0]=checkpoint_role_sequence[1]=0;
 memset(panic_buffer.before,0xa5,sizeof panic_buffer.before);
 memset(panic_buffer.after,0x5a,sizeof panic_buffer.after);memset(panic_buffer.text,0,sizeof panic_buffer.text);
 native_ufs_log_write=fake_log_write;native_ufs_log_sync=fake_log_sync;
}
static void guards(void) {
 for(unsigned i=0;i<16;++i){assert(panic_buffer.before[i]==0xa5);assert(panic_buffer.after[i]==0x5a);}
}
static void call_panic(const char *format,...) {
 va_list args;va_start(args,format);boot_log_panic_record(format,&args,0xabcd);
 /* va_copy in the actual provider must leave the caller's list untouched. */
 assert(va_arg(args,int)==42);va_end(args);
}
int main(int argc,char **argv) {
 assert(argc==2);
 static char checkpoint[4096];static struct boot_log_header live;memset(&live,0,sizeof live);
 reset_test();checkpoint_buffer=checkpoint;boot_log_live=&live;live.window_blocks=8192;
 if(!strcmp(argv[1],"panic-gates")) {
  enabled=0;call_panic("failure %d",42);assert(!flush_count && !read_regs && !write_count);
  enabled=1;boot_log_state=1;call_panic("failure %d",42);assert(!flush_count);
  boot_log_state=2;call_panic("failure %d",42);
  assert(flush_count==1 && strstr(panic_buffer.text,"failure 42 caller=abcd"));
  char old[2048];memcpy(old,panic_buffer.text,sizeof old);call_panic("second %d",42);
  assert(flush_count==1 && !memcmp(old,panic_buffer.text,sizeof old));guards();
 } else if(!strcmp(argv[1],"panic-bounds")) {
  char huge[6000];memset(huge,'P',sizeof huge-1);huge[sizeof huge-1]=0;
  /* actual formatter consumes one integer and its string; the list remains valid */
  call_panic("%d %s",42,huge);assert(flush_count==1 && strlen(panic_buffer.text)==2047);guards();
 } else if(!strcmp(argv[1],"checkpoint-bounds")) {
  /* Every possible small layout, both roles, ring wrapping, never an export/GPT write. */
  uint64_t cases=0;
  for(uint32_t blocks=0;blocks<=9000;++blocks) {
   live.window_blocks=blocks;
   for(int role=0;role<2;++role) {
    current_pid=role?1:0;write_count=sync_count=0;boot_log_checkpoint("bounded");
    if(blocks<=33 || (blocks-33)%16<2){assert(!write_count && !sync_count);}
    else {
     uint64_t tail=33+(blocks-33)/16*16;
     assert(write_count==1 && sync_count==1 && written_slot>=tail && written_slot<blocks);
     uint64_t half=(blocks-tail)/2;
     if(role)assert(written_slot>=tail+half);else assert(written_slot<tail+half);
     assert(!strncmp(written,"SHSTG001\n",9) && memchr(written,0,sizeof written));
    }
    assert(!locks);++cases;
   }
  }
  fprintf(stdout,"bounds=%" PRIu64 " ",cases);
 } else if(!strcmp(argv[1],"checkpoint-gates")) {
  enabled=0;boot_log_checkpoint("disabled");assert(!write_count && !read_regs);
  enabled=1;parse_present=0;boot_log_checkpoint("absent");assert(!write_count && !read_regs);
  parse_present=1;native_ufs_log_write=NULL;boot_log_checkpoint("missing");assert(!read_regs);
  native_ufs_log_write=fake_log_write;boot_log_live=NULL;boot_log_checkpoint("pending");assert(print_count==1 && !write_count);
  boot_log_live=&live;checkpoint_lock=NULL;boot_log_checkpoint("unallocated");assert(!write_count);
  checkpoint_lock=&lock_object;checkpoint_buffer=NULL;boot_log_checkpoint("unallocated");assert(!write_count);
  checkpoint_buffer=checkpoint;write_ok=0;boot_log_checkpoint("failed-write");assert(write_count==1 && !sync_count);
  write_ok=1;native_ufs_log_sync=NULL;boot_log_checkpoint("no-sync");assert(write_count==2 && !sync_count);
  native_ufs_log_sync=fake_log_sync;char huge[10000];memset(huge,'S',sizeof huge-1);huge[sizeof huge-1]=0;
  boot_log_checkpoint(huge);assert(write_count==3 && sync_count==1 && !written[4095]);
 } else if(!strcmp(argv[1],"stage-result")) {
  boot_log_state=1;boot_log_startup_stage(1,"off");assert(!write_count);
  boot_log_state=2;interrupt_context=1;boot_log_startup_stage(1,"irq");assert(!write_count);
  interrupt_context=0;current_pid=50;boot_log_startup_stage(0,"notpid1");assert(!write_count);
  current_pid=1;boot_log_startup_result("Data mount returned",28);
  assert(write_count==1 && strstr(written,"Data mount returned result=28"));
  /* result text is bounded even for a much larger stage. */
  char huge[10000];memset(huge,'R',sizeof huge-1);huge[sizeof huge-1]=0;
  boot_log_startup_result(huge,-1);assert(write_count==2 && memchr(written,0,4096));
 } else if(!strcmp(argv[1],"exit-evidence")) {
  boot_log_process_exit(8,"Calendar",0,0,0,NULL,0);assert(!print_count);
  boot_log_process_exit(8,"Calendar",9,0,0,NULL,0);assert(!print_count);
  boot_log_process_exit(8,"Calendar",15,0,0,NULL,0);assert(!print_count);
  boot_log_process_exit(8,"Calendar",5,0,0x1234,"swift failure",0x5678);
  assert(print_count==1 && strstr(printed,"Calendar[8] status=0x5 reason=0/0x1234 csflags=0x5678 description=swift failure"));
  boot_log_process_exit(8,"Calendar",9,3,77,NULL,1);assert(print_count==2);
  boot_log_process_exit(8,"WindowServer",0,0,0,NULL,0);assert(print_count==3);
  boot_log_process_exit(8,"WallpaperVideoExtension",0,0,0,NULL,0);assert(print_count==4);
  char long_desc[1000];memset(long_desc,'D',sizeof long_desc-1);long_desc[sizeof long_desc-1]=0;
  boot_log_process_exit(8,"Calendar",6,0,0,long_desc,0);assert(print_count==5);
  assert(printed_bytes<400 && strlen(strstr(printed,"description=")+12)==257);
  assert(!write_count && !sync_count && !flush_count && !read_regs);
  assert(bl_latency_message(printed,strlen(printed)));
  char buffer[512]="ordinary line\nunixnu-exit: app[1] status=0x5\nordinary tail\n";
  unsigned length=bl_latency_messages(buffer,(unsigned)strlen(buffer));
  assert(length==strlen("unixnu-exit: app[1] status=0x5\n") && !memcmp(buffer,"unixnu-exit: app[1] status=0x5\n",length));
 } else if(!strcmp(argv[1],"append-end")) {
  uint8_t guarded[300];const char row[]="abc \t\001Z ";
  unsigned cases=0;
  for(size_t cap=0;cap<128;++cap)for(size_t start=0;start<=cap;++start) {
   memset(guarded,0xa5,sizeof guarded);char *out=(char *)guarded+16;memset(out,0,cap);
   size_t at=put(out,start,cap,row,sizeof row-1);
   assert(at>=start && at<=cap);
   for(unsigned i=0;i<16;++i)assert(guarded[i]==0xa5);
   for(unsigned i=(unsigned)(16+cap);i<sizeof guarded;++i)assert(guarded[i]==0xa5);
   if(cap && start<cap)assert(out[cap-1]==0);
   ++cases;
  }
  char out[64]={0};size_t at=put(out,0,sizeof out,"first",5);at=put(out,at,sizeof out,"second",6);
  assert(!strcmp(out,"first\nsecond\n") && at==13);
  fprintf(stdout,"append=%u ",cases);
 } else abort();
 fprintf(stdout,"PASS %s\n",argv[1]);return 0;
}
'''


def run(args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=90)
    if p.returncode:
        raise RuntimeError(str(args) + '\n' + p.stdout[-2000:] + p.stderr[-6000:])
    return p.stdout + p.stderr


def assert_preserved(old, new):
    for name in ('writer', 'boot_log_panic_flush', 'boot_reset_arm', 'boot_log_export_put',
                 'msg_stream_write', 'msg_stream_round', 'msg_append', 'copy_msgbuf', 'diag_flush', 'diag_emit', 'diag_thread', 'put'):
        if overlay.function(old, name) != overlay.function(new, name):
            raise ValueError('Unrelated Sony storage body changed: ' + name)
    if old[old.index('enum {LogBlock'):old.index('// Writer state')] != new[new.index('enum {LogBlock'):new.index('// Writer state')]:
        raise ValueError('Log window/header layout changed')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build', type=Path, default=HERE / 'build-001')
    p.add_argument('--out', type=Path, default=HERE / 'tests-002')
    a = p.parse_args()
    out = a.out.resolve()
    if not out.is_relative_to(HERE) or out == HERE or out.exists():
        raise ValueError('Fresh assigned output directory required')
    report = load(a.build / 'result.json')
    if not report['compiled'] or not report['source_and_object_unchanged']:
        raise ValueError('Completed isolated build required')
    new = (a.build / 'BootLog.c').read_text()
    provider_row = next(row for row in report['jobs'] if row.get('member') == 'BootLog.o')
    old = Path(provider_row['input_source']).read_text()
    assert_preserved(old, new)
    fresh = (overlay.FRESH / 'package/BootLog.c').read_text()
    checkpoint, panic, init = overlay.provider_parts(fresh)
    if checkpoint not in new or panic not in new or init not in new:
        raise ValueError('Selected provider functions not exact official text')
    # Host reader/register substitution only; the target compiled source is untouched.
    checkpoint_host = re.sub(r'__asm__ volatile\("mrs %0, ([^"]+)" : "=r"\(([^)]+)\)\);',
                             lambda m: m[2] + '=fake_reg("' + m[1] + '");', checkpoint)
    checkpoint_host = checkpoint_host.replace('&native_ufs_log_write', 'native_ufs_log_write').replace('&native_ufs_log_sync', 'native_ufs_log_sync')
    if '__asm__' in checkpoint_host:
        raise ValueError('Unknown official hardware-read statement')
    header = new[new.index('enum {LogBlock'):new.index('// Writer state')]
    program = PREAMBLE + header + '\nstatic struct boot_log_header *volatile boot_log_live;\n'
    program += checkpoint_host + panic + overlay.function(new, 'put') + '\n#include "BootLatencyFiles.h"\n' + TESTS
    out.mkdir()
    (out / 'tests.c').write_text(program)
    cmd = ['clang-18', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-pointer-bool-conversion',
           '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-I', str(a.build),
           str(out / 'tests.c'), '-o', str(out / 'tests')]
    compile_log = run(cmd)
    (out / 'compile.log').write_text(compile_log)
    modes = ('checkpoint-bounds', 'checkpoint-gates', 'stage-result', 'exit-evidence', 'append-end', 'panic-gates', 'panic-bounds')
    logs = {mode: run([str(out / 'tests'), mode]) for mode in modes}
    (out / 'run.log').write_text(''.join(logs.values()))
    # Header fallback is tested in a separate TU with real compiled official macros.
    header_program = r'''
#include <assert.h>
#include <string.h>
#define XNU_BOOT_PROGRESS 0
#include "kern/boot_progress.h"
static int calls,last_pid;static const char *last;
void boot_log_startup_stage(int pid,const char *stage){++calls;last_pid=pid;last=stage;}
int main(void){boot_progress_stage("headless");assert(calls==1 && last_pid==0 && !strcmp(last,"headless"));
boot_progress_process_stage(123,"unused","process");assert(calls==2 && last_pid==123 && !strcmp(last,"process"));return 0;}
'''
    (out / 'header.c').write_text(header_program)
    hc = ['clang-18', '-std=c11', '-fsanitize=address,undefined', '-I', str(a.build / 'include'), str(out / 'header.c'), '-o', str(out / 'header')]
    (out / 'header-compile.log').write_text(run(hc))
    run([str(out / 'header')])
    # Main owns the cleaned BootProgress archive member. Its target uses the
    # enabled header branch, which this official fallback patch does not alter.
    # Prove exact preprocessing equality instead of replacing main's source.
    work_header = Path(report['header_input'])
    for value in [0, 1]:
        outputs = []
        for label, path in [('old', work_header), ('new', a.build / 'include/kern/boot_progress.h')]:
            source = out / f'header-{label}-{value}.c'
            source.write_text('#define XNU_BOOT_PROGRESS ' + str(value) + '\n#include "' + str(path) + '"\n')
            outputs.append(run(['clang-18', '-E', '-P', str(source)]))
        if value == 1 and outputs[0] != outputs[1]:
            raise ValueError('Active header branch changed underneath main BootProgress')
        if value == 0 and outputs[0] == outputs[1]:
            raise ValueError('Expected new official headless fallback not selected')
    absent = header_program[:header_program.index('static int calls')] + '''
int main(void){boot_progress_stage("no-provider");boot_progress_process_stage(7,"n","no-provider");return 0;}
'''
    (out / 'header-absent.c').write_text(absent)
    absent_command = ['clang-18', '-std=c11', '-fsanitize=address,undefined', '-I', str(a.build / 'include'),
                      str(out / 'header-absent.c'), '-o', str(out / 'header-absent')]
    (out / 'header-absent-compile.log').write_text(run(absent_command))
    run([str(out / 'header-absent')])
    # Composable adapter is single-use and retains the exact Data error path.
    exec_row = next(r for r in report['jobs'] if r['xnu_relative'] == 'bsd/kern/kern_exec.c')
    ex = Path(exec_row['source']).read_text()
    if overlay.adapt_exec(Path(exec_row['input_source']).read_text()) != ex:
        raise ValueError('Exec adapter composition changed')
    try:
        overlay.adapt_exec(ex)
    except ValueError:
        pass
    else:
        raise ValueError('Logging adapter must reject repeat application')
    for text in ['if (data_error) panic("offline scratch Data mount failed: %d", data_error);',
                 'if (cache_error) panic("offline owner SystemOS mount failed: %d", cache_error);',
                 'VATTR_SET(&va, va_data_size, size);', 'AGXMetalG14.bundle']:
        if text not in ex:
            raise ValueError('D27 protected path/overlay lost: ' + text)
    result = {'passed': True, 'target_build': str(a.build), 'target_result_sha256': sha(a.build / 'result.json'),
              'modes': modes, 'logs': logs, 'sanitizers': ['address', 'undefined'],
              'checkpoint_layout_cases': 18002, 'append_bounds_cases': 8256,
              'header_fallback_tested': True, 'exact_provider_functions_from_fresh': True,
              'active_header_branch_preprocessed_identical': True,
              'main_owned_bootprogress_member_not_overwritten': True,
              'headless_absent_weak_provider_noop_tested': True,
              'sony_writer_header_msg_export_watchdog_unchanged': True,
              'official_checkpoint_probe_gate_preserved': True, 'd27_mount_error_paths_and_addon_composition_retained': True,
              'target_source_mutation_for_host_tests': False, 'phone_operations': False,
              'host_only_modeled_callbacks': True, 'device_or_apfs_runtime_verified': False,
              'limitations': ['Host tests substitute7architectural read-only register reads, kernel locks/current process and bounded UFS log callbacks.',
                             'No new raw-storage implementation, platform-sleep or performance policy is selected.',
                             'storage-probe=1 is required for checkpoint/panic sinks; ordinary process exit printf does not depend on it.']}
    save = lambda name, value: (out / name).write_text(json.dumps(value, indent=2) + '\n')
    save('result.json', result)
    print(json.dumps({'passed': True, 'out': str(out), 'modes': len(modes), 'layout_cases': 18002, 'append_cases': 8256}))


if __name__ == '__main__':
    main()
