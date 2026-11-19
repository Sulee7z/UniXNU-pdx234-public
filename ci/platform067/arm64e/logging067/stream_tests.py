#!/usr/bin/env python3
"""Execute unchanged selected message-ring/diag append bodies with modeled log I/O."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from audit import sha, load
sys.path.insert(0, str(HERE))
import source as overlay

PRE = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "BootLatencyFiles.h"
enum {LogBlock=4096,LogMsgFirst=1,LogMsgBlocks=32};
struct boot_log_msgbuf {int msg_magic,msg_size,msg_bufx,msg_bufr;char *msg_bufc;};
static struct boot_log_msgbuf *msgbufp;
static uint8_t memory_ring[131072],medium[131072];
static uint8_t *boot_log_msg_ring=memory_ring;
static struct {const char *bufc; int size, bufx, synced; uint64_t head, written;} msg_stream;
static uint64_t diag_msg_scan;
static unsigned write_calls;static int fail_write;
static int native_ufs_log_write(uint64_t relative,uint32_t blocks,const void *buffer) {
 ++write_calls;assert(relative>=1 && relative<33 && blocks && blocks<=33-relative);
 if(fail_write)return 0;memcpy(medium+(relative-1)*4096,buffer,(size_t)blocks*4096);return 1;
}
'''

CASES = r'''
static void reset(void){memset(&msg_stream,0,sizeof msg_stream);memset(memory_ring,0,sizeof memory_ring);memset(medium,0,sizeof medium);diag_msg_scan=0;write_calls=0;fail_write=0;msgbufp=NULL;}
int main(void) {
 reset();msg_append(0);assert(!msg_stream.head);const uint64_t cap=sizeof memory_ring;
 for(uint64_t n=0;n<cap+103;++n)msg_append((uint8_t)('A'+n%26));
 assert(msg_stream.head==cap+103);
 for(uint64_t n=103;n<cap+103;++n)assert(memory_ring[n%cap]==(uint8_t)('A'+n%26));
 assert(msg_stream_write() && msg_stream.written==msg_stream.head && write_calls<=2);
 assert(!memcmp(medium,memory_ring,sizeof medium));
 write_calls=0;assert(msg_stream_write() && !write_calls);
 msg_append('x');fail_write=1;uint64_t written=msg_stream.written;
 assert(!msg_stream_write() && msg_stream.written==written);fail_write=0;
 assert(msg_stream_write() && msg_stream.written==msg_stream.head && !memcmp(medium,memory_ring,sizeof medium));
 reset();uint32_t resyncs=0;char kernel[128]={0};struct boot_log_msgbuf m={0,sizeof kernel,0,0,kernel};msgbufp=&m;
 assert(msg_stream_round(&resyncs)==0 && !resyncs);
 const char first[]="ordinary\nunixnu-exit: App[9] status=0x5";
 memcpy(kernel,first,sizeof first-1);m.msg_bufx=sizeof first-1;
 assert(msg_stream_round(&resyncs)==sizeof first-1);
 char output[1024]={0};size_t at=diag_msg_lines(output,0,sizeof output);
 assert(at==0 && diag_msg_scan==strlen("ordinary\n"));
 kernel[m.msg_bufx++]='\n';assert(msg_stream_round(&resyncs)==1);
 at=diag_msg_lines(output,0,sizeof output);
 assert(at && strstr(output,"[diag msgs]\nunixnu-exit: App[9] status=0x5\n"));
 uint64_t scanned=diag_msg_scan;assert(diag_msg_lines(output,at,sizeof output)==at && diag_msg_scan==scanned);
 assert(!write_calls);assert(msg_stream_write() && write_calls==1);
 char changed[16]="EXC_GUARD\n";m.msg_bufc=changed;m.msg_size=sizeof changed;m.msg_bufx=10;
 assert(msg_stream_round(&resyncs)==10 && resyncs==1);
 /* message-end/index zero and ring-size changes never index before/after supplied buffers */
 reset();char tiny[1]={'x'};m.msg_bufc=tiny;m.msg_size=1;m.msg_bufx=-1;msgbufp=&m;
 assert(msg_stream_round(&resyncs)==1 && msg_stream.bufx==0);
 m.msg_bufx=1;assert(msg_stream_round(&resyncs)==0 && msg_stream.bufx==0);
 m.msg_size=0;assert(msg_stream_round(&resyncs)==0);
 /* after overwrite, scan starts at retained head-cap; never reads unretained data */
 reset();for(uint64_t i=0;i<cap+8;++i)msg_append('q');
 char guarded[80];memset(guarded,0xa5,sizeof guarded);memset(guarded+8,0,64);
 at=diag_msg_lines(guarded+8,0,64);assert(at==0 && diag_msg_scan==8);
 for(unsigned i=0;i<8;++i){assert((unsigned char)guarded[i]==0xa5);assert((unsigned char)guarded[72+i]==0xa5);}
 printf("PASS actual message ring append/end/wrap, write failure/retry, complete-line exit persistence, resync and guards\n");return 0;
}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build', type=Path, default=HERE / 'build-002')
    p.add_argument('--out', type=Path, default=HERE / 'stream-tests-001')
    a = p.parse_args()
    out = a.out.resolve()
    if not out.is_relative_to(HERE) or out == HERE or out.exists():
        raise ValueError('Fresh assigned output required')
    text = (a.build / 'BootLog.c').read_text()
    names = ('msg_append', 'msg_stream_round', 'msg_stream_write', 'put', 'diag_msg_lines')
    program = PRE + '\n'.join(overlay.function(text, name) for name in names) + CASES
    out.mkdir()
    path = out / 'tests.c'
    path.write_text(program)
    cmd = ['clang-18', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
           '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-I', str(a.build), str(path), '-o', str(out / 'tests')]
    for command, log in [(cmd, 'compile.log'), ([str(out / 'tests')], 'run.log')]:
        done = subprocess.run(command, capture_output=True, text=True, timeout=90)
        (out / log).write_text(done.stdout + done.stderr)
        if done.returncode:
            raise RuntimeError(done.stdout + done.stderr)
    result = {'passed': True, 'functions': names, 'target_source_sha256': sha(a.build / 'BootLog.c'),
              'test_source_sha256': sha(path), 'command': cmd, 'sanitizers': ['address', 'undefined'],
              'actual_bodies_unchanged': True, 'modeled_ufs_callback_only': True,
              'device_operations': False, 'target_build_result_sha256': sha(a.build / 'result.json')}
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print((out / 'run.log').read_text().strip())


if __name__ == '__main__':
    main()
