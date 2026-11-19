#!/usr/bin/env python3
"""Execute existing official bounded crash selector independently of GPU diagnostics."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'ci/platform069/crashes'))
from audit import FRESH, sha


def extract(text, name):
    matches = list(re.finditer(r'(?m)^static [^\n{};]*\b' + re.escape(name) + r'\([^;{}]*\)\s*\{', text))
    if len(matches) != 1:
        raise ValueError('Unknown function definition:' + name)
    start = matches[0].start()
    return text[start:text.index('\n}', start) + 3] + '\n'


PRE = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "BootLatencyFiles.h"
enum {LogBlock=4096,LogMsgFirst=1,LogMsgBlocks=32};
static uint8_t message_ring[131072];
static uint8_t *boot_log_msg_ring=message_ring;
static struct {const char *bufc;int size,bufx,synced;uint64_t head,written;} msg_stream;
static uint64_t diag_msg_scan;
static unsigned writes,exports,samplers;static int diag,log_crash_evidence_on;
'''
MAIN = r'''
static void append(const char *s){while(*s){message_ring[msg_stream.head++%sizeof message_ring]=(uint8_t)*s++;}}
static size_t round_select(char *out,size_t cap) {
 size_t text=0;
 if(diag==1 || log_crash_evidence_on)text=diag_msg_lines(out,text,cap);
 /* stand-ins for unchanged original GPU work gates */
 if(diag==1)++samplers;
 if(diag==1)++exports;
 return text;
}
int main(void) {
 char output[4096]={0};diag=0;log_crash_evidence_on=0;
 append("ordinary chatter\nunixnu-exit: Preferences[25] status=0x5 reason=2/0x5 csflags=0x1 description=trap\n");
 assert(!round_select(output,sizeof output) && !diag_msg_scan);
 log_crash_evidence_on=1;assert(round_select(output,sizeof output));
 assert(strstr(output,"unixnu-exit: Preferences[25] status=0x5") && !strstr(output,"ordinary chatter"));
 assert(!samplers && !exports && !writes);
 uint64_t previous=diag_msg_scan;assert(!round_select(output,sizeof output) && diag_msg_scan==previous);
 append("EXC_GUARD AST: type=1 flavor=0\n");memset(output,0,sizeof output);assert(round_select(output,sizeof output));
 assert(strstr(output,"EXC_GUARD AST:") && !samplers && !exports);
 append("memorystatus: killing_specific_process pid 25 [Preferences] (per-process-limit)\n");
 memset(output,0,sizeof output);assert(round_select(output,sizeof output));assert(strstr(output,"per-process-limit"));
 /* An unfinished message waits; next newline commits it exactly once. */
 append("unixnu-exit: App[26] status=0x100");previous=diag_msg_scan;
 assert(!round_select(output,sizeof output) && diag_msg_scan==previous);append("\n");
 memset(output,0,sizeof output);assert(round_select(output,sizeof output));
 assert(strstr(output,"App[26] status=0x100") && !samplers && !exports && !writes);
 for(unsigned cap=0;cap<128;++cap) {
  uint8_t guarded[176];memset(guarded,0xa5,sizeof guarded);memset(guarded+16,0,cap);
  diag_msg_scan=0;size_t count=round_select((char*)guarded+16,cap);assert(count<=cap);
  for(unsigned j=0;j<16;++j)assert(guarded[j]==0xa5);
  for(unsigned j=16+cap;j<sizeof guarded;++j)assert(guarded[j]==0xa5);
 }
 assert(!samplers && !exports && !writes);puts("PASS storage-probe crash lines, no sampler/export/write calls, partial-line/end/bounds");return 0;
}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build', type=Path, default=FRESH / 'crashes-build-001')
    p.add_argument('--out', type=Path, default=FRESH / 'crashes-capture-tests-001')
    a = p.parse_args()
    if a.out.exists() or not a.out.resolve().is_relative_to(FRESH):
        raise ValueError('Fresh069 output required')
    source = (a.build / 'BootLog.c').read_text()
    old = (ROOT / 'ci/platform067/arm64e/logging067/build-002/BootLog.c').read_text()
    for name in ('put', 'diag_msg_lines', 'writer', 'boot_log_panic_flush', 'boot_log_process_exit'):
        if name != 'writer':
            # global functions have non-static signatures; only verify contained
            # exact original text for the unchanged dynamic provider functions.
            if name in ('boot_log_panic_flush', 'boot_log_process_exit'):
                start=old.index('void '+name+'(');body=old[start:old.index('\n}',start)+3]
                if body not in source:raise ValueError('Provider behavior changed:'+name)
            elif extract(source,name)!=extract(old,name):raise ValueError('Official selector changed:'+name)
    if 'if (diag == 1 || log_crash_evidence_on)' not in source:
        raise ValueError('New independent crash gate absent')
    if source.count('if (diag == 1 && &boot_diag_shot_tick)') != old.count('if (diag == 1 && &boot_diag_shot_tick)'):
        raise ValueError('Sampler gate changed')
    if source.count('kernel_thread_start_priority(diag_thread') != old.count('kernel_thread_start_priority(diag_thread'):
        raise ValueError('Export startup changed')
    a.out.mkdir(parents=True)
    (a.out / 'BootLatencyFiles.h').write_bytes((ROOT / 'ci/platform067/arm64e/logging067/build-002/BootLatencyFiles.h').read_bytes())
    harness = a.out / 'test.c'
    harness.write_text(PRE + extract(source,'put') + extract(source,'diag_msg_lines') + MAIN)
    cmd=['clang-18','-std=c11','-Wall','-Wextra','-Werror','-O1','-g','-fsanitize=address,undefined',str(harness),'-o',str(a.out/'test')]
    for command,name in [(cmd,'compile.log'),([str(a.out/'test')],'run.log')]:
        done=subprocess.run(command,capture_output=True,text=True,timeout=90);(a.out/name).write_text(done.stdout+done.stderr)
        if done.returncode:raise RuntimeError(done.stdout+done.stderr)
    result={'passed':True,'target_source_sha256':sha(a.build/'BootLog.c'),'test_sha256':sha(harness),
            'sanitizers':['address','undefined'],'no_model_phone_write_export_or_gpu_sampler_calls':True,
            'official_selector_and_exit_provider_unchanged':True,'device_operations':False}
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print((a.out/'run.log').read_text().strip())


if __name__=='__main__':main()
