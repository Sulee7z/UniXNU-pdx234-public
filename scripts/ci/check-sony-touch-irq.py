#!/usr/bin/env python3
"""Exercise the actual linked ArmCpu mask API with Sony's production attach-before-mask helper."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True)
    a=parser.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    plan=json.loads((BASE/'native-screen007-055-001/plan.json').read_text())
    job=next(job for job in plan['jobs'] if Path(job['source']).name=='ArmCpu.cpp')
    source=Path(job['source']);text=source.read_text()
    start=text.index('extern "C" IOReturn armcpu_spi_mask ')
    end=text.index('\nextern "C" uint64_t armcpu_spi_count',start)
    method=text[start:end]
    barrier='  __asm__ volatile ("dsb sy" ::: "memory");'
    if method.count(barrier)!=1:raise ValueError('Actual ArmCpu mask implementation changed')
    method=method.replace(barrier,'  __atomic_thread_fence(__ATOMIC_SEQ_CST);')
    fixture=r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include "SonyTouchIrq.h"
using IOReturn=int;
constexpr int kIOReturnSuccess=0,kIOReturnNotReady=-1,kIOReturnNotFound=-2;
uintptr_t gDist=0x17100000;unsigned armcpu_gic_ready=1;
uint32_t gSpiRoutes[1024]={};unsigned calls=0,writes=0;bool failedAttach=false;
uint32_t peripheral[1024]={};uint32_t lastGicOffset=0,lastGicValue=0;
void write32(uintptr_t base,unsigned offset,uint32_t value){assert(base==gDist);++writes;lastGicOffset=offset;lastGicValue=value;}
''' + method + r'''
static int mask(uint32_t id,int value){return armcpu_spi_mask(id,value!=0);}
static void mmio(void *,uint32_t at,uint32_t value){assert(at<sizeof(peripheral));peripheral[at/4]=value;}
static void handler(void *){}
static int attach(uint32_t id,int edge,void (*callback)(void *),void *context,uint32_t *readback,uint64_t *router){
  ++calls;assert(id==389 && !edge && callback==handler && !context);
  assert(peripheral[0xe1c/4]==0 && peripheral[0xe18/4]==0);
  if(failedAttach)return -3;
  gSpiRoutes[id]=1;*readback=0xa003;*router=0;return 0;
}
int main(){
  // Exact063 defect: no route was registered, therefore mask fails without writing GIC.
  assert(armcpu_spi_mask(389,true)==kIOReturnNotFound && !writes);
  SonyGeniIo se={nullptr,mmio,nullptr};SonyTouchIrqOps ops={attach,mask};SonyTouchIrqState state;
  peripheral[0xe1c/4]=15;peripheral[0xe18/4]=15;
  assert(!sony_touch_irq_prepare(&se,&ops,handler,&state));
  assert(state.registered && state.masked && state.attach_result==0 && state.mask_result==0 && calls==1 && writes==1);
  assert(lastGicOffset==0x1b0 && lastGicValue==(1u<<5));
  gSpiRoutes[389]=0;failedAttach=true;
  assert(sony_touch_irq_prepare(&se,&ops,handler,&state)==-3 && !state.registered && !state.masked && writes==1);
  puts("PASS actual ArmCpu unregistered-mask failure reproduced; production helper quiets SE, registers route then masks; attach failure never masks or starts transfer");
}
'''
    generated=a.out/'actual-mask.cpp';generated.write_text(fixture)
    driver=ROOT/'drivers/SonyLxsTouch';obj=a.out/'SonyTouchIrq.o'
    subprocess.run(['clang','-std=c11','-O1','-g','-fsanitize=address,undefined','-Wall','-Wextra','-Werror',
                    '-I',str(driver),'-c',str(driver/'SonyTouchIrq.c'),'-o',str(obj)],check=True)
    command=['clang++','-std=c++17','-O1','-g','-fsanitize=address,undefined','-Wall','-Wextra','-Werror',
             '-I',str(driver),str(generated),str(obj),'-o',str(a.out/'actual-mask')]
    subprocess.run(command,check=True)
    done=subprocess.run([str(a.out/'actual-mask')],capture_output=True,text=True,timeout=15)
    (a.out/'run.log').write_text(done.stdout+done.stderr)
    if done.returncode:raise RuntimeError(done.stdout+done.stderr)
    result=dict(passed=True,source=str(source),source_sha256=sha(source),
        helper_sources={str(p):sha(p) for p in [driver/'SonyTouchIrq.c',driver/'SonyTouchIrq.h']},
        actual_mask_body_extracted=True,old_mask_before_attach_reproduced=True,attach_before_mask_passed=True,
        sanitizers=['address','undefined'],output=done.stdout,hardware_runtime_verified=False)
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(done.stdout,end='')


if __name__=='__main__':main()
