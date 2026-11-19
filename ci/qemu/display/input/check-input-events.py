#!/usr/bin/env python3
"""Run the emitted VirtIO event decoding/queue methods under ASan/UBSan."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def body(text,signature):
    start=text.index(signature);brace=text.index('{',start);depth=1;end=brace+1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return text[start:end]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    source=a.build/'source/VirtioInput.cpp';text=source.read_text()
    methods='\n'.join(body(text,s) for s in ('    void publish()', '    void handle(const Event &event)', '    void poll()'))
    methods=methods.replace('__asm__ volatile("dmb ish" ::: "memory");','')
    code=r'''
#include <cassert>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <vector>
constexpr unsigned kQueueSize=64;
constexpr uint16_t kEvSyn=0,kEvKey=1,kEvAbs=3,kAbsX=0,kAbsY=1,kBtnLeft=0x110,kBtnTouch=0x14a,kKeyHome=102,kKeyF1=59;
constexpr int kTouchWidth=30480,kTouchHeight=20320;
struct Used {uint32_t id,length;};
struct Event {uint16_t type,code;uint32_t value;};
uint32_t native_touch_seq=0,native_touch_count=0,native_hid_input_command=0;
uint32_t native_virtio_input_events=0,native_virtio_input_touches=0,native_virtio_input_keys=0,native_virtio_input_failures=0;
int native_touch_ids[12],native_touch_xs[12],native_touch_ys[12];
unsigned notifications=0;
void native_touch_published(){assert(!(native_touch_seq&1));++notifications;}
void dmaBarrier(){}
struct Memory {unsigned char bytes[4096]={};void *getBytesNoCopy(){return bytes;}};
struct Device {
 Memory eventMemory;Memory *events=&eventMemory;
 uint16_t available=64,used=0;uint32_t maxX=0x7fff,maxY=0x7fff,x=0,y=0,status=15,interrupt=0;
 bool button=false,touching=false;uint16_t avail[66]={},usedHead[2]={};Used ring[64]={};unsigned notifies=0;
 uint16_t *availableRing(){return avail;}uint16_t *usedHeader(){return usedHead;}Used *usedRing(){return ring;}
 uint32_t read32(unsigned at){return at==0x70?status:at==0x60?interrupt:0;}
 void write32(unsigned at,uint32_t value){if(at==0x70)status=value;if(at==0x50)++notifies;if(at==0x64)interrupt&=~value;}
''' + methods + r'''
};
int main(){
 Device d;
 d.handle({kEvAbs,kAbsX,0x7fff});d.handle({kEvAbs,kAbsY,0x7fff});d.handle({kEvKey,kBtnLeft,1});d.handle({kEvSyn,0,0});
 assert(native_touch_count==1 && native_touch_xs[0]==30479 && native_touch_ys[0]==20319 && native_touch_ids[0]==1);
 d.handle({kEvAbs,kAbsX,0xffffffff});d.handle({kEvSyn,0,0});assert(native_touch_xs[0]==30479 && notifications==2);
 d.handle({kEvKey,kBtnLeft,0});d.handle({kEvSyn,0,0});assert(native_touch_count==0 && notifications==3);
 d.handle({kEvSyn,0,0});assert(notifications==3);
 d.handle({kEvKey,kKeyHome,1});assert(native_hid_input_command==1);
 d.handle({kEvKey,kKeyHome,0});assert(native_hid_input_command==1);
 native_hid_input_command=0;d.handle({kEvKey,kKeyF1,1});assert(native_hid_input_command==1);
 Device poll;Event event={kEvKey,kBtnTouch,1};memcpy(poll.eventMemory.bytes,&event,sizeof(event));
 poll.ring[0]={0,8};poll.usedHead[1]=1;poll.poll();assert(poll.used==1 && poll.available==65 && poll.avail[2]==0 && poll.notifies==1 && poll.button);
 Device wrap;wrap.used=wrap.available=65535;wrap.usedHead[1]=0;wrap.ring[63]={1,8};
 memcpy(wrap.eventMemory.bytes+8,&event,8);wrap.poll();assert(wrap.used==0 && wrap.available==0 && wrap.avail[65]==1);
 for(auto bad:std::vector<Used>{{64,8},{0,7},{0,0},{0,9}}){
  Device invalid;invalid.ring[0]=bad;invalid.usedHead[1]=1;auto failures=native_virtio_input_failures;
  invalid.poll();assert((invalid.status&128) && native_virtio_input_failures==failures+1 && invalid.available==64 && !invalid.notifies);
 }
 Device failed;failed.status=128;auto failures=native_virtio_input_failures;failed.poll();assert(native_virtio_input_failures==failures+1);
 puts("PASS actual VirtIO methods: down/move/up, axis clamp, Home press/release, queue completion/wrap and malformed completion failure");
}
'''
    cpp=a.out/'actual-input-events.cpp';cpp.write_text(code)
    command=['clang++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
             '-fno-omit-frame-pointer',str(cpp),'-o',str(a.out/'actual-input-events')]
    subprocess.run(command,check=True)
    done=subprocess.run([str(a.out/'actual-input-events')],check=True,capture_output=True,text=True)
    receipt=dict(source=str(source),source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                 command=command,output=done.stdout,sanitizers=['address','undefined'],guest_runtime=False)
    (a.out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n');print(done.stdout,end='')


if __name__=='__main__':main()
