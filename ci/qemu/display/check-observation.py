#!/usr/bin/env python3
"""ASan/UBSan checks of the actual passive D27 observation implementation."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=False)
    production=args.build/'source/QemuDisplayObservation.cpp'
    source='\n'.join(line for line in production.read_text().splitlines() if not line.startswith('#include'))
    offsets=(args.build/'source/QemuDisplayOffsets.h').read_text()
    code=r'''
#include <cassert>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <climits>
struct OSObject { const char *kind=""; bool metaCast(const char *s)const{return !strcmp(kind,s);} };
struct IOService:OSObject {};
struct IOMemoryDescriptor:OSObject {uint64_t bytes=0;uint64_t getLength(){return bytes;}};
static IOMemoryDescriptor memory;
static bool descriptor=true;
static uint64_t width=800,height=600,stride=3200;
static uint32_t format=0x42475241,planes=0;
extern "C" IOMemoryDescriptor *native_legacy_surface_descriptor(OSObject *) {return descriptor?&memory:nullptr;}
extern "C" uint64_t native_legacy_surface_width(OSObject *) {return width;}
extern "C" uint64_t native_legacy_surface_height(OSObject *) {return height;}
extern "C" uint64_t native_legacy_surface_stride(OSObject *) {return stride;}
extern "C" uint32_t native_legacy_surface_format(OSObject *) {return format;}
extern "C" uint32_t native_legacy_surface_planes(OSObject *) {return planes;}
''' + offsets + '\n' + source + r'''
int main() {
    alignas(16) unsigned char display[0x1dd8]={};
    unsigned char before[sizeof(display)];
    const uint32_t requested=0,powered=1;
    const uint64_t current=0x12345678,pending=0x87654321;
    memcpy(display+kQemuRequested,&requested,4);memcpy(display+kQemuPowered,&powered,4);
    memcpy(display+kQemuCurrent,&current,8);memcpy(display+kQemuPending,&pending,8);
    OSObject surface;surface.kind="IOSurface";
    OSObject *pointer=&surface;memcpy(display+kQemuDefaultSurface,&pointer,sizeof(pointer));
    memory.kind="IOMemoryDescriptor";memory.bytes=stride*height;
    memcpy(before,display,sizeof(display));
    native_qemu_display_observe(0,nullptr);assert(native_qemu_display_observation_count==0);
    native_qemu_display_observe(1,reinterpret_cast<IOService *>(display));
    const auto &first=native_qemu_display_observations[0];
    assert(first.sequence==1 && first.requested==0 && first.powered==1 && first.current==current && first.pending==pending);
    assert(first.surfaceValid && first.width==800 && first.height==600 && first.descriptorBytes==1920000);
    assert(!memcmp(display,before,sizeof(display)));
    for(unsigned i=0;i<8;++i) {
        descriptor=true;width=800;height=600;stride=3200;format=0x42475241;planes=0;memory.bytes=1920000;
        if(i==0)descriptor=false;
        if(i==1)width=0;
        if(i==2)height=0;
        if(i==3)stride=3199;
        if(i==4)memory.bytes=1919999;
        if(i==5)format=0x52476841;
        if(i==6)planes=1;
        if(i==7){height=16384;stride=UINT64_MAX;}
        native_qemu_display_observe(i+2,reinterpret_cast<IOService *>(display));
        assert(!native_qemu_display_observations[i+1].surfaceValid);
        assert(!memcmp(display,before,sizeof(display)));
    }
    for(unsigned i=0;i<100;++i)native_qemu_display_observe(99,reinterpret_cast<IOService *>(display));
    assert(native_qemu_display_observation_count==109);
    assert(first.sequence==1 && first.surfaceValid);
    assert(native_qemu_display_observations[31].sequence==32);
    puts("PASS actual passive observations: unchanged state/surface, bounds, wrong descriptors/formats, fixed ring capacity");
}
'''
    cpp=args.out/'actual-observation.cpp';cpp.write_text(code)
    command=['clang++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
             '-fno-omit-frame-pointer',str(cpp),'-o',str(args.out/'actual-observation')]
    subprocess.run(command,check=True)
    result=subprocess.run([str(args.out/'actual-observation')],check=True,capture_output=True,text=True)
    receipt=dict(command=command,production_sha256=hashlib.sha256(production.read_bytes()).hexdigest(),
                 offsets_sha256=hashlib.sha256(offsets.encode()).hexdigest(),
                 output=result.stdout,sanitizers=['address','undefined'],guest_runtime=False)
    (args.out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(result.stdout,end='')


if __name__=='__main__':main()
