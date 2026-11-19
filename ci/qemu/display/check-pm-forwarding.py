#!/usr/bin/env python3
"""Check the emitted QEMU PM method's real early/late forwarding branches."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def extract(text,marker):
    start=text.index(marker);brace=text.index('{',start);depth=1;end=brace+1
    while depth:depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return text[start:end].replace(' override','')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    path=a.build/'source/NativeLegacyDisplay.cpp'
    method=extract(path.read_text(),'    IOReturn setPowerState(unsigned long ordinal,IOService *device)')
    code=r'''
#include <cassert>
#include <cstdio>
#include <vector>
using IOReturn=int;
constexpr int kIOReturnSuccess=0,kIOReturnUnsupported=-1;
struct IOService {};
struct IOMobileFramebufferLegacy {
    unsigned calls=0;unsigned long lastOrdinal=99;IOService *lastDevice=nullptr;
    IOReturn setPowerState(unsigned long ordinal,IOService *device){++calls;lastOrdinal=ordinal;lastDevice=device;return 42;}
};
static std::vector<unsigned> events,stages;
static void native_qemu_display_observe(unsigned event,void *){events.push_back(event);}
static void native_legacy_pm_observed(unsigned stage,IOReturn,unsigned long){stages.push_back(stage);}
struct Display:IOMobileFramebufferLegacy {
    bool logicalPM=false,bootMapping=false;
''' + method + r'''
};
int main(){
    IOService device;
    // Early original-family path keeps arbitrary genuine ordinals and device.
    for(unsigned long ordinal:{0ul,1ul,7ul}){
        Display d;events.clear();stages.clear();
        assert(d.setPowerState(ordinal,&device)==42);
        assert(d.calls==1 && d.lastOrdinal==ordinal && d.lastDevice==&device);
        assert((events==std::vector<unsigned>{5,6}) && stages.empty());
    }
    // Logical-PM path keeps both accepted ordinals and a null device unchanged.
    for(unsigned long ordinal:{0ul,1ul}){
        Display d;d.logicalPM=d.bootMapping=true;events.clear();stages.clear();
        assert(d.setPowerState(ordinal,nullptr)==42);
        assert(d.calls==1 && d.lastOrdinal==ordinal && !d.lastDevice);
        assert((events==std::vector<unsigned>{5}) && (stages==std::vector<unsigned>{3,4}));
    }
    for(bool mapping:{false,true}){
        Display d;d.logicalPM=true;d.bootMapping=mapping;events.clear();stages.clear();
        assert(d.setPowerState(2,&device)==kIOReturnUnsupported && !d.calls);
        assert((events==std::vector<unsigned>{5}) && (stages==std::vector<unsigned>{3}));
    }
    puts("PASS actual QEMU setPowerState: early/late branches preserve ordinal/device/result; unsupported states remain rejected");
}
'''
    cpp=a.out/'actual-pm-forwarding.cpp';cpp.write_text(code)
    cmd=['clang++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
         '-fno-omit-frame-pointer',str(cpp),'-o',str(a.out/'actual-pm-forwarding')]
    subprocess.run(cmd,check=True)
    result=subprocess.run([str(a.out/'actual-pm-forwarding')],check=True,capture_output=True,text=True)
    receipt=dict(command=cmd,source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                 actual_method_sha256=hashlib.sha256(method.encode()).hexdigest(),output=result.stdout,
                 sanitizers=['address','undefined'],guest_runtime=False)
    (a.out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(result.stdout,end='')


if __name__=='__main__':main()
