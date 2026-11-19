#!/usr/bin/env python3
"""Exercise extracted production methods with failing IOKit services and completions."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

import sony_display_overlay as overlay


def method(source, marker):
    start = source.index(marker)
    brace = source.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    original = (args.baseline/'drivers/GopFramebuffer/NativeLegacyDisplay.cpp').read_text()
    gop = overlay.apply_gop(original)
    abi = json.loads((args.baseline/'scripts/legacy-display-24A446.json').read_text())
    fields = overlay.qualify(abi, args.cache.read_bytes())
    upstream_probe = (args.baseline.parent/'sources/sheng/package/LegacyDisplayProbe.cpp').read_text()
    probe = overlay.apply_probe(upstream_probe, fields)
    presenter = (args.baseline/'drivers/GopFramebuffer/NativeGOPPresenter.cpp').read_text()
    # Replay fails closed on a changed/already-overlaid input or mismatching OS.
    for bad in (original+'\n', gop):
        try:
            overlay.apply_gop(bad)
        except ValueError:
            pass
        else:
            raise AssertionError('Overlay accepted unqualified input')
    badabi = dict(abi, kernelcache_sha256='0'*64)
    try:
        overlay.qualify(badabi, b'')
    except ValueError:
        pass
    else:
        raise AssertionError('Overlay accepted different OS')
    start = method(gop, '    bool start(IOService *provider) override').replace(' override', '')
    publish = method(gop, '    bool publishOneLayer()')
    offer = method(gop, '        if(!gpuBypass && native_legacy_gpu_offer(')
    finish = method(gop, '    void finishGpuSwap(int status)')
    complete = method(presenter, 'IOReturn NativeGOPPresenter::completeSwap').replace('NativeGOPPresenter::', '')
    retirement = method(probe, '__attribute__((noinline)) void native_legacy_retirement_observed')
    power = method(probe, 'extern "C" unsigned native_legacy_state_words')
    code = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
using IOReturn=int;
constexpr int kIOReturnSuccess=0,kIOReturnBadArgument=1;
static int failure,alive,earlyArg=-1;
struct IOService {};
struct Ref { int refs=1; Ref(){++alive;} virtual ~Ref(){--alive;} void retain(){++refs;} void release(){if(!--refs)delete this;} };
struct OSNumber:Ref { static OSNumber *withNumber(unsigned long long n,unsigned bits){assert(n==1 && bits==32);return failure==2?nullptr:new OSNumber;} };
struct OSDictionary:Ref {
    OSNumber *number=nullptr;
    static OSDictionary *withCapacity(unsigned n){assert(n==1);return failure==1?nullptr:new OSDictionary;}
    bool setObject(const char *key,OSNumber *value){assert(!strcmp(key,"MaxNumLayers"));if(failure==3)return false;number=value;value->retain();return true;}
    ~OSDictionary(){if(number)number->release();}
};
#define OSSafeReleaseNULL(p) do {if(p){(p)->release();(p)=nullptr;}}while(0)
struct Publish {
    OSDictionary *property=nullptr; int baseCalls=0,vsync=0,direct=0; bool baseOK=true;
    ~Publish(){OSSafeReleaseNULL(property);}
    bool setProperty(const char *key,OSDictionary *value){assert(!strcmp(key,"IOMFBNumLayers"));if(failure==4)return false;property=value;value->retain();return true;}
    bool startDisplay(IOService *){++baseCalls;assert(property && property->number);return baseOK;}
    void startVsync(){++vsync;}void startDirect(){++direct;}
''' + start + '\n' + publish + r'''
};
struct OriginalLegacySwapRequest {int id;};
struct Frame:Ref {};
static int fallbackCount,transferCount;
static unsigned native_legacy_early_retires,native_legacy_early_failures;
static unsigned native_gop_gpu_failures,native_gop_gpu_completions;
static void PE_parse_boot_argn(const char *key,unsigned *out,unsigned){assert(!strcmp(key,"early-retire"));if(earlyArg>=0)*out=earlyArg;}
static void native_legacy_swap_stage(int){}static void countFormat(int){}
static void native_legacy_gpu_fallback_observed(int){++fallbackCount;}
static void native_legacy_transfer_observed(int,const OriginalLegacySwapRequest *,uint64_t){++transferCount;}
struct Display;
static void native_legacy_gpu_complete(void *,int);
static bool native_legacy_gpu_offer(Display *,Frame *,uint64_t,uint32_t,uint32_t,uint32_t){return true;}
constexpr unsigned NGP_BGRX8888=1;
struct Display {
    bool gpuBypass=false,shadowValid=true,transferred=false,gpuRetired=false;
    const OriginalLegacySwapRequest *gpuRequest=nullptr;
    uint64_t gpuTraceRequest=0,gpuLength=0; int retired=0,kicks=0;
    unsigned halfOfferFormat(){return 2;}uint64_t traceId(const OriginalLegacySwapRequest *){return 1;}
    bool retireSwap(const OriginalLegacySwapRequest *r,bool force){assert(r && force);++retired;return true;}
    void kickSwapQueue(){++kicks;}
    void finishTransfer(const OriginalLegacySwapRequest *r,bool force){retireSwap(r,force);transferred=false;kickSwapQueue();}
    void offerFrame(const OriginalLegacySwapRequest *request,Frame *memory){
        uint64_t sourceStride=32,length=64;uint32_t width=8,height=2;bool half=false;
''' + offer + '\n    }\n' + finish + r'''
};
static void native_legacy_gpu_complete(void *d,int status){static_cast<Display *>(d)->finishGpuSwap(status);}
static void IOLockLock(int){}static void IOLockUnlock(int){}
struct Presenter {
    int gate=1;
    struct Swap {bool offered=false,delivered=false;uint64_t sequence=0;void *display=nullptr;Frame *memory=nullptr,*map=nullptr;} swap;
''' + complete + r'''
};
static uint64_t native_legacy_object,native_legacy_retired_current,native_legacy_retired_pending;
static uint32_t native_legacy_retired_generation,native_legacy_presented_generation,native_legacy_retired_frames,native_legacy_retirement_calls;
''' + retirement + '\n' + power + r'''
int main(){
    IOService provider;
    for(failure=0;failure<=4;++failure){
        {Publish p;bool ok=p.start(&provider);assert(ok==(failure==0));assert(p.baseCalls==(failure==0));assert(p.vsync==(failure==0) && p.direct==(failure==0));}
        assert(alive==0);
    }
    failure=0;{Publish p;p.baseOK=false;assert(!p.start(&provider));assert(p.baseCalls==1 && p.vsync==0 && p.direct==0);}assert(alive==0);
    OriginalLegacySwapRequest request{1};
    // Actual offer branch must keep the request until the matching sequence completes.
    {Display d;Frame *frame=new Frame;d.offerFrame(&request,frame);assert(d.retired==0 && d.transferred && d.gpuRequest==&request);
     Presenter p;p.swap={true,true,42,&d,frame,nullptr};
     assert(p.completeSwap(41,0)==kIOReturnBadArgument);assert(d.retired==0 && alive==1);
     assert(p.completeSwap(42,0)==0);assert(d.retired==1 && !d.transferred && d.kicks==1 && alive==0);
     assert(p.completeSwap(42,0)==kIOReturnBadArgument);assert(d.retired==1);}
    // A failed copy invokes fallback without falsely completing the family swap.
    {Display d;Frame *frame=new Frame;d.offerFrame(&request,frame);Presenter p;p.swap={true,true,8,&d,frame,nullptr};
     assert(p.completeSwap(8,5)==0);assert(d.retired==0 && d.gpuBypass && !d.transferred && d.kicks==1 && alive==0);}
    // Explicit compatibility opt-in remains available; arbitrary values do not enable it.
    for(int mode: {0,1,2}){earlyArg=mode;Display d;Frame *frame=new Frame;d.offerFrame(&request,frame);
        assert(d.retired==(mode==1));d.finishGpuSwap(0);assert(d.retired==1);frame->release();}
    assert(alive==0 && fallbackCount==1 && native_gop_gpu_completions==1 && native_gop_gpu_failures==1);
    // D27 reads must ignore plausible-looking values in the old layout.
    alignas(16) unsigned char object[0x1dd8];memset(object,0xa5,sizeof object);
    uint64_t current=0x12345678,head=0x87654321;uint32_t requested=2,powered=1;
    memcpy(object+6720,&current,8);memcpy(object+6728,&head,8);memcpy(object+7180,&requested,4);memcpy(object+7184,&powered,4);
    native_legacy_object=(uintptr_t)object;native_legacy_retirement_observed(reinterpret_cast<IOService *>(object));
    assert(native_legacy_retired_current==current && native_legacy_retired_pending==head);
    assert(native_legacy_retired_generation==UINT32_MAX && native_legacy_presented_generation==UINT32_MAX && native_legacy_retired_frames==UINT32_MAX);
    char out[128];native_legacy_state_words(out,sizeof out);assert(strstr(out,"requested=2 powered=1"));
    assert(native_legacy_state_words(nullptr,0)==0);char tiny[2];assert(native_legacy_state_words(tiny,2)==1 && tiny[1]==0);
    puts("PASS: publication failure/ordering, matching completion/rejection/fallback, compatibility, D27 observation bounds");
}
'''
    source = args.out/'actual-methods.cpp'
    source.write_text(code)
    command = ['clang++', '-std=c++17', '-g', '-O1', '-Wall', '-Wextra', '-Werror',
               '-fsanitize=address,undefined', '-fno-omit-frame-pointer', str(source), '-o', str(args.out/'actual-methods')]
    subprocess.run(command, check=True)
    result = subprocess.run([str(args.out/'actual-methods')], check=True, capture_output=True, text=True)
    receipt = dict(command=command, output=result.stdout, helper_sha256=overlay.digest(Path(overlay.__file__).read_bytes()),
                   extracted_test_sha256=overlay.digest(source.read_bytes()), upstream_gop_sha256=overlay.GOP_SHA256,
                   adapted_gop_sha256=overlay.digest(gop.encode()), diagnostic_fields=fields,
                   device_operations=False, sanitizers=['address','undefined'])
    (args.out/'result.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(result.stdout, end='')


if __name__ == '__main__':
    main()
