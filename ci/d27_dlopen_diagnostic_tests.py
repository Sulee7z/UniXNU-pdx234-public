#!/usr/bin/env python3
"""Host sanitizer tests for owned dlerror, exact prefix parsing and two-slot loss accounting."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import d27_dlopen_diagnostic as adapter


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--plugin', type=Path, required=True, help='Already startup-adapted plugin source')
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    if shutil.disk_usage('/mnt/g').free < 8*1024**3:
        raise RuntimeError('G: free space below 8 GiB')
    args.out.mkdir(parents=True, exist_ok=False)
    original = args.plugin.read_text()
    adapted = adapter.adapt(original)
    for bad in (adapted, original.replace('const char *loaderError', 'const char *changedError')):
        try:
            adapter.adapt(bad)
        except ValueError:
            pass
        else:
            raise AssertionError('Accepted changed/already applied startup code')
    first = adapted.index('        d27dlopen::Diagnostic loaderDiagnostic(')
    last = adapted.index('        gpu->mark(0x6804);', first)+len('        gpu->mark(0x6804);')
    # Execute the adapter's actual output; only translate the ObjC log literal
    # and nil to host C++ equivalents. Loader, log and marker calls are modeled.
    branch = adapted[first:last].replace('NSLog(@"', 'testLog("').replace('return nil;', 'return 0;')
    source = args.out/'actual-dlopen.cpp'
    source.write_text(r'''
#include "D27DlopenDiagnostic.h"
#include <cassert>
#include <cstring>
#include <string>
#include <vector>
#include <cstdarg>
#include <pthread.h>
static pthread_mutex_t gStreamLock=PTHREAD_MUTEX_INITIALIZER;
static char loaderBuffer[8192];
static std::string injected,logged;
static unsigned mode,slot;
static std::string report[2];
enum {RTLD_NOW=2,RTLD_LOCAL=4};
static char *dlerror(){return loaderBuffer[0]?loaderBuffer:nullptr;}
static void *dlopen(const char *,int){strcpy(loaderBuffer,injected.c_str());return mode==0?nullptr:(void*)1;}
static void *dlsym(void *,const char *){strcpy(loaderBuffer,injected.c_str());return mode==1?nullptr:(void*)1;}
static void poison(){strcpy(loaderBuffer,"REPLACED BY LATER CALL");}
static void testLog(const char *format,...){
    poison();char buffer[8192];va_list ap;va_start(ap,format);vsnprintf(buffer,sizeof buffer,format,ap);va_end(ap);logged=buffer;
}
struct Gpu {unsigned failure=0;
    void mark(unsigned value){
        poison();if(value==0x7ffe || value==0x7fff){slot=value==0x7fff;report[slot].clear();}
        else if(value>=0x7000 && value<0x7100){assert(report[slot].size()<63);report[slot]+=(char)(value&255);}
        else failure=value;
    }
};
static int run(Gpu *gpu,const char *turnip){
''' + branch + r'''
    return 1;
}
static void checkRows(const d27dlopen::Diagnostic &d,bool symbol=false){
    char rows[2][64];memset(rows,0xa5,sizeof rows);d.rows(rows,symbol);
    assert(strlen(rows[0])<=63 && strlen(rows[1])<=63);
    size_t n=0;char plus=0;unsigned capture=0,wire=0;
    // Parse the explicit lower-bound marker separately.
    const char *p=strchr(rows[0],'L');assert(p);
    n=strtoul(p+1,nullptr,10);p=strchr(p,' ');assert(p);
    plus=p[-1]=='+';assert(sscanf(p," C%u W%u",&capture,&wire)==2);
    assert(n==strlen(d.cause()) && capture==d.rawOverflow && plus==d.rawOverflow);
    const char *head=strstr(rows[0]," H:")+3,*tail=strchr(rows[1],':')+1;
    const char *offset=strchr(rows[1],' ')+1;offset+=d.rawOverflow?2:1;
    size_t at=strtoul(offset,nullptr,10);
    assert(at+strlen(tail)==n);
    assert(wire==(d.rawOverflow || strlen(head)+strlen(tail)<n));
    for(size_t i=0;i<strlen(head);++i)assert(head[i]==d.printable(d.cause()[i]));
    for(size_t i=0;i<strlen(tail);++i)assert(tail[i]==d.printable(d.cause()[at+i]));
    if(!wire)assert(std::string(head)+tail==d.cause());
}
int main(){
    using d27dlopen::Diagnostic;
    const char *path="/System/Library/Extensions/NativeAdrenoMetal.bundle/libvulkan_freedreno.dylib";
    Diagnostic d(path,6);
    std::string prefix=std::string("dlopen(")+path+", 0x0006): ";
    std::string cause="Library not loaded: /usr/lib/libmissing.dylib; Reason: symbol not found: _tail_symbol";
    std::string error=prefix+cause;
    strcpy(loaderBuffer,error.c_str());d.capture(dlerror());poison();
    assert(std::string(d.raw)==error && std::string(d.path)==path && std::string(d.cause())==cause);
    checkRows(d);
    for(const auto &valid: {std::string("6"),std::string("0x6"),std::string("0x0006")}){
        std::string raw=std::string("dlopen(")+path+", "+valid+"): "+cause;d.capture(raw.c_str());assert(d.cause()==cause);checkRows(d);
    }
    const std::vector<std::string> bad={
        "prefix "+error, std::string("dlopen(/different, 0x0006): ")+cause,
        std::string("dlopen(")+path+", 0x0002): "+cause,
        std::string("dlopen(")+path+", 4294967302): "+cause,
        std::string("dlopen(")+path+", 0x100000006): "+cause,
        std::string("dlopen(")+path+", 0x): "+cause,
        std::string("dlopen(")+path+",6): "+cause,
        std::string("dlopen(")+path+", 6):"+cause,
        std::string("dlopen(")+path+", 6) "+cause,
        std::string("dlopen(")+path+", 6):\n"+cause,
        "Reason: "+cause, "tried: "+cause, "image not found: "+cause
    };
    for(const auto &raw:bad){d.capture(raw.c_str());assert(d.causeOffset()==0 && std::string(d.cause())==raw);checkRows(d);}
    // Path with punctuation is matched byte-for-byte, not scanned to first ')'.
    Diagnostic punctuation("/foo), 6): bar",6);std::string special="dlopen(/foo), 6): bar, 6): true cause";
    punctuation.capture(special.c_str());assert(!strcmp(punctuation.cause(),"true cause"));checkRows(punctuation);
    // All row/capture boundary lengths, including a truly oversized error.
    for(size_t n=0;n<=5000;++n){std::string value(n,'x');if(n>=4)value.replace(n-4,4,"TAIL");
        d.capture(value.c_str());assert(d.rawLength==(n<4096?n:4095));assert(d.rawOverflow==(n>=4096));checkRows(d,n%2);
    }
    d.capture(nullptr);assert(d.missing && !strcmp(d.cause(),"dlerror unavailable"));checkRows(d);
    d.capture("");assert(d.missing);checkRows(d);
    std::string emptyPrefix=prefix;d.capture(emptyPrefix.c_str());assert(!d.missing && !*d.cause());checkRows(d);
    std::string longPath(1024,'p');Diagnostic truncatedPath(longPath.c_str(),6);
    std::string longError="dlopen("+longPath+", 6): cause";truncatedPath.capture(longError.c_str());
    assert(truncatedPath.pathOverflow && truncatedPath.causeOffset()==0);checkRows(truncatedPath);
    d.capture("message\nwith\tcontrol\x01 bytes");char control[2][64];d.rows(control,false);
    assert(strstr(control[0],"message?with?control? bytes"));
    // Actual adapter code: logging/marking deliberately invalidate dlerror storage.
    for(mode=0;mode<=2;++mode){Gpu gpu;report[0].clear();report[1].clear();logged.clear();injected=error;
        int result=run(&gpu,path);assert(result==(mode==2));
        if(mode<2){assert(gpu.failure==(mode?0x68f5u:0x68f4u));
            assert(logged.find(error)!=std::string::npos && logged.find(path)!=std::string::npos);
            assert(logged.find("REPLACED BY LATER CALL")==std::string::npos);
            assert(report[0].find("Library not loaded")!=std::string::npos);
            assert(report[1].find("_tail_symbol")!=std::string::npos);
            assert(report[0].find(mode?"D5":"D4")==0);
        }else assert(report[0].empty() && report[1].empty() && gpu.failure==0x6804);
    }
    puts("PASS: immediate owned dlerror, exact path/flags prefix, 5001 lengths, head/tail/overflow, adapter failure/success branches");
}
''')
    command = ['clang++', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
               '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-pthread',
               '-I'+str(Path(adapter.__file__).parent), str(source), '-o', str(args.out/'actual-dlopen')]
    build = subprocess.run(command, capture_output=True, text=True)
    (args.out/'compile.log').write_text(build.stdout+build.stderr)
    if build.returncode:
        raise RuntimeError(build.stdout+build.stderr)
    run = subprocess.run([str(args.out/'actual-dlopen')], capture_output=True, text=True)
    (args.out/'test.log').write_text(run.stdout+run.stderr)
    if run.returncode:
        raise RuntimeError(run.stdout+run.stderr)
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    receipt = dict(command=command, output=run.stdout, original_plugin=str(args.plugin),
                   original_plugin_sha256=digest(args.plugin), adapted_plugin_sha256=hashlib.sha256(adapted.encode()).hexdigest(),
                   header_sha256=digest(Path(adapter.__file__).with_name('D27DlopenDiagnostic.h')),
                   adapter_sha256=digest(Path(adapter.__file__)), test_sha256=digest(source),
                   report_slots=2, report_payload_bytes=63, error_capture_bytes=4095, path_capture_bytes=1023,
                   arbitrary_error_complete=False, device_operations=False, image_built=False,
                   kernel_changes=False, hardware_verified=False)
    (args.out/'result.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
