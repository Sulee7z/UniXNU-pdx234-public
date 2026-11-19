#!/usr/bin/env python3
"""Execute the actual adapted IOUserClient method with ASan/UBSan stubs.

Only IOKit objects, its IPC lock/dispatch, boot-argument lookup and optional
observers are stubbed. The qualified helper and method are extracted unchanged
from adapt_source()'s full IOUserClient.cpp result. No GPU behavior is modeled.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import framebuffer_call_trace as overlay


BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
SOURCE = BASE / 'sources/UniXNU/out/pdx234/ios-27.0.1-24A446-iphone14/pdx234_sheng27_bulk/tree/.cache/xnu-work/iokit/Kernel/IOUserClient.cpp'
PRELUDE = r'''
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <type_traits>
#include <vector>
#pragma weak pdx_framebuffer_call_begin
#pragma weak pdx_framebuffer_call_end
#include "PdxFramebufferCallTrace.h"
using IOReturn = int32_t;
constexpr IOReturn kIOReturnSuccess=0;
enum {kIPCLockNone=0,kIPCLockRead=1,kIPCLockWrite=2};
static int optionPresent=1,optionValue=1,optionCalls=0,metaCalls=0,providerCalls=0;
static int activeLock=-1,beginCalls=0,endCalls=0,dispatchCalls=0;
static bool classMatches=true,zeroToken=false,checkInputs=false;
static std::vector<int> events;
static int providerObject;
static const uint64_t *expectedInputs;
static uint32_t expectedInputCount;
static IOReturn resultStatus=0;
static uint32_t returnedCount=0,returnedSize=0,returnedDescriptorSize=0;
static uint64_t *replacementOutput=nullptr;
static bool replaceOutput=false;
static bool PE_parse_boot_argn(const char *name,void *value,unsigned size) {
    assert(!strcmp(name,"first-frame-diag") && size==sizeof(unsigned));
    ++optionCalls;if(optionPresent)*(unsigned *)value=(unsigned)optionValue;return optionPresent;
}
struct IOExternalMethodArguments {
    const uint64_t *scalarInput=nullptr;uint32_t scalarInputCount=0;
    const void *structureInput=nullptr;uint32_t structureInputSize=0;
    void *structureInputDescriptor=nullptr;
    uint64_t *scalarOutput=nullptr;uint32_t scalarOutputCount=0;
    void *structureOutput=nullptr;uint32_t structureOutputSize=0;
    void *structureOutputDescriptor=nullptr;uint32_t structureOutputDescriptorSize=0;
    void *structureVariableOutputData=nullptr;
};
struct IOExternalMethodArgumentsOpaque {};
struct Capture {
    uint64_t token;const void *client,*provider;uint32_t selector,inCount,outCount,endCount;
    const uint64_t *inputPointer,*outputPointer;uint64_t input[3],output[2],inBytes,outBytes,endBytes;
    int32_t status;bool ended;
};
static std::vector<Capture> calls;
static IOReturn dispatch(uint32_t selector,IOExternalMethodArguments *args) {
    assert(activeLock>=0);events.push_back(3);++dispatchCalls;
    if(checkInputs)assert(args && args->scalarInput==expectedInputs && args->scalarInputCount==expectedInputCount);
    if(args) {
        // A callee may report more than it wrote. The observer must not read
        // beyond the entry buffer, or start following a substituted pointer.
        if(args->scalarOutput && resultStatus==0) {
            for(uint32_t i=0;i<std::min(args->scalarOutputCount,returnedCount);++i)args->scalarOutput[i]=100+selector+i;
        }
        args->scalarOutputCount=returnedCount;args->structureOutputSize=returnedSize;
        args->structureOutputDescriptorSize=returnedDescriptorSize;
        if(replaceOutput)args->scalarOutput=replacementOutput;
    }
    return resultStatus;
}
class IOUserClient {
public:
    bool uc2022=false,defaultLocking=false,defaultLockingSingleThreadExternalMethod=false;
    IOReturn callExternalMethod(uint32_t,IOExternalMethodArguments *);
    virtual ~IOUserClient()=default;
    virtual IOReturn externalMethod(uint32_t selector,IOExternalMethodArguments *args) {
        assert(!uc2022);return dispatch(selector,args);
    }
    void ipcEnter(int kind){assert(activeLock==-1);activeLock=kind;events.push_back(1);}
    void ipcExit(int kind){assert(activeLock==kind);events.push_back(5);activeLock=-1;}
    void *metaCast(const char *name){assert(activeLock>=0 && !strcmp(name,"IOMobileFramebufferUserClient"));++metaCalls;return classMatches?this:nullptr;}
    void *getProvider(){assert(activeLock>=0);++providerCalls;return &providerObject;}
};
class IOUserClient2022:public IOUserClient {
public:
    using IOUserClient::externalMethod;
    IOUserClient2022(){uc2022=true;}
    virtual IOReturn externalMethod(uint32_t selector,IOExternalMethodArgumentsOpaque *args) {
        assert(uc2022);return dispatch(selector,reinterpret_cast<IOExternalMethodArguments *>(args));
    }
};
#if PDX_TEST_PROVIDER_BEGIN
extern "C" uint64_t pdx_framebuffer_call_begin(const void *client,const void *provider,uint32_t selector,
    uint32_t count,const uint64_t *input,uint64_t inBytes,uint64_t outBytes,uint32_t outCount) {
    assert(activeLock>=0);events.push_back(2);++beginCalls;
    assert(client && provider==&providerObject);
    Capture call={};call.token=zeroToken?0:static_cast<uint64_t>(calls.size()+1);
    call.client=client;call.provider=provider;call.selector=selector;
    call.inCount=count;call.outCount=outCount;call.inBytes=inBytes;call.outBytes=outBytes;call.inputPointer=input;
    if(input)for(unsigned i=0;i<3 && i<count;++i)call.input[i]=input[i];
    calls.push_back(call);return call.token;
}
#endif
#if PDX_TEST_PROVIDER_END
extern "C" void pdx_framebuffer_call_end(uint64_t token,int32_t status,uint32_t count,const uint64_t *output,uint64_t bytes) {
    assert(activeLock>=0 && token && token<=calls.size());events.push_back(4);++endCalls;
    Capture &call=calls[static_cast<size_t>(token-1)];assert(!call.ended);call.ended=true;
    call.status=status;call.endCount=count;call.outputPointer=output;call.endBytes=bytes;
    if(output)for(unsigned i=0;i<2 && i<count;++i)call.output[i]=output[i];
}
#endif
using BeginABI=uint64_t (*)(const void *,const void *,uint32_t,uint32_t,const uint64_t *,uint64_t,uint64_t,uint32_t);
using EndABI=void (*)(uint64_t,int32_t,uint32_t,const uint64_t *,uint64_t);
static_assert(std::is_same<decltype(&pdx_framebuffer_call_begin),BeginABI>::value,"begin primitive ABI");
static_assert(std::is_same<decltype(&pdx_framebuffer_call_end),EndABI>::value,"end primitive ABI");
'''
TESTS = r'''
static void resetCall() {
    events.clear();calls.clear();activeLock=-1;beginCalls=endCalls=dispatchCalls=0;
    classMatches=true;zeroToken=false;resultStatus=0;returnedCount=0;returnedSize=0;returnedDescriptorSize=0;
    checkInputs=false;replaceOutput=false;replacementOutput=nullptr;
}
static void run(IOUserClient &client,uint32_t selector,IOExternalMethodArguments *args,bool traced,bool token=true) {
    const unsigned oldBegin=beginCalls,oldEnd=endCalls,oldDispatch=dispatchCalls;
    IOReturn result=client.callExternalMethod(selector,args);
    assert(result==resultStatus && activeLock==-1 && dispatchCalls==static_cast<int>(oldDispatch+1));
    assert(beginCalls==static_cast<int>(oldBegin+(traced?1:0)));
    assert(endCalls==static_cast<int>(oldEnd+(traced && token?1:0)));
    const std::vector<int> expected=traced?(token?std::vector<int>{1,2,3,4,5}:std::vector<int>{1,2,3,5}):std::vector<int>{1,3,5};
    assert(events==expected);
}
int main(int argc,char **argv) {
    assert(argc==2);optionValue=atoi(argv[1]);optionPresent=optionValue>=0;
    const bool on=optionPresent && optionValue==1;
    const bool providers=PDX_TEST_PROVIDER_BEGIN && PDX_TEST_PROVIDER_END;
    IOUserClient classic;IOUserClient2022 modern;
    unsigned cases=0;
    // All selectors, both actual dispatch branches and all lock modes. A
    // dispatch that returns an early argument/permission error must still end
    // the matching record, without changing status or any caller arguments.
    for(unsigned selector=0;selector<=101;++selector)for(unsigned branch=0;branch<2;++branch)for(unsigned lock=0;lock<3;++lock) {
        resetCall();IOUserClient &client=branch?static_cast<IOUserClient &>(modern):classic;
        client.defaultLocking=lock!=0;client.defaultLockingSingleThreadExternalMethod=lock==2;
        uint64_t input[3]={selector,0x1122334455667788ull,0xfedcba9876543210ull},output[2]={};
        IOExternalMethodArguments args;args.scalarInput=input;args.scalarInputCount=3;args.scalarOutput=output;args.scalarOutputCount=2;
        args.structureInputSize=1760;args.structureOutputSize=32;
        // Unreadable structure payloads must remain opaque to the observer.
        args.structureInput=reinterpret_cast<const void *>(uintptr_t(1));args.structureOutput=reinterpret_cast<void *>(uintptr_t(3));
        resultStatus=selector%3==0?0:selector%3==1?static_cast<int32_t>(0xe00002c2u):5;
        returnedCount=selector%3;returnedSize=64+selector;
        checkInputs=true;expectedInputs=input;expectedInputCount=3;
        run(client,selector,&args,on && providers);
        assert(args.scalarOutputCount==returnedCount && args.structureOutputSize==returnedSize && args.scalarInput==input && args.scalarInputCount==3);
        if(on && providers) {
            const Capture &call=calls.back();assert(call.selector==selector && call.inCount==3 && call.outCount==2);
            assert(call.input[0]==input[0] && call.input[1]==input[1] && call.input[2]==input[2]);
            assert(call.inBytes==1760 && call.outBytes==32 && call.endBytes==returnedSize && call.endCount==returnedCount && call.status==resultStatus);
            assert((call.outputPointer!=nullptr)==(resultStatus==0));
            if(resultStatus==0)for(unsigned i=0;i<returnedCount;++i)assert(call.output[i]==100+selector+i);
        }
        ++cases;
    }
    resetCall();classMatches=false;IOExternalMethodArguments args;run(classic,5,&args,false);assert(providerCalls==static_cast<int>(on && providers?cases:0));++cases;
    resetCall();run(modern,5,nullptr,false);++cases;
    resetCall();zeroToken=true;run(modern,6,&args,on && providers,false);++cases;
    // Exact-length heap arrays turn accidental extra scalar reads into ASan
    // failures. Reported count growth is clamped only for the observer.
    for(unsigned capacity=0;capacity<=3;++capacity)for(unsigned count=0;count<=4;++count) {
        resetCall();uint64_t *out=capacity?new uint64_t[capacity]():nullptr;
        args={};args.scalarOutput=out;args.scalarOutputCount=capacity;returnedCount=count;
        run(modern,3,&args,on && providers);
        assert(args.scalarOutputCount==count);
        if(on && providers){const Capture &call=calls.back();assert(call.endCount==std::min(count,capacity));if(out && count)assert(call.output[0]==103);}
        delete[] out;++cases;
    }
    for(unsigned count=0;count<=4;++count) {
        resetCall();uint64_t *input=count?new uint64_t[count]():nullptr;
        for(unsigned i=0;i<count;++i)input[i]=i+0x700;
        args={};args.scalarInput=input;args.scalarInputCount=count;
        run(classic,72,&args,on && providers);
        if(on && providers){const Capture &call=calls.back();for(unsigned i=0;i<std::min(count,3u);++i)assert(call.input[i]==i+0x700);}
        delete[] input;++cases;
    }
    // NULL/count, substituted output pointers and failed/uninitialized outputs
    // must not cause observation reads or alter the driver's original verdict.
    resetCall();args={};args.scalarInputCount=3;args.scalarOutputCount=2;returnedCount=2;
    run(classic,74,&args,on && providers);if(on && providers)assert(!calls.back().inputPointer && !calls.back().outputPointer);++cases;
    resetCall();uint64_t out[1]={};args={};args.scalarOutput=out;args.scalarOutputCount=1;returnedCount=UINT32_MAX;
    replaceOutput=true;replacementOutput=reinterpret_cast<uint64_t *>(uintptr_t(1));
    run(modern,3,&args,on && providers);assert(args.scalarOutputCount==UINT32_MAX && args.scalarOutput==replacementOutput);
    if(on && providers)assert(calls.back().endCount==1 && !calls.back().outputPointer);++cases;
    resetCall();args={};args.scalarOutput=reinterpret_cast<uint64_t *>(uintptr_t(1));args.scalarOutputCount=2;
    resultStatus=static_cast<int32_t>(0xe00002c1u);returnedCount=2;
    run(classic,5,&args,on && providers);if(on && providers)assert(!calls.back().outputPointer && calls.back().status==resultStatus);++cases;
    // Descriptor identities are deliberately invalid: an added getLength or
    // a variable-output dereference would fault. Existing size fields suffice.
    resetCall();args={};args.structureInputDescriptor=reinterpret_cast<void *>(uintptr_t(1));
    args.structureInputSize=17;args.structureOutputDescriptor=reinterpret_cast<void *>(uintptr_t(3));
    args.structureOutputSize=19;args.structureOutputDescriptorSize=4096;
    args.structureVariableOutputData=reinterpret_cast<void *>(uintptr_t(5));returnedSize=23;returnedDescriptorSize=2048;
    run(modern,5,&args,on && providers);
    if(on && providers)assert(calls.back().inBytes==UINT64_MAX && calls.back().outBytes==4096 && calls.back().endBytes==2048);++cases;
    if(!providers)assert(optionCalls==0 && metaCalls==0 && providerCalls==0);
    else if(!on)assert(optionCalls==1 && metaCalls==0 && providerCalls==0);
    else assert(optionCalls==1 && metaCalls>0 && providerCalls>0);
    printf("PASS %u cases: option=%d begin=%d end=%d; actual helper/method, lock/dispatch/status, bounded opaque observations\n",cases,optionValue,PDX_TEST_PROVIDER_BEGIN,PDX_TEST_PROVIDER_END);
}
'''


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run_logged(command, log, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, **kwargs)
    log.write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f'{command}: {result.stdout}\n{result.stderr}')
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--source', type=Path, default=SOURCE)
    parser.add_argument('--built', type=Path, help='Also verify an isolated native compile receipt')
    args = parser.parse_args()
    ci = Path(__file__).resolve().parent
    inputs = {name:(ci / name).read_bytes() for name in ('framebuffer_call_trace.py', overlay.HEADER_NAME)}
    raw = args.source.read_bytes()
    assert digest(raw) == overlay.SOURCE_SHA256
    original = raw.decode()
    adapted = overlay.adapt_source(original)
    code = overlay.extracted_code(adapted)
    assert code.count('return ret;') == 1 and code.count('ipcEnter(') == 1 and code.count('ipcExit(') == 1
    for line in overlay.ORIGINAL_METHOD.splitlines():
        if 'externalMethod(selector,' in line:
            assert code.count(line) == 1
    assert code.index('ipcEnter(') < code.index('pdx_framebuffer_call_begin(this,') < code.index('if (uc2022)')
    assert code.index('pdx_framebuffer_call_end(pdx_trace_token,') < code.index('ipcExit(') < code.index('return ret;')
    assert not any(value in code for value in ('getLength(', 'structureInput[', 'structureOutput[', 'copyin(', 'copyout(', '__asm__'))
    for changed in (original + '\n', original.replace('return ret;', 'return 0;', 1), adapted):
        try:
            overlay.adapt_source(changed)
        except ValueError:
            pass
        else:
            raise AssertionError('Changed/double-overlay source was not refused')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    (out / overlay.HEADER_NAME).write_bytes(inputs[overlay.HEADER_NAME])
    (out / 'adapted-IOUserClient.cpp').write_bytes(adapted.encode())
    harness = out / 'actual-method.cpp'
    harness.write_text(PRELUDE + code + TESTS)
    flags = ['clang++', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
             '-Wno-ignored-attributes', '-Wno-pointer-bool-conversion',
             '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-I' + str(out)]
    env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    results = []
    for begin, end in ((1, 1), (1, 0), (0, 1), (0, 0)):
        name = f'callbacks-{begin}{end}'
        executable = out / name
        command = flags + [f'-DPDX_TEST_PROVIDER_BEGIN={begin}', f'-DPDX_TEST_PROVIDER_END={end}', str(harness), '-o', str(executable)]
        run_logged(command, out / (name + '-compile.log'))
        undefined = subprocess.check_output(['nm', '-u', str(executable)], text=True)
        for available, symbol in ((begin, 'pdx_framebuffer_call_begin'), (end, 'pdx_framebuffer_call_end')):
            if not available:
                assert any(line.split() == ['w', symbol] for line in undefined.splitlines()), f'Absent callback must remain weak: {symbol}'
        for option in ('1', '0', '2', '-1'):
            invocation = [str(executable), option]
            output = run_logged(invocation, out / (name + '-option' + option + '.log'), env=env)
            results.append(dict(command=invocation, output=output))
    built = None
    if args.built:
        built = json.loads((args.built / 'result.json').read_text())
        assert built['original_source_sha256'] == digest(raw)
        assert built['source_sha256'] == digest(adapted.encode())
        assert built['header_sha256'] == digest(inputs[overlay.HEADER_NAME])
        assert built['overlay_sha256'] == digest(inputs['framebuffer_call_trace.py'])
        assert digest(Path(built['object']).read_bytes()) == built['object_sha256']
        assert built['native_pac_dispatch_verified'] and not built['relinked']
    for name, data in inputs.items():
        assert (ci / name).read_bytes() == data, 'Trace inputs changed during tests'
    assert args.source.read_bytes() == raw
    receipt = dict(passed=True, original_source_sha256=digest(raw), adapted_source_sha256=digest(adapted.encode()),
                   method_sha256=digest(code.encode()), headers={overlay.HEADER_NAME:digest(inputs[overlay.HEADER_NAME])},
                   overlay_sha256=digest(inputs['framebuffer_call_trace.py']), test_sha256=digest(Path(__file__).read_bytes()),
                   harness_sha256=digest(harness.read_bytes()), compiler=subprocess.check_output(['clang++', '--version'], text=True).splitlines()[0],
                   flags=flags, runs=results, source_envelope_only=True, sanitizers=['address', 'undefined'], native_build=built,
                   actual_code='Qualified full-source overlay; extracted byte-identical helper and callExternalMethod',
                   modeled_boundaries='IOKit class identity/provider, IPC lock, original dispatch and primitive RAM observer',
                   descriptor_dereferences=False, user_memory_reads=False, vtable_interposition=False,
                   runtime_verified=False, device_operations=False)
    (out / 'result.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
