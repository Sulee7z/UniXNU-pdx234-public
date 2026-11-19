#!/usr/bin/env python3
"""Validate overlay against the pinned source and execute its real POSIX helper."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.request

DEVICE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(DEVICE / 'ci'))
from d27_metal_source import adapt as qualify
from d27_metal_startup import adapt, adapt_frontend


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--compiler', default='c++')
    parser.add_argument('--source-only', action='store_true')
    args = parser.parse_args()
    if args.source:
        original = args.source.read_text()
    else:
        url = 'https://raw.githubusercontent.com/UniXNU/AdrenoMetal/243d63cf43305a85c8119b66b49cb7df4b30b019/NativeAdrenoMetalPlugin.mm'
        original = urllib.request.urlopen(url, timeout=30).read().decode()
        original = qualify(original)
    modified = adapt(original)
    # The non-render-server branch and all post-open work remain byte-identical.
    start = original.index('static id deviceForPort(unsigned port)')
    prefix = modified[:modified.index('static id deviceForPort(unsigned port)')]
    for line in ('#include "D27MetalStartup.h"\n', 'extern "C" const char *d27_metal_open_error();\n',
                 'extern "C" const char *d27_metal_open_stage();\n',
                 'extern "C" bool d27_metal_runtime_ready();\n'):
        prefix = prefix.replace(line, '')
    assert prefix == original[:start]
    tail = '        gpu->mark(0x6802);'
    assert original[original.index(tail):] == modified[modified.index(tail):]
    assert 'writeTask(' not in modified and 'patchFramebufferBranch(' not in modified
    assert 'access(candidates[i], W_OK)' not in modified[modified.index('static id deviceForPort(unsigned port)'):]
    for invalid in (modified, original.replace('static const unsigned order[] = {5, 4, 0, 1, 2, 3};', '')):
        try:
            adapt(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError('adapter accepted duplicate or drifted source')
    print('PASS pinned-source overlay/scope/drift checks', hashlib.sha256(modified.encode()).hexdigest())
    if args.source_only:
        print('POSIX helper execution NOT RUN (--source-only)')
        return
    with tempfile.TemporaryDirectory(prefix='d27-metal-') as temp:
        if args.source:
            frontend = adapt_frontend(args.source.with_name('NativeBridgeMetalFrontend.mm').read_text())
            # Execute the exact adapted entrance/terminal guards with opaque
            # stand-ins for handles. This checks a later call cannot restart
            # runtime initialization after a frontend refusal/exception.
            start = frontend.index('static thread_local std::string d27OpenError;')
            end = frontend.index(' gMissing=missing;gInFlight=', start)
            guard = frontend[start:end]
            harness = '''#include <string>
#include <cassert>
using id=void*;
using uint64_t=unsigned long;
#define nil nullptr
void *gDevice=nullptr,*gDeviceObject=nullptr;
int initializations=0;
''' + guard + '''
 ++initializations; return nullptr;
}
int main(){
 native_bridge_metal_open(nullptr,nullptr,0,nullptr);assert(initializations==1);
 gDevice=(void*)1;d27OpenStage="frontend-new-device";d27OpenError="allocation nil";
 for(int i=0;i<6;++i)assert(!native_bridge_metal_open(nullptr,nullptr,0,nullptr));
 assert(initializations==1);assert(d27_metal_runtime_ready());
 assert(d27OpenError=="allocation nil");assert(std::string(d27_metal_open_stage())=="frontend-new-device");
 gDeviceObject=(void*)2;assert(native_bridge_metal_open(nullptr,nullptr,0,nullptr)==gDeviceObject);
 assert(initializations==1);
}
'''
            fixture = Path(temp) / 'frontend-guard.cpp'
            fixture.write_text(harness)
            binary = Path(temp) / 'frontend-guard'
            subprocess.run([args.compiler, '-std=c++17', '-fsanitize=address,undefined', str(fixture), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True)
            print('PASS exact adapted frontend terminal guard: repeated calls preserve live handle/error/stage')
        exe = Path(temp) / 'startup-test'
        subprocess.run([args.compiler, '-std=c++17', '-pthread', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-I', str(DEVICE / 'ci'),
                        str(DEVICE / 'tests/d27_metal_startup_host.cpp'), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
        objc = Path(temp) / 'startup-exception-test'
        subprocess.run([args.compiler, '-std=c++17', '-pthread', '-Wall', '-Wextra', '-Werror',
                        '-fexceptions', '-fobjc-exceptions', '-I', str(DEVICE / 'ci'),
                        str(DEVICE / 'tests/d27_metal_startup_exception.mm'), '-lobjc', '-o', str(objc)], check=True)
        subprocess.run([str(objc)], check=True)
    print('PASS actual POSIX cache probe and optional environment lifetime')
    print('PASS actual Objective-C caught-exception environment restoration (GNU host runtime)')


if __name__ == '__main__':
    main()
