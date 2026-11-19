#!/usr/bin/env python3
"""ASan/UBSan exercise of the actual cached readSectors and original block verifier."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    text=a.source.read_text();start=text.index('IOReturn NativeVirtioBlock::readSectors(uint64_t sector, uint32_t bytes)')
    brace=text.index('{',start);depth=1;end=brace+1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    method=text[start:end]
    code=r'''
#include <cassert>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <vector>
#include <openssl/sha.h>
#include "D27VerifiedReadCache.h"
#include "verified_root.h"
using IOReturn=int;
constexpr int kIOReturnSuccess=0,kIOReturnBadArgument=1,kIOReturnNotPrivileged=2;
constexpr unsigned transferSize=65536;
uint64_t native_virtio_cache_hits=0,native_virtio_cache_misses=0,native_virtio_verified_blocks=0;
uint32_t native_virtio_integrity_failures=0;
int digest(const void *data,size_t bytes,uint8_t out[32]){return SHA256(static_cast<const unsigned char *>(data),bytes,out)?1:0;}
const vr_crypto vr_xnu_crypto={digest,nullptr};
void panic(const char *){assert(false);}
struct Memory {std::vector<unsigned char> bytes=std::vector<unsigned char>(65536);void *getBytesNoCopy(){return bytes.data();}};
struct NativeVirtioBlock {
 bool online=true;uint64_t capacity=64;unsigned char *verifiedSnapshot=nullptr;Memory transport;Memory *transferMemory=&transport;
 vr_view verified={};D27VerifiedReadCache readCache;unsigned reads=0,resets=0;bool fail=false;
 std::vector<unsigned char> disk=std::vector<unsigned char>(32768),snapshot=std::vector<unsigned char>(65536),cache=std::vector<unsigned char>(D27VerifiedReadCache::bytes),hashes=std::vector<unsigned char>(256);
 std::vector<uint64_t> tags=std::vector<uint64_t>(D27VerifiedReadCache::slots);
 NativeVirtioBlock(){
  for(size_t i=0;i<disk.size();++i)disk[i]=static_cast<unsigned char>(i*17+i/4096);
  verifiedSnapshot=snapshot.data();readCache.initialize(cache.data(),tags.data());
  for(size_t i=0;i<8;++i)assert(digest(disk.data()+4096*i,4096,hashes.data()+32*i)==1);
  verified.hashes=hashes.data();verified.block_count=8;verified.image_bytes=disk.size();
 }
 IOReturn readRawSectors(uint64_t sector,uint32_t bytes){++reads;if(fail)return 9;assert(sector*512+bytes<=disk.size());memcpy(transport.bytes.data(),disk.data()+sector*512,bytes);return 0;}
 bool reset(){++resets;online=false;return true;}
 IOReturn readSectors(uint64_t sector,uint32_t bytes);
};
''' + method + r'''
int main(){
 NativeVirtioBlock first;
 assert(first.readSectors(1,512)==0 && first.reads==1);
 assert(!memcmp(first.verifiedSnapshot,first.disk.data()+512,512));
 auto blocks=native_virtio_verified_blocks;
 assert(first.readSectors(1,512)==0 && first.reads==1 && native_virtio_verified_blocks>blocks);
 assert(!memcmp(first.verifiedSnapshot,first.disk.data()+512,512));
 first.cache[0]^=1;
 assert(first.readSectors(1,512)==kIOReturnNotPrivileged && first.resets==1 && !first.online);
 NativeVirtioBlock range;
 assert(range.readSectors(7,8192)==0 && !memcmp(range.verifiedSnapshot,range.disk.data()+7*512,8192));
 const auto before=range.reads;assert(range.readSectors(8,4096)==0 && range.reads==before);
 NativeVirtioBlock bad;bad.disk[0]^=1;assert(bad.readSectors(0,512)==kIOReturnNotPrivileged && bad.tags[0]==UINT64_MAX);
 NativeVirtioBlock failed;failed.fail=true;assert(failed.readSectors(0,512)==9 && failed.tags[0]==UINT64_MAX);
 NativeVirtioBlock disabled;disabled.readCache.initialize(nullptr,nullptr);
 assert(disabled.readSectors(0,512)==0 && disabled.readSectors(0,512)==0 && disabled.reads==2);
 assert(disabled.readSectors(64,512)==kIOReturnBadArgument);
 assert(disabled.readSectors(0,511)==kIOReturnBadArgument);
 D27VerifiedReadCache collision;std::vector<unsigned char> storage(collision.bytes),input(4096,42),output(4096);
 std::vector<uint64_t> identities(collision.slots);collision.initialize(storage.data(),identities.data());
 collision.storeVerified(0,4096,input.data());assert(collision.copy(0,4096,output.data()));
 collision.storeVerified(collision.slots,4096,input.data());assert(!collision.copy(0,4096,output.data()));
 assert(collision.copy(collision.slots,4096,output.data()));
 assert(!collision.copy(UINT64_MAX,4096,output.data()));
 puts("PASS actual readSectors: unaligned reads, cache hits rehashed, corrupted DMA and cached bytes refused, failed reads uncached, bounded collisions, allocation fallback");
}
'''
    cpp=a.out/'actual-verified-cache.cpp';cpp.write_text(code)
    kit=BASE/'sources/UniXNU/kits/VerifiedRoot'
    verifier=a.out/'verified_root.o'
    subprocess.run(['clang','-O1','-g','-fsanitize=address,undefined','-I',str(kit/'include'),
        '-c',str(kit/'src/verified_root.c'),'-o',str(verifier)],check=True)
    command=['clang++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
        '-fno-omit-frame-pointer','-I',str(a.source.parent),'-I',str(kit/'include'),str(cpp),str(verifier),
        '-lcrypto','-o',str(a.out/'actual-verified-cache')]
    subprocess.run(command,check=True)
    done=subprocess.run([str(a.out/'actual-verified-cache')],capture_output=True,text=True)
    (a.out/'execution.log').write_text(done.stdout+done.stderr)
    if done.returncode:raise RuntimeError(done.stdout+done.stderr)
    result=dict(source=str(a.source),source_sha256=hashlib.sha256(a.source.read_bytes()).hexdigest(),
        original_verifier_sha256=hashlib.sha256((kit/'src/verified_root.c').read_bytes()).hexdigest(),
        command=command,sanitizers=['address','undefined'],output=done.stdout,guest_runtime=False)
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(done.stdout,end='')


if __name__=='__main__':main()
