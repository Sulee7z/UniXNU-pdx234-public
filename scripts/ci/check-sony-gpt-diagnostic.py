#!/usr/bin/env python3
"""Execute the actual staged probe10 body against captured Sony GPT/fault inputs."""
import argparse
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adapter', type=Path, required=True)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    text = (args.adapter / 'source/NativeUfs.cpp').read_text()
    begin = text.index('  if (probe == 10) {')
    end = text.index('  if (probe == 11) {', begin)
    body = text[begin:end]
    fixture = r'''
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/sha.h>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>
#include <cstdarg>
using IOReturn = unsigned;
static constexpr IOReturn kIOReturnSuccess = 0;
static std::vector<uint8_t> header, table;
static uint8_t gScratch[131072], capacity[8];
static unsigned reads, fault, diagnosticFailures;
static uint32_t le32(const uint8_t *p) { uint32_t v=0; for(unsigned i=0;i<4;++i)v|=uint32_t(p[i])<<(i*8); return v; }
static uint64_t le64(const uint8_t *p) {return le32(p)|uint64_t(le32(p+4))<<32;}
static uint32_t getBe32(const uint8_t *p) {return uint32_t(p[0])<<24|uint32_t(p[1])<<16|uint32_t(p[2])<<8|p[3];}
static void be32(uint8_t *p,uint32_t v) {for(unsigned i=0;i<4;++i)p[3-i]=uint8_t(v>>(i*8));}
static uint32_t rootCrc32(const uint8_t *p,size_t n,bool hdr=false) {
  uint32_t crc=~0U; for(size_t i=0;i<n;++i){crc^=hdr&&i>=16&&i<20?0:p[i];for(unsigned k=0;k<8;++k)crc=crc>>1^(0xedb88320U&(0U-(crc&1)));}return ~crc;
}
static bool hostBringUp(const char **why) {if(fault==1){*why="injected bringup";return false;}return true;}
static void rootDiagnosticFailure(const char *) {++diagnosticFailures;}
static IOReturn hostScsi(uint8_t lun,const uint8_t *cdb,unsigned n,bool read,unsigned bytes,unsigned,uint32_t *scsi) {
  assert(lun==0&&n==10&&cdb[0]==0x25&&read&&bytes==8);*scsi=fault==2?2:0;return fault==2?1:0;
}
struct Slot {uint8_t *data;};
static Slot ufsSlot(unsigned index) {assert(index==0);return {capacity};}
static IOReturn hostRead4k(uint8_t lun,uint64_t lba,unsigned blocks,void *dst) {
  assert(lun==0);++reads;
  if(lba==1&&blocks==1){if(fault==3)return 1;memcpy(dst,header.data(),4096);if(fault==7&&reads==3)static_cast<uint8_t *>(dst)[100]^=1;}
  else if(lba==2&&blocks==4){if(fault==4)return 1;memcpy(dst,table.data(),16384);}
  else {assert(false);}return 0;
}
[[noreturn]] static void panic(const char *fmt,...) {
  char out[4096];va_list a;va_start(a,fmt);vsnprintf(out,sizeof(out),fmt,a);va_end(a);throw std::runtime_error(out);
}
static void diagnostic() {unsigned probe=10;
// BODY
}
static std::vector<uint8_t> input(const char *p){std::ifstream s(p,std::ios::binary);assert(s.good());return {std::istreambuf_iterator<char>(s),{}};}
int main(int argc,char **argv) {
 assert(argc==3);const auto originalHeader=input(argv[1]),originalTable=input(argv[2]);assert(originalHeader.size()==4096&&originalTable.size()==16384);
 unsigned count=0;
  for(unsigned test=0;test<50;++test){
  header=originalHeader;table=originalTable;fault=test;reads=diagnosticFailures=0;be32(capacity,62461951);be32(capacity+4,4096);
  if(test==5)header[16]^=1;
  if(test==6)table[200]^=1;
  if(test==8)be32(capacity+4,512);
   if(test==9){header[100]^=1;uint32_t crc=rootCrc32(header.data(),92,true);for(unsigned i=0;i<4;++i)header[16+i]=uint8_t(crc>>(i*8));}
   if(test>=10&&test<42){
    const unsigned part=test<26?67:82, value=(test-10)%16;
    table[part*128+54]=uint8_t((table[part*128+54]&~0x78U)|(value<<3));
   }
   if(test==42)table[67*128+54]^=1; // priority remains identity-bound
   if(test==43)table[67*128+54]^=0x80; // unbootable remains identity-bound
   if(test==44)table[67*128+32]^=1; // partition range
   if(test==45)table[67*128+16]^=1; // unique GUID
   if(test==46)table[67*128+56]^=1; // partition name
   if(test==47)table[67*128+48]^=0x10; // unrelated attribute
   if(test==48)table[66*128+54]^=8; // another partition's attribute
   if(test==49)header[56]^=1; // disk GUID
   if(test>=10){
    const uint32_t tc=rootCrc32(table.data(),97*128);
    for(unsigned i=0;i<4;++i)header[88+i]=uint8_t(tc>>(i*8));
    const uint32_t hc=rootCrc32(header.data(),92,true);
    for(unsigned i=0;i<4;++i)header[16+i]=uint8_t(hc>>(i*8));
   }
  try {diagnostic();assert(false);}catch(const std::runtime_error &e){
   std::string msg=e.what();
   const char *expected[]={"GPT READ PASS","bring-up failed","capacity command failed","header read failed","table read failed","header rejected","table CRC rejected","repeated header differs","capacity differs","valid GPT differs"};
    const char *want=test<10?expected[test]:test<42?"GPT READ PASS":"valid GPT differs";
    if(msg.find(want)==std::string::npos){fprintf(stderr,"test%u: %s\n",test,e.what());return 1;}
    if(test==0||(test>=10&&test<42)) {assert(reads==3);}
   if(test==1||test==2) {assert(diagnosticFailures==1);}
  }++count;
 }
 printf("PASS: actual probe10 body, %u capacity/header/table/repeated-read/identity and failure-path cases; captured Sony GPT; no device I/O\n",count);
}
'''.replace('// BODY', body)
    source = args.out / 'SonyGptDiagnostic.cpp'
    source.write_text(fixture)
    binary = args.out / 'SonyGptDiagnostic'
    command = ['g++', '-std=c++17', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
               '-g', str(source), '-lcrypto', '-o', str(binary)]
    r = subprocess.run(command, capture_output=True, text=True)
    (args.out / 'compile.log').write_text(r.stdout + r.stderr)
    r.check_returncode()
    r = subprocess.run([str(binary), str(args.capture / 'gpt-header.bin'),
                        str(args.capture / 'gpt-table.bin')], capture_output=True, text=True, timeout=30)
    (args.out / 'run.log').write_text(r.stdout + r.stderr)
    print(r.stdout + r.stderr)
    r.check_returncode()
    (args.out / 'report.json').write_text(json.dumps(dict(actual_staged_body=True, cases=50,
        boot_slot_retry_success_variants=32, identity_change_refusals=8,
        sanitizers=['address', 'undefined'], captured_gpt=True, device_io=False, passed=True), indent=2) + '\n')


if __name__ == '__main__':
    main()
