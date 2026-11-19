// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <cassert>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
using id=void *;using SEL=void *;using Method=void *;using IMP=bool (*)(id,SEL,long long);
constexpr uint32_t MH_MAGIC_64=0xfeedfacf,CPU_TYPE_ARM64=0x100000c,CPU_SUBTYPE_ARM64E=2,LC_UUID=0x1b;
constexpr int RTLD_NOW=2,RTLD_LOCAL=4;
struct mach_header_64 {uint32_t magic,cputype,cpusubtype,filetype,ncmds,sizeofcmds,flags,reserved;};
struct load_command {uint32_t cmd,cmdsize;};
struct uuid_command {uint32_t cmd,cmdsize;unsigned char uuid[16];};
struct Fixture {mach_header_64 header;uuid_command uuid;} fixture;
static const char *program="backboardd",*types="B24@0:8q16";
static bool library=true,methodExists=true;static unsigned replacements,args=3,calls;static long long forwarded;
static IMP installed;
static const char *getprogname(){return program;}
static void *dlopen(const char *,int){return library?&fixture:nullptr;}
static uint32_t _dyld_image_count(){return 1;}
static const char *_dyld_get_image_name(uint32_t){return "/System/Library/PrivateFrameworks/CoreBrightness.framework/CoreBrightness";}
static const mach_header_64 *_dyld_get_image_header(uint32_t){return &fixture.header;}
static void *objc_getClass(const char *){return &fixture;}
static SEL sel_registerName(const char *){return &fixture;}
static Method class_getInstanceMethod(void *,SEL){return methodExists?&fixture:nullptr;}
static const char *method_getTypeEncoding(Method){return types;}
static unsigned method_getNumberOfArguments(Method){return args;}
static bool original(id,SEL,long long mode){++calls;forwarded=mode;return mode==1;}
static IMP method_setImplementation(Method,IMP replacement){++replacements;installed=replacement;return original;}
#define D69_BACKLIGHT_HOST 1
#include "../drivers/SonyOledBacklight/platform069/BacklightMode069.m"
static void reset(){
    fixture={{MH_MAGIC_64,CPU_TYPE_ARM64,0x80000002,6,1,sizeof(uuid_command),0,0},{LC_UUID,sizeof(uuid_command),{}}};
    memcpy(fixture.uuid.uuid,d69FrameworkUuid,16);program="backboardd";types="B24@0:8q16";args=3;
    library=methodExists=true;replacements=calls=0;installed=nullptr;
}
int main(){
    reset();d69BacklightStart();assert(replacements==1&&installed);
    for(long long mode:{0ll,1ll,2ll,3ll,4ll,0x100000003ll}){
        const bool result=installed(nullptr,nullptr,mode);assert(forwarded==(mode==3?1:mode));assert(result==(forwarded==1));
    }
    assert(calls==6);
    for(unsigned i=0;i<16;++i){reset();fixture.uuid.uuid[i]^=1;d69BacklightStart();assert(!replacements);}
    for(const char *bad:{"v24@0:8q16","B24@0:8Q16","B20@0:8i16","B24@0:8l16","B24@0:8q16junk",""}){
        reset();types=bad;d69BacklightStart();assert(!replacements);
    }
    for(const char *other:{"installd","SpringBoard","backboardd-copy"}){reset();program=other;d69BacklightStart();assert(!replacements);}
    reset();library=false;d69BacklightStart();assert(!replacements);
    reset();methodExists=false;d69BacklightStart();assert(!replacements);
    reset();args=4;d69BacklightStart();assert(!replacements);
    reset();fixture.uuid.cmdsize=0;d69BacklightStart();assert(!replacements);
    reset();fixture.header.ncmds=2;d69BacklightStart();assert(!replacements);
    reset();fixture.header.cpusubtype=0;d69BacklightStart();assert(!replacements);
    puts("PASS actual brightness-only constructor: exact24A446 UUID/fullABI/process/3to1-only/64bit/rejections; host-only");
}
