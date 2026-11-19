// SPDX-License-Identifier: GPL-3.0-or-later
// Brightness-only derivative of official563595ab scripts/appsync/BacklightMode.m.
// No installation, signature-validation, MobileGestalt or user-trust hooks.
#ifndef D69_BACKLIGHT_HOST
#include <objc/runtime.h>
#include <stdbool.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

static const char d69Framework[]="/System/Library/PrivateFrameworks/CoreBrightness.framework/CoreBrightness";
static const unsigned char d69FrameworkUuid[16]={0xb9,0x83,0xd2,0x78,0x44,0x58,0x31,0x1d,0x93,0xde,0x08,0x1e,0x4c,0x75,0xf9,0x86};
static bool (*d69OriginalInit)(id,SEL,long long);

static bool d69InitBLControl(id object,SEL selector,long long mode){
    return d69OriginalInit(object,selector,mode==3?1:mode);
}

static bool d69ImageMatches(void){
    for(uint32_t i=0;i<_dyld_image_count();++i){
        const char *name=_dyld_get_image_name(i);
        if(!name||strcmp(name,d69Framework))continue;
        const struct mach_header_64 *header=(const struct mach_header_64 *)_dyld_get_image_header(i);
        if(!header||header->magic!=MH_MAGIC_64||header->cputype!=CPU_TYPE_ARM64||
           (header->cpusubtype&0x00ffffff)!=CPU_SUBTYPE_ARM64E||header->sizeofcmds>1024*1024)return false;
        const unsigned char *cursor=(const unsigned char *)(header+1),*end=cursor+header->sizeofcmds;
        unsigned matches=0;
        for(uint32_t c=0;c<header->ncmds;++c){
            if((size_t)(end-cursor)<sizeof(struct load_command))return false;
            const struct load_command *command=(const struct load_command *)cursor;
            if(command->cmdsize<sizeof(*command)||command->cmdsize%8||(size_t)(end-cursor)<command->cmdsize)return false;
            if(command->cmd==LC_UUID){
                if(command->cmdsize!=sizeof(struct uuid_command)||
                   memcmp(((const struct uuid_command *)command)->uuid,d69FrameworkUuid,16))return false;
                ++matches;
            }
            cursor+=command->cmdsize;
        }
        return cursor==end&&matches==1;
    }
    return false;
}

#ifndef D69_BACKLIGHT_HOST
__attribute__((constructor))
#endif
static void d69BacklightStart(void){
    if(strcmp(getprogname(),"backboardd"))return;
    if(!dlopen(d69Framework,RTLD_NOW|RTLD_LOCAL)||!d69ImageMatches()){
        fprintf(stderr,"[sony069-brightness] CoreBrightness24A446 UUID mismatch; inactive\n");return;
    }
    Method method=class_getInstanceMethod(objc_getClass("BrightnessSystemInternal"),sel_registerName("initBLControl:"));
    const char *encoding=method?method_getTypeEncoding(method):NULL;
    // Entire original D27 signature, including BOOL return and64-bit mode.
    if(!method||!encoding||strcmp(encoding,"B24@0:8q16")||method_getNumberOfArguments(method)!=3){
        fprintf(stderr,"[sony069-brightness] initBLControl24A446 ABI mismatch; inactive\n");return;
    }
    d69OriginalInit=(bool (*)(id,SEL,long long))method_setImplementation(method,(IMP)d69InitBLControl);
    fprintf(stderr,"[sony069-brightness] physical brightness control selected;24A446 brightness-only\n");
}
