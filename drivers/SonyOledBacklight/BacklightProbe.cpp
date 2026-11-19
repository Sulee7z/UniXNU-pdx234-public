// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <IOKit/IOService.h>
#include <libkern/OSKextLib.h>
#include <mach/kmod.h>
#include <pexpert/pexpert.h>
#include "SonyOledBacklight.h"
extern kmod_info_t g_kernel_kmod_info;
extern "C" void sony_oled_static_init(void) __asm__("__GLOBAL__sub_I_SonyOledBacklight.cpp");
extern "C" void native_sony_oled_backlight_start(void);
extern "C" { volatile int32_t native_sony_oled_stats[24]; }

extern "C" void native_sony_oled_backlight_probe(void) {
    unsigned enabled=0;
    if(!PE_parse_boot_argn("backlight",&enabled,sizeof enabled) || enabled!=1)return;
    int32_t expected=0;
    if(!__atomic_compare_exchange_n(&native_sony_oled_stats[0],&expected,1,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return;
    void *handle=OSMetaClass::preModLoad(g_kernel_kmod_info.name);
    if(!handle){native_sony_oled_stats[0]=-5;native_sony_oled_stats[8]=kIOReturnNoMemory;return;}
    sony_oled_static_init();
    const OSReturn status=OSMetaClass::postModLoad(handle);
    if(status){native_sony_oled_stats[0]=-5;native_sony_oled_stats[8]=status;return;}
    native_sony_oled_backlight_start();
}
