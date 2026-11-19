// SPDX-License-Identifier: BSD-2-Clause-Patent
#if defined(SONY_BUTTONS_HOST_TEST)
#include "sony_buttons_startup_iokit.h"
#else
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <libkern/c++/OSSymbol.h>
#include <libkern/OSKextLib.h>
#include <kern/thread.h>
#include <mach/kmod.h>
#include <pexpert/pexpert.h>
#endif
#include "SonyButtonsSpmi.h"

extern kmod_info_t g_kernel_kmod_info;
extern "C" {
void native_sony_buttons_static_init(void) __asm__("__GLOBAL__sub_I_SonyButtonsHid.cpp");
IOService *native_sony_buttons_allocate(const SonyButtonsReadOps *, int qualification);
extern volatile int32_t native_sony_buttons_stats[16];
}

namespace {
uint32_t gPon = ~0u, gGpio = ~0u;
int gQualification = SonyButtonsNotOwned;
void failure(int stage, int error) {
    native_sony_buttons_stats[0] = -stage;
    native_sony_buttons_stats[11] = error;
    IOLog("[sony-buttons] refused stage=%d error=%d pon=%u gpio=%u\n", stage, error, gPon, gGpio);
}
void startupWorker() {
    SonyButtonsSpmi *transport = nullptr;
    if (!gQualification) {
        transport = new SonyButtonsSpmi;
        gQualification = transport ? transport->prepare(gPon, gGpio) : -12;
        if (gQualification) { delete transport; transport = nullptr; }
    }
    native_sony_buttons_stats[13] = gQualification;
    if (gQualification)
        IOLog("[sony-buttons] hardware qualification failed error=%d pon=%u gpio=%u; registering neutral HID, no observer reads\n",
            gQualification, gPon, gGpio);
    int result = OSKextLoadKextWithIdentifier("com.apple.iokit.IOHIDFamily");
    if (result) { failure(5, result); delete transport; return; }
    const OSSymbol *name = OSSymbol::withCString("IOHIDDevice");
    const OSMetaClass *meta = name ? OSMetaClass::getMetaClassWithName(name) : nullptr;
    const bool valid = meta && meta->getClassSize() == 208;
    OSSafeReleaseNULL(name);
    if (!valid) { failure(5, -208); delete transport; return; }
    void *handle = OSMetaClass::preModLoad(g_kernel_kmod_info.name);
    if (!handle) { failure(5, -3); delete transport; return; }
    native_sony_buttons_static_init();
    result = OSMetaClass::postModLoad(handle);
    if (result) { failure(5, result); delete transport; return; }
    OSDictionary *matching = IOService::serviceMatching("IOHIDResource");
    IOService *parent = matching ? IOService::waitForMatchingService(matching, 5000000000ULL) : nullptr;
    OSSafeReleaseNULL(matching);
    SonyButtonsReadOps ops = {};
    if (transport) ops = {transport, SonyButtonsSpmi::read, transport->enabledMask()};
    IOService *device = native_sony_buttons_allocate(&ops, gQualification);
    bool attached = false;
    if (!parent || !device || !device->init() || !(attached = device->attach(parent)) || !device->start(parent)) {
        if (attached) device->detach(parent);
        OSSafeReleaseNULL(device); OSSafeReleaseNULL(parent); delete transport; failure(5, -5); return;
    }
    OSSafeReleaseNULL(parent);
    IOLog("[sony-buttons] HID started hardware=%u qualification=%d pon=%u gpio=%u mask=%x; %s\n",
        transport != nullptr, gQualification, gPon, gGpio, ops.enabled_mask,
        transport ? "inherited observer only" : "neutral registration only / no observer transactions");
    // Built-in lifetime: device/provider attachment and read-only mappings remain
    // retained for this boot. No unload, power/reset or interrupt ownership API.
}
void startup(void *, wait_result_t) { startupWorker(); thread_terminate(current_thread()); }
}

extern "C" void native_sony_buttons_start(void) {
    unsigned enabled = 0, qualified = 0;
    if (!PE_parse_boot_argn("sony-buttons", &enabled, sizeof(enabled)) || enabled != 1) return;
    static bool started = false;
    if (__atomic_exchange_n(&started, true, __ATOMIC_ACQ_REL)) return;
    // Source-qualified experimental opt-in, not a claim of a previous completed
    // XNU read. Same-boot metadata gates the FIRST observer read and each sample.
    // Without it even controller MMIO mappings are not made.
    if (PE_parse_boot_argn("sony-buttons-read-qualified", &qualified, sizeof(qualified)) && qualified == 1) {
        (void)PE_parse_boot_argn("sony-buttons-pon-apid", &gPon, sizeof(gPon));
        (void)PE_parse_boot_argn("sony-buttons-gpio-apid", &gGpio, sizeof(gGpio));
        gQualification = (gPon == ~0u && gGpio == ~0u) || (gPon != ~0u && gPon >= 1024) ||
                         (gGpio != ~0u && gGpio >= 1024) ? SonyButtonsBadArgument : 0;
    }
    native_sony_buttons_stats[0] = 1;
    native_sony_buttons_stats[13] = gQualification;
    native_sony_buttons_stats[14] = (int32_t)gPon;
    native_sony_buttons_stats[15] = (int32_t)gGpio;
    thread_t thread = nullptr;
    const kern_return_t result = kernel_thread_start(startup, nullptr, &thread);
    if (result == KERN_SUCCESS) thread_deallocate(thread);
    else failure(2, (int)result);
}
