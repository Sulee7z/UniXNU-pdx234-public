// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "sony_buttons_startup_iokit.h"
#include "SonyButtonsSpmi.h"
extern "C" { volatile int32_t native_sony_buttons_stats[16]; }
kmod_info_t g_kernel_kmod_info = {"kernel"};
extern "C" void native_sony_buttons_static_init() __asm__("__GLOBAL__sub_I_SonyButtonsHid.cpp");
extern "C" void native_sony_buttons_static_init() {}
extern "C" IOService *native_sony_buttons_allocate(const SonyButtonsReadOps *ops, int qualification) {
    ++buttons_test::allocations; buttons_test::allocationQualification = qualification;
    buttons_test::allocationMask = ops->enabled_mask;
    buttons_test::allocationContext = ops->context;
    assert((ops->enabled_mask != 0) == (ops->read8 != nullptr));
    return buttons_test::dummyStartupDevice = new IOService;
}
#include "SonyButtons.cpp"
int main(int argc, char **argv) {
    using namespace buttons_test;
    assert(argc == 2); const std::string mode = argv[1];
    native_sony_buttons_start(); assert(!starts && !coreMaps);
    bootargs["sony-buttons"] = 0; native_sony_buttons_start(); assert(!starts && !coreMaps);
    bootargs["sony-buttons"] = 1;
    if (mode != "neutral") bootargs["sony-buttons-read-qualified"] = 1;
    if (mode == "bad-apid") bootargs["sony-buttons-pon-apid"] = 1024;
    if (mode == "read" || mode == "foreign") bootargs["sony-buttons-pon-apid"] = 560;
    native_sony_buttons_start(); assert(starts == 1 && deallocates == 1 && scheduled);
    native_sony_buttons_start(); assert(starts == 1 && !coreMaps && !observerMaps);
    core[0] = 0x70000001; core[1] = 768;
    core[(0x2000 + 4*560)/4] = (1u<<24) | (0x13u<<8);
    owner[560] = mode == "foreign" ? 1 : 0;
    scheduled(nullptr, 0);
    assert(allocations == 1);
    if (mode == "read") {
        assert(allocationQualification == 0 && allocationMask == 6 && observerMaps == 1);
    } else {
        assert(allocationQualification == (mode == "bad-apid" || mode == "missing-apid" ? SonyButtonsBadArgument : SonyButtonsNotOwned));
        assert(!allocationMask && !observerMaps);
        if (mode != "foreign") assert(!coreMaps && !ownerMaps);
    }
    assert(observer[0] == 0 && observer[560*0x20/4] == 0); // prepare never reads PMIC
    // Native lifetime is built-in; the host model explicitly frees it at exit.
    dummyStartupDevice->release(); dummyStartupDevice = nullptr;
    delete static_cast<SonyButtonsSpmi *>(allocationContext);
    printf("PASS actual startup %s: one-shot HID registration, qualification=%d mask=%x coremaps=%u observermaps=%u, no PMIC command\n",
           mode.c_str(), allocationQualification, allocationMask, coreMaps, observerMaps);
}
