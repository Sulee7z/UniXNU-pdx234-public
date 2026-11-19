// SPDX-License-Identifier: BSD-2-Clause-Patent
// Start the real source driver late; diagnostic modes never open a media write window.
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <IOKit/storage/IOBlockStorageDevice.h>
#include <libkern/OSKextLib.h>
#include <libkern/c++/OSData.h>
#include <mach/kmod.h>
#include <pexpert/pexpert.h>

extern kmod_info_t g_kernel_kmod_info;
extern "C" void sony_base_init(void) __asm__("__GLOBAL__sub_I_IOBlockStorageDevice.cpp");
extern "C" void sony_ufs_init(void) __asm__("__GLOBAL__sub_I_NativeUfs.cpp");
extern "C" IOService *native_ufs_source_create(void);
extern "C" void native_source_storage_set_parent(const OSMetaClass *);
extern "C" {
volatile uint32_t native_sony_ufs_test_stage = 0;
volatile uint64_t native_sony_ufs_progress_observations = 0;
void boot_progress_poll(void)
{
    __atomic_fetch_add(&native_sony_ufs_progress_observations, 1, __ATOMIC_RELAXED);
}
}

extern "C" bool native_sony_ufs_test_start(void)
{
    unsigned enabled = 0;
    if (!PE_parse_boot_argn("sony-ufs-test", &enabled, sizeof(enabled)) || enabled != 1) return false;
    unsigned displayTest = 0;
    if (PE_parse_boot_argn("sony-ufs-display-selftest", &displayTest, sizeof(displayTest)) && displayTest == 1) {
        char *heap = static_cast<char *>(IOMallocData(256));
        if (!heap) panic("SonyUfsTest: diagnostic heap allocation failed");
        snprintf(heap, 256, "HEAP STRING READ PASS\nSMMU reason: diagnostic fixture\n"
                 "ID0=40000080 ID1=60000046 ID2=00005111\n"
                 "DMA=880100000 bytes=22000\nNo Sony MMIO. No disk writes.");
        panic("%s", heap);
    }
    if (native_sony_ufs_test_stage) panic("SonyUfsTest: duplicate initialization");
    IORegistryEntry *root = IORegistryEntry::fromPath("/", gIODTPlane);
    OSData *identity = root ? OSDynamicCast(OSData, root->getProperty("compatible")) : nullptr;
    const char sony[] = "somc,pdx234-generic";
    const bool match = identity && identity->getLength() >= sizeof(sony) &&
        !memcmp(identity->getBytesNoCopy(), sony, sizeof(sony));
    OSSafeReleaseNULL(root);
    if (!match) panic("SonyUfsTest: Sony platform guard refused");
    unsigned probe = 0, rootMode = 0, store = 0, log = 0;
    PE_parse_boot_argn("native-ufs-probe", &probe, sizeof(probe));
    PE_parse_boot_argn("native-ufs-root", &rootMode, sizeof(rootMode));
    PE_parse_boot_argn("sheng-data-persist", &store, sizeof(store));
    PE_parse_boot_argn("sheng-log", &log, sizeof(log));
    if ((probe != 2 && probe != 10) || rootMode || store || log)
        panic("SonyUfsTest: requires diagnostic 2/10 and disabled root, Data and log writes");
    native_sony_ufs_test_stage = 1;
    OSReturn status = OSKextLoadKextWithIdentifier("com.apple.iokit.IOStorageFamily");
    if (status != kOSReturnSuccess) panic("SonyUfsTest: storage load failed %x", status);
    const OSSymbol *name = OSSymbol::withCString("IOBlockStorageDevice");
    const OSMetaClass *parent = name ? OSMetaClass::getMetaClassWithName(name) : nullptr;
    OSSafeReleaseNULL(name);
    if (!parent || parent->getClassSize() != sizeof(IOBlockStorageDevice))
        panic("SonyUfsTest: D27 storage class size differs");
    native_source_storage_set_parent(parent);
    void *handle = OSMetaClass::preModLoad(g_kernel_kmod_info.name);
    if (!handle) panic("SonyUfsTest: cannot begin registration");
    sony_base_init();
    sony_ufs_init();
    status = OSMetaClass::postModLoad(handle);
    if (status != kOSReturnSuccess) panic("SonyUfsTest: registration failed %x", status);
    native_sony_ufs_test_stage = 2;
    OSDictionary *matching = IOService::serviceMatching("IOPlatformExpertDevice");
    IOService *provider = matching ? IOService::waitForMatchingService(matching, 5000000000ULL) : nullptr;
    IOService *driver = native_ufs_source_create();
    if (!provider || !driver || !driver->init() || !driver->attach(provider))
        panic("SonyUfsTest: provider/driver attachment failed");
    native_sony_ufs_test_stage = 3;
    const bool started = driver->start(provider);
    panic("SonyUfsTest: diagnostic unexpectedly returned %u", started);
}
