// SPDX-License-Identifier: BSD-2-Clause-Patent
// QEMU-only late registration. No Sony UFS controller or writable media.
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOCatalogue.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOService.h>
#include <IOKit/storage/IOBlockStorageDevice.h>
#include <libkern/OSKextLib.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSString.h>
#include <mach/kmod.h>
#include <pexpert/pexpert.h>

static_assert(sizeof(IOBlockStorageDevice) == 0x90, "D27 block class layout changed");
extern kmod_info_t g_kernel_kmod_info;
extern "C" void qemu_storage_base_init(void) __asm__("__GLOBAL__sub_I_IOBlockStorageDevice.cpp");
extern "C" void qemu_storage_transport_init(void) __asm__("__GLOBAL__sub_I_NativeVirtioBlock.cpp");
#if defined(D27_QEMU_DATA) && D27_QEMU_DATA
extern "C" void qemu_storage_ram_init(void) __asm__("__GLOBAL__sub_I_NativeRamBlock.cpp");
#endif
#if defined(SONY_UFS_TEST) && SONY_UFS_TEST
extern "C" bool native_sony_ufs_test_start(void);
#endif
#if defined(NATIVE_VERIFIED_POLICY_HANDOFF) && NATIVE_VERIFIED_POLICY_HANDOFF
extern "C" bool native_source_root_policies_load(void);
#endif
extern "C" {
volatile uint32_t native_qemu_storage_state = 0;
}

static const OSMetaClass *storageParent;

#if defined(SONY_UFS_TEST) && SONY_UFS_TEST
extern "C" void native_source_storage_set_parent(const OSMetaClass *parent)
{
    if (storageParent || !parent) panic("SourceStorage: invalid parent transition");
    storageParent = parent;
}
#endif

// The public class spelling stays unchanged for compiler-authored PAC types.
extern "C" const OSMetaClass *native_source_storage_parent(void)
{
    if (!storageParent) panic("QemuSourceStorage: original class unavailable");
    return storageParent;
}

static bool qemu_platform()
{
    IORegistryEntry *root = IORegistryEntry::fromPath("/", gIODTPlane);
    IORegistryEntry *defaults = IORegistryEntry::fromPath("/defaults", gIODTPlane);
    OSData *compatible = root ? OSDynamicCast(OSData, root->getProperty("compatible")) : nullptr;
    OSData *vmm = defaults ? OSDynamicCast(OSData, defaults->getProperty("vmm-present")) : nullptr;
    uint32_t value = 0;
    if (vmm && vmm->getLength() == sizeof(value)) memcpy(&value, vmm->getBytesNoCopy(), sizeof(value));
    const char expected[] = "linux,dummy-virt";
    bool valid = value == 1 && compatible && compatible->getLength() == sizeof(expected) &&
        memcmp(compatible->getBytesNoCopy(), expected, sizeof(expected)) == 0;
    OSSafeReleaseNULL(defaults);
    OSSafeReleaseNULL(root);
    return valid;
}

extern "C" void native_qemu_storage_start(void)
{
#if defined(SONY_UFS_TEST) && SONY_UFS_TEST
    if (native_sony_ufs_test_start()) return;
#endif
    uint32_t enabled = 0;
    if (!PE_parse_boot_argn("native-qemu-storage", &enabled, sizeof(enabled)) || enabled != 1 ||
        native_qemu_storage_state != 0) return;
    if (!qemu_platform()) panic("QemuSourceStorage: QEMU-only platform guard refused");
    native_qemu_storage_state = 1;
    OSReturn status = OSKextLoadKextWithIdentifier("com.apple.iokit.IOStorageFamily");
    if (status != kOSReturnSuccess) panic("QemuSourceStorage: IOStorageFamily load failed %x", status);
    const OSSymbol *name = OSSymbol::withCString("IOBlockStorageDevice");
    storageParent = name ? OSMetaClass::getMetaClassWithName(name) : nullptr;
    OSSafeReleaseNULL(name);
    if (!storageParent || storageParent->getClassSize() != sizeof(IOBlockStorageDevice))
        panic("QemuSourceStorage: original class layout differs from source");
    status = OSKextLoadKextWithIdentifier("com.apple.filesystems.apfs");
    if (status != kOSReturnSuccess) panic("QemuSourceStorage: APFS load failed %x", status);
    native_qemu_storage_state = 2;
#if defined(NATIVE_VERIFIED_POLICY_HANDOFF) && NATIVE_VERIFIED_POLICY_HANDOFF
    if (!native_source_root_policies_load())
        panic("QemuSourceStorage: target owner policy authentication failed");
#endif

    // Retire a possible early built-in personality before its late class exists.
    // There must be one owner per actual MMIO device, never two queue/reset owners.
    OSDictionary *personality = OSDictionary::withCapacity(3);
    OSString *className = OSString::withCString("NativeVirtioBlock");
    bool selected = personality && className && personality->setObject("IOClass", className);
    OSSafeReleaseNULL(className);
    if (!selected || !gIOCatalogue || !gIOCatalogue->removeDrivers(personality, false))
        panic("QemuSourceStorage: cannot retire the early transport personality");
    void *handle = OSMetaClass::preModLoad(g_kernel_kmod_info.name);
    if (!handle) panic("QemuSourceStorage: class registration unavailable");
    qemu_storage_base_init();
    qemu_storage_transport_init();
#if defined(D27_QEMU_DATA) && D27_QEMU_DATA
    qemu_storage_ram_init();
#endif
    status = OSMetaClass::postModLoad(handle);
    if (status != kOSReturnSuccess) panic("QemuSourceStorage: class registration failed %x", status);
    native_qemu_storage_state = 3;

    OSString *provider = OSString::withCString("IOPlatformDevice");
    OSNumber *score = OSNumber::withNumber(1000, 32);
    bool configured = provider && score && personality->setObject("IOProviderClass", provider) &&
        personality->setObject("IOProbeScore", score);
    OSArray *drivers = configured ? OSArray::withCapacity(1) : nullptr;
    if (!drivers || !drivers->setObject(personality) || !gIOCatalogue->addDrivers(drivers, true))
        panic("QemuSourceStorage: cannot request transport matching");
    OSSafeReleaseNULL(drivers);
    OSSafeReleaseNULL(score);
    OSSafeReleaseNULL(provider);
    OSSafeReleaseNULL(personality);
    native_qemu_storage_state = 4;
#if defined(D27_QEMU_DATA) && D27_QEMU_DATA
    IORegistryEntry *map = IORegistryEntry::fromPath("/chosen/memory-map", gIODTPlane);
    bool seed = map && (map->getProperty("PackedRAMDisk") || map->getProperty("RAMDisk"));
    OSSafeReleaseNULL(map);
    if (seed) {
        OSDictionary *matching = IOService::serviceMatching("IOPlatformExpertDevice");
        IOService *parent = matching ? IOService::waitForMatchingService(matching, 5000000000ULL) : nullptr;
        IOService *ram = OSDynamicCast(IOService, OSMetaClass::allocClassWithName("NativeRamBlock"));
        if (!parent || !ram || !ram->init() || !ram->attach(parent) || !ram->start(parent))
            panic("QemuSourceStorage: Data RAM disk start failed");
        printf("QemuSourceStorage: original source RAM Data disk started\n");
    }
#endif
    printf("QemuSourceStorage: transport matching requested; root mount not yet observed\n");
}
