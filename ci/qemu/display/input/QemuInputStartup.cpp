// SPDX-License-Identifier: BSD-2-Clause-Patent
// Current D27 virtual keyboard/digitizer; actual reports use the original HID family.
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSSymbol.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSIterator.h>
#include <libkern/c++/OSData.h>
#include <libkern/OSKextLib.h>
#include <mach/kmod.h>
#include <pexpert/pexpert.h>

extern kmod_info_t g_kernel_kmod_info;
extern "C" {
void native_qemu_hid_static_init(void) __asm__("__GLOBAL__sub_I_NativeHidInput.cpp");
IOService *native_hid_input_allocate(void);
void native_virtio_input_probe(void);
volatile uint32_t native_hid_stage, native_hid_input_command;
volatile int native_hid_load_status=-1, native_hid_input_meta_status=-1;
volatile uint64_t native_hid_input_object;
volatile uint32_t native_hid_input_events[8];
volatile int native_hid_input_results[8]={-1,-1,-1,-1,-1,-1,-1,-1};
volatile uint64_t *native_touch_report_ring;
volatile uint32_t native_touch_report_count;

void native_hid_input_observed(unsigned event,int result) {
    if(event<8){native_hid_input_events[event]=native_hid_input_events[event]+1;native_hid_input_results[event]=result;}
}
bool native_hid_input_requested(void) {
    return __atomic_exchange_n(&native_hid_input_command,0,__ATOMIC_ACQ_REL)==1;
}
}

namespace {
IORegistryEntry *eventDriver(IORegistryEntry *parent,unsigned depth) {
    if(!depth)return nullptr;
    OSIterator *iterator=parent->getChildIterator(gIOServicePlane);
    if(!iterator)return nullptr;
    IORegistryEntry *found=nullptr;
    while(OSObject *object=iterator->getNextObject()) {
        IORegistryEntry *entry=OSDynamicCast(IORegistryEntry,object);
        if(!entry)continue;
        if(entry->metaCast("IOHIDEventDriver")){found=entry;found->retain();break;}
        if((found=eventDriver(entry,depth-1)))break;
    }
    iterator->release();return found;
}
}

extern "C" void native_hid_live_checkpoint(IOService *device) {
    static IORegistryEntry *publishedFor;
    IORegistryEntry *driver=eventDriver(device,4);
    if(!driver)return;
    // The keyboard collection matches the generic D27 event driver. The same
    // owned device also carries the digitizer collection. Publish its actual
    // builtin touch capability to the event service consumed by backboardd.
    if(driver!=publishedFor) {
        driver->setProperty("Built-In",kOSBooleanTrue);
        driver->setProperty("DisplayIntegrated",kOSBooleanTrue);
        driver->setProperty("PrimaryUsagePage",0x0dULL,32);
        driver->setProperty("PrimaryUsage",4ULL,32);
        if(IORegistryEntry *interface=driver->getParentEntry(gIOServicePlane)) {
            interface->setProperty("Built-In",kOSBooleanTrue);
            interface->setProperty("DisplayIntegrated",kOSBooleanTrue);
            interface->setProperty("PrimaryUsagePage",0x0dULL,32);
            interface->setProperty("PrimaryUsage",4ULL,32);
        }
        if(publishedFor)publishedFor->release();
        publishedFor=driver;driver->retain();
    }
    driver->release();
}

extern "C" void native_qemu_input_start(void) {
    unsigned enabled=0;
    if(!PE_parse_boot_argn("qemu-input",&enabled,sizeof(enabled)) || enabled!=1 || native_hid_stage)return;
    IORegistryEntry *root=IORegistryEntry::fromPath("/",gIODTPlane);
    OSData *compatible=root?OSDynamicCast(OSData,root->getProperty("compatible")):nullptr;
    const char expected[]="linux,dummy-virt";
    bool valid=compatible && compatible->getLength()==sizeof(expected) &&
        !memcmp(compatible->getBytesNoCopy(),expected,sizeof(expected));
    OSSafeReleaseNULL(root);
    if(!valid)panic("QEMU input: wrong virtual platform");
    native_hid_stage=1;
    native_hid_load_status=OSKextLoadKextWithIdentifier("com.apple.iokit.IOHIDFamily");
    if(native_hid_load_status)return;
    const OSSymbol *name=OSSymbol::withCString("IOHIDDevice");
    const OSMetaClass *meta=name?OSMetaClass::getMetaClassWithName(name):nullptr;
    bool extent=meta && meta->getClassSize()==208;
    OSSafeReleaseNULL(name);
    if(!extent)panic("QEMU input: D27 IOHIDDevice ABI mismatch");
    void *handle=OSMetaClass::preModLoad(g_kernel_kmod_info.name);
    if(!handle)return;
    native_qemu_hid_static_init();
    native_hid_input_meta_status=OSMetaClass::postModLoad(handle);
    if(native_hid_input_meta_status)return;
    native_hid_stage=2;
    OSDictionary *matching=IOService::serviceMatching("IOHIDResource");
    IOService *parent=matching?IOService::waitForMatchingService(matching,5000000000ULL):nullptr;
    OSSafeReleaseNULL(matching);
    IOService *device=native_hid_input_allocate();
    bool attached=false;
    if(!parent || !device || !device->init() || !(attached=device->attach(parent)) || !device->start(parent)) {
        native_hid_input_observed(7,kIOReturnError);
        if(attached)device->detach(parent);
        OSSafeReleaseNULL(device);OSSafeReleaseNULL(parent);return;
    }
    native_hid_input_object=(uintptr_t)device;
    native_hid_stage=3;
    native_virtio_input_probe();
    OSSafeReleaseNULL(parent);
}
