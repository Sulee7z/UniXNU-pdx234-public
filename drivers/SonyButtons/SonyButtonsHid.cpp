// SPDX-License-Identifier: BSD-2-Clause-Patent
#if defined(SONY_BUTTONS_HOST_TEST)
#include "sony_buttons_iokit.h"
#else
#include <IOKit/IOService.h>
#include <IOKit/hid/IOHIDDevice.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOTimerEventSource.h>
#include <libkern/c++/OSIterator.h>
#include <libkern/c++/OSString.h>
#include <mach/mach_time.h>
#endif
#include "SonyButtonsCore.h"

// stage, samples, successful reports, stable, queue, read errors, submit errors,
// last read/submit error, matched event service, enabled mask, terminal,
// hardware-enabled, qualification-error, requested-PON-APID, requested-GPIO-APID.
extern "C" { volatile int32_t native_sony_buttons_stats[16]; }

class SonyButtonsHid : public IOHIDDevice {
    OSDeclareDefaultStructors(SonyButtonsHid)
    IOWorkLoop *inputLoop = nullptr;
    IOTimerEventSource *timer = nullptr;
    SonyButtonsReadOps readOps = {};
    SonyButtonsState state = {};
    bool running = false, configured = false;
    unsigned recoveryTicks = 0, logTicks = 0;
    int qualificationError = 0;

    static bool hasEventService(IORegistryEntry *parent, unsigned depth, unsigned &budget) {
        if (!depth || !budget) return false;
        OSIterator *children = parent->getChildIterator(gIOServicePlane);
        if (!children) return false;
        bool found = false;
        while (budget) {
            OSObject *object = children->getNextObject();
            if (!object) break;
            --budget;
            IORegistryEntry *entry = OSDynamicCast(IORegistryEntry, object);
            if (!entry) continue;
            if (entry->metaCast("IOHIDEventDriver") || entry->metaCast("AppleUserHIDEventService") ||
                hasEventService(entry, depth - 1, budget)) { found = true; break; }
        }
        children->release();
        return found;
    }

    static int submit(void *context, const uint8_t *bytes, size_t length) {
        SonyButtonsHid *self = static_cast<SonyButtonsHid *>(context);
        IOBufferMemoryDescriptor *buffer = IOBufferMemoryDescriptor::withBytes(bytes, length, kIODirectionNone);
        const IOReturn result = buffer ? self->handleReport(buffer, kIOHIDReportTypeInput, 0) : kIOReturnNoMemory;
        OSSafeReleaseNULL(buffer);
        return (int)result;
    }

    void record(bool matched) {
        native_sony_buttons_stats[1] = (int32_t)state.samples;
        native_sony_buttons_stats[2] = (int32_t)state.reports;
        native_sony_buttons_stats[3] = state.stable;
        native_sony_buttons_stats[4] = state.count;
        native_sony_buttons_stats[5] = (int32_t)state.read_errors;
        native_sony_buttons_stats[6] = (int32_t)state.submit_errors;
        native_sony_buttons_stats[7] = state.last_read_error;
        native_sony_buttons_stats[8] = state.last_submit_error;
        native_sony_buttons_stats[9] = matched;
        native_sony_buttons_stats[10] = state.enabled_mask;
        native_sony_buttons_stats[11] = state.terminal_error;
    }

    static void tick(OSObject *owner, IOTimerEventSource *source) {
        SonyButtonsHid *self = OSDynamicCast(SonyButtonsHid, owner);
        if (!self || !self->running) return;
        uint64_t ns = 0;
        absolutetime_to_nanoseconds(mach_absolute_time(), &ns);
        if (self->readOps.enabled_mask && !self->state.stopped)
            (void)sony_buttons_poll(&self->state, &self->readOps, ns / 1000000);
        unsigned budget = 32;
        const bool matched = hasEventService(self, 4, budget);
        if (matched) (void)sony_buttons_flush(&self->state, submit, self, 8);
        self->record(matched);
        native_sony_buttons_stats[0] = !self->readOps.enabled_mask ? (!self->state.count ? 7 : 6) :
                                     self->state.stopped ? -6 : matched ? 5 : 4;
        if (!(self->logTicks++ % 100)) {
            IOLog("[sony-buttons] s=%d samples=%u reports=%u stable=%x queue=%u readerr=%u submiterr=%u last=%d/%d event=%u terminal=%d\n",
                native_sony_buttons_stats[0], self->state.samples, self->state.reports, self->state.stable,
                self->state.count, self->state.read_errors, self->state.submit_errors,
                self->state.last_read_error, self->state.last_submit_error, matched, self->state.terminal_error);
        }
        if (!self->readOps.enabled_mask) {
            // A published neutral consumer is useful for chain qualification,
            // not a pretend working key. No transport or hardware callback.
            if (!self->state.count || ++self->recoveryTicks >= 600) {
                IOLog("[sony-buttons] neutral-ready=%u event=%u pending=%u qualification=%d hardware=0\n",
                    self->state.count == 0, matched, self->state.count, self->qualificationError);
                return;
            }
            source->setTimeoutMS(100);
        } else if (self->state.stopped) {
            if (!self->state.count || ++self->recoveryTicks >= 64) {
                IOLog("[sony-buttons] stopped error=%d neutral-pending=%u last-submit=%d\n",
                    self->state.terminal_error, self->state.count, self->state.last_submit_error);
                return; // No further hardware reads; neutral retries are also bounded.
            }
            source->setTimeoutMS(100);
        } else source->setTimeoutMS(self->state.stable || self->state.candidate ? 5 : 20);
    }

    static IOReturn stopAction(OSObject *owner, void *, void *, void *, void *) {
        SonyButtonsHid *self = OSDynamicCast(SonyButtonsHid, owner);
        if (!self) return kIOReturnBadArgument;
        self->running = false;
        sony_buttons_cancel(&self->state, 0);
        unsigned budget = 32;
        const bool matched = hasEventService(self, 4, budget);
        const int result = matched ? sony_buttons_flush(&self->state, submit, self, 1) : 0;
        self->record(matched);
        return (IOReturn)result;
    }

public:
    bool configure(const SonyButtonsReadOps *ops, int qualification) {
        if (configured || !ops || (ops->enabled_mask ? !ops->read8 : ops->read8 != nullptr) ||
            sony_buttons_init(&state, ops->enabled_mask)) return false;
        readOps = *ops;
        qualificationError = qualification;
        configured = true;
        return true;
    }
    IOWorkLoop *getWorkLoop() const override { return inputLoop; }
    OSString *newTransportString() const override { return OSString::withCString("SPMI"); }
    OSString *newProductString() const override { return OSString::withCString("Sony PMIC Buttons"); }
    IOReturn newReportDescriptor(IOMemoryDescriptor **out) const override {
        if (!out) return kIOReturnBadArgument;
        *out = IOBufferMemoryDescriptor::withBytes(sony_buttons_descriptor, sizeof(sony_buttons_descriptor), kIODirectionNone);
        return *out ? kIOReturnSuccess : kIOReturnNoMemory;
    }
    bool start(IOService *provider) override {
        if (!configured || inputLoop) return false;
        inputLoop = IOWorkLoop::workLoop();
        if (!inputLoop) return false;
        // Consumer Control is a separate real device. No keyboard/Home report,
        // digitizer property rewrite, event-service vtable copy or touch globals.
        if (!setProperty("HIDDefaultBehavior", true) || !setProperty("Built-In", true) ||
            !setProperty("SonyPMICButtons", true) ||
            !setProperty("SonyButtonsHardwareQualified", readOps.enabled_mask != 0) ||
            !IOHIDDevice::start(provider)) {
            OSSafeReleaseNULL(inputLoop); return false;
        }
        timer = IOTimerEventSource::timerEventSource(this, tick);
        if (!timer || inputLoop->addEventSource(timer) != kIOReturnSuccess) {
            OSSafeReleaseNULL(timer); IOHIDDevice::stop(provider); OSSafeReleaseNULL(inputLoop); return false;
        }
        running = true;
        native_sony_buttons_stats[12] = readOps.enabled_mask != 0;
        native_sony_buttons_stats[13] = qualificationError;
        native_sony_buttons_stats[0] = 3;
        timer->setTimeoutMS(1);
        return true;
    }
    void stop(IOService *provider) override {
        if (timer) timer->cancelTimeout();
        if (running && inputLoop) {
            const IOReturn result = inputLoop->runAction(stopAction, this);
            if (result != kIOReturnSuccess) IOLog("[sony-buttons] stop neutral failed result=%d\n", (int)result);
        }
        if (timer) { inputLoop->removeEventSource(timer); OSSafeReleaseNULL(timer); }
        IOHIDDevice::stop(provider);
    }
    void free() override { OSSafeReleaseNULL(inputLoop); IOHIDDevice::free(); }
};
OSDefineMetaClassAndStructors(SonyButtonsHid, IOHIDDevice)
extern "C" IOService *native_sony_buttons_allocate(const SonyButtonsReadOps *ops, int qualification) {
    SonyButtonsHid *device = new SonyButtonsHid;
    if (device && !device->configure(ops, qualification)) { device->release(); return nullptr; }
    return device;
}
