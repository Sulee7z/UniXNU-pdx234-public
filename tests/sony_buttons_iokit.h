// SPDX-License-Identifier: BSD-2-Clause-Patent
// Test doubles only. Target builds always include the real IOService/HID headers.
#ifndef SONY_BUTTONS_TEST_IOKIT_H
#define SONY_BUTTONS_TEST_IOKIT_H
#include <cassert>
#include <cstdint>
#include <cstring>
#include <cstdarg>
#include <cstdio>
#include <vector>
#define OSDeclareDefaultStructors(name)
#define OSDefineMetaClassAndStructors(name, parent)
#define OSDynamicCast(type, object) dynamic_cast<type *>(object)
#define OSSafeReleaseNULL(object) do { if (object) { (object)->release(); (object) = nullptr; } } while (0)
using IOReturn = int;
using IOOptionBits = unsigned;
constexpr int kIOReturnSuccess = 0, kIOReturnNoMemory = -10, kIOReturnBadArgument = -11;
constexpr int kIODirectionNone = 0, kIOHIDReportTypeInput = 0, kIOMapAnywhere = 1, kIOMapInhibitCache = 2;
inline void *gIOServicePlane = nullptr;
namespace buttons_test {
inline bool eventPresent = false, failAllocation = false, failSubmission = false;
inline unsigned failStart = 0;
inline uint64_t nowMs = 0;
inline std::vector<std::vector<uint8_t>> reports;
inline uint32_t core[0x3000 / 4], owner[0x4000 / 4], observer[0x80000 / 4];
inline unsigned coreMaps = 0, ownerMaps = 0, observerMaps = 0;
}
struct OSObject {
    virtual ~OSObject() = default;
    virtual void release() { delete this; }
};
struct OSIterator : OSObject { virtual OSObject *getNextObject() { return nullptr; } };
struct IORegistryEntry : OSObject {
    virtual OSIterator *getChildIterator(void *);
    virtual void *metaCast(const char *) { return nullptr; }
};
struct ButtonEventService : IORegistryEntry {
    void *metaCast(const char *name) override { return !strcmp(name, "AppleUserHIDEventService") ? this : nullptr; }
    OSIterator *getChildIterator(void *) override { return new OSIterator; }
};
inline ButtonEventService buttonEventService;
struct ButtonChildren : OSIterator {
    unsigned used = 0;
    OSObject *getNextObject() override { return buttons_test::eventPresent && !used++ ? &buttonEventService : nullptr; }
};
inline OSIterator *IORegistryEntry::getChildIterator(void *) { return new ButtonChildren; }
struct IOMemoryDescriptor : OSObject { std::vector<uint8_t> bytes; };
struct IOBufferMemoryDescriptor : IOMemoryDescriptor {
    static IOBufferMemoryDescriptor *withBytes(const void *data, size_t bytes, int) {
        if (buttons_test::failAllocation) return nullptr;
        auto *memory = new IOBufferMemoryDescriptor;
        memory->bytes.assign(static_cast<const uint8_t *>(data), static_cast<const uint8_t *>(data) + bytes);
        return memory;
    }
};
struct OSString : OSObject { static OSString *withCString(const char *) { return new OSString; } };
struct IOWorkLoop;
struct OSDictionary : OSObject {};
struct IOService : IORegistryEntry {
    virtual bool init() { return true; }
    virtual bool attach(IOService *) { return true; }
    virtual void detach(IOService *) {}
    static OSDictionary *serviceMatching(const char *) { return new OSDictionary; }
    static IOService *waitForMatchingService(OSDictionary *, uint64_t) { return new IOService; }
    virtual bool start(IOService *) { return !buttons_test::failStart; }
    virtual void stop(IOService *) {}
    virtual void free() {}
    virtual IOWorkLoop *getWorkLoop() const { return nullptr; }
    bool setProperty(const char *, bool) { return true; }
};
struct IOHIDDevice : IOService {
    virtual OSString *newTransportString() const { return nullptr; }
    virtual OSString *newProductString() const { return nullptr; }
    virtual IOReturn newReportDescriptor(IOMemoryDescriptor **) const { return -1; }
    IOReturn handleReport(IOMemoryDescriptor *memory, int type, unsigned options) {
        assert(type == kIOHIDReportTypeInput && !options);
        if (buttons_test::failSubmission) return -12;
        buttons_test::reports.push_back(memory->bytes);
        return 0;
    }
};
struct IOTimerEventSource : OSObject {
    using Action = void (*)(OSObject *, IOTimerEventSource *);
    inline static IOTimerEventSource *current = nullptr;
    Action action = nullptr;
    OSObject *owner = nullptr;
    unsigned due = 0;
    static IOTimerEventSource *timerEventSource(OSObject *owner, Action action) {
        auto *timer = new IOTimerEventSource;
        timer->owner = owner; timer->action = action;
        return current = timer;
    }
    void setTimeoutMS(unsigned ms) { assert(ms && ms <= 100); due = ms; }
    void cancelTimeout() { due = 0; }
    void fire(uint64_t ms) { buttons_test::nowMs = ms; due = 0; action(owner, this); }
};
struct IOWorkLoop : OSObject {
    using Action = IOReturn (*)(OSObject *, void *, void *, void *, void *);
    static IOWorkLoop *workLoop() { return new IOWorkLoop; }
    int addEventSource(OSObject *) { return 0; }
    void removeEventSource(OSObject *) {}
    int runAction(Action action, OSObject *owner) { return action(owner, nullptr, nullptr, nullptr, nullptr); }
};
struct IOMemoryMap : OSObject {
    uint32_t *address;
    explicit IOMemoryMap(uint32_t *p) : address(p) {}
    uintptr_t getVirtualAddress() { return reinterpret_cast<uintptr_t>(address); }
};
struct IODeviceMemory : OSObject {
    uint64_t address, bytes;
    static IODeviceMemory *withRange(uint64_t address, uint64_t bytes) {
        auto *m = new IODeviceMemory; m->address = address; m->bytes = bytes; return m;
    }
    IOMemoryMap *map(int flags) {
        assert(flags == (kIOMapAnywhere | kIOMapInhibitCache));
        if (address == 0x0c400000 && bytes == 0x3000) { ++buttons_test::coreMaps; return new IOMemoryMap(buttons_test::core); }
        if (address == 0x0c42d000 && bytes == 0x4000) { ++buttons_test::ownerMaps; return new IOMemoryMap(buttons_test::owner); }
        if (address == 0x0c440000 && bytes == 0x80000) { ++buttons_test::observerMaps; return new IOMemoryMap(buttons_test::observer); }
        assert(false && "unexpected SPMI/PDC/channel mapping"); return nullptr;
    }
};
inline uint64_t mach_absolute_time() { return buttons_test::nowMs * 1000000; }
inline void absolutetime_to_nanoseconds(uint64_t time, uint64_t *out) { *out = time; }
inline void IOLog(const char *, ...) {}
#endif
