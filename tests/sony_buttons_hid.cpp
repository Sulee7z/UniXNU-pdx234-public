// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "sony_buttons_iokit.h"
#include "SonyButtonsCore.h"
struct Hardware {
    uint8_t pon = 0, gpio = 1;
    int error = 0;
    unsigned reads = 0;
    static int read(void *context, uint16_t ppid, uint8_t offset, uint8_t *out) {
        auto *h = static_cast<Hardware *>(context); ++h->reads;
        assert(offset == 0x10 && (ppid == 0x13 || ppid == 0x18d));
        if (h->error) return h->error;
        *out = ppid == 0x13 ? h->pon : h->gpio; return 0;
    }
};
#include "SonyButtonsHid.cpp"
int main() {
    using namespace buttons_test;
    Hardware hardware; SonyButtonsReadOps ops{&hardware, Hardware::read, 14}; IOService provider;
    auto *device = native_sony_buttons_allocate(&ops, 0); assert(device);
    IOMemoryDescriptor *descriptor = nullptr;
    assert(!static_cast<SonyButtonsHid *>(device)->newReportDescriptor(&descriptor));
    assert(descriptor->bytes == std::vector<uint8_t>(sony_buttons_descriptor, sony_buttons_descriptor+sizeof(sony_buttons_descriptor)));
    descriptor->release();
    assert(device->start(&provider)); auto *timer = IOTimerEventSource::current;
    hardware.pon = 0x80; timer->fire(0); timer->fire(15); hardware.pon = 0; timer->fire(20); timer->fire(35);
    assert(reports.empty() && timer->due == 20); // callbacks occur before event attachment; keep sampling for release
    eventPresent = true; timer->fire(100);
    assert(reports == std::vector<std::vector<uint8_t>>({{2,0},{2,2},{2,0}}));
    assert(timer->due == 20); // idle timeout, not an unbounded busy loop
    hardware.pon = 0x40; timer->fire(120); failSubmission = true; timer->fire(135);
    assert(reports.size() == 3 && native_sony_buttons_stats[6] == 1);
    hardware.pon = 0; timer->fire(140); failSubmission = false; timer->fire(155);
    assert(reports[3][1] == 4 && reports.back()[1] == 0); // never lose a release behind a failed press
    hardware.pon = 0x80; timer->fire(160); failAllocation = true; timer->fire(175);
    assert(native_sony_buttons_stats[8] == kIOReturnNoMemory); failAllocation = false; timer->fire(180);
    assert(reports.back()[1] == 2);
    for (unsigned i = 0; i < 100; ++i) timer->fire(200+i*100);
    assert(reports.back()[1] == 2); // no auto-release during a long hold
    hardware.error = -102; timer->fire(20000); timer->fire(20005); timer->fire(20010);
    assert(!timer->due && reports.back()[1] == 0 && native_sony_buttons_stats[0] == -6);
    const unsigned reads = hardware.reads; timer->fire(20020); assert(hardware.reads == reads);
    device->stop(&provider); device->free(); device->release();
    // Stop during a real held key sends neutral through the actual stop action.
    hardware.error = 0; reports.clear(); device = native_sony_buttons_allocate(&ops, 0); assert(device->start(&provider));
    timer = IOTimerEventSource::current; timer->fire(0); timer->fire(15); assert(reports.back()[1] == 2);
    device->stop(&provider); assert(!reports.back()[1]); device->free(); device->release();
    // No event service + repeated failures: neutral retries terminate at64 ticks.
    eventPresent = false; hardware.error = -102; device = native_sony_buttons_allocate(&ops, 0); assert(device->start(&provider));
    timer = IOTimerEventSource::current; for (unsigned i = 0; i < 66; ++i) timer->fire(i*100);
    assert(!timer->due && native_sony_buttons_stats[4] == 1); device->stop(&provider); device->free(); device->release();
    // Missing qualification still publishes a neutral ready service, but must
    // never call a hardware callback or schedule endless post-ready work.
    SonyButtonsReadOps neutral = {}; eventPresent = false; reports.clear();
    const unsigned before = hardware.reads;
    device = native_sony_buttons_allocate(&neutral, SonyButtonsNotOwned); assert(device->start(&provider));
    timer = IOTimerEventSource::current;
    for (unsigned i = 0; i < 5; ++i) timer->fire(i*100);
    assert(reports.empty() && hardware.reads == before && native_sony_buttons_stats[0] == 6);
    eventPresent = true; failSubmission = true; timer->fire(500);
    assert(native_sony_buttons_stats[0] == 6 && reports.empty() && timer->due == 100);
    failSubmission = false; timer->fire(600);
    assert(reports == std::vector<std::vector<uint8_t>>({{2,0}}) && !timer->due);
    assert(native_sony_buttons_stats[0] == 7 && native_sony_buttons_stats[12] == 0 &&
           native_sony_buttons_stats[13] == SonyButtonsNotOwned);
    device->stop(&provider); device->free(); device->release();
    eventPresent = false; device = native_sony_buttons_allocate(&neutral, SonyButtonsBadArgument); assert(device->start(&provider));
    timer = IOTimerEventSource::current; for (unsigned i = 0; i < 600; ++i) timer->fire(i*100);
    assert(!timer->due && hardware.reads == before && native_sony_buttons_stats[4] == 1);
    device->stop(&provider); device->free(); device->release();
    puts("PASS neutral HID readiness independent of qualification: zero hardware reads, delayed matching/neutral submission, qualification error preserved, bounded60s match timeout");
    puts("PASS actual SonyButtonsHid: separate consumer descriptor/start/timer/match/handleReport/retry/longhold/release/stop and bounded neutral recovery; IOKit services modeled");
}
