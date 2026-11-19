/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <assert.h>
#include <stdio.h>
#include "HIDLib.h"
#include "SonyButtonsCore.h"
int main(void) {
    HIDPreparsedDataRef parsed = NULL;
    assert(!HIDOpenReportDescriptor((void *)sony_buttons_descriptor, sizeof(sony_buttons_descriptor), &parsed, 0));
    IOByteCount length = 0;
    assert(!HIDGetReportLength(kHIDInputReport, 2, &length, parsed) && length == 2);
    for (unsigned mask = 0; mask <= 14; mask += 2) {
        uint8_t report[] = {2, (uint8_t)mask}; HIDUsage usages[8]; UInt32 count = 8;
        const OSStatus status = HIDGetButtonsOnPage(kHIDInputReport, 12, 0, usages, &count, parsed, report, 2);
        assert(status == (mask ? kHIDSuccess : kHIDUsageNotFoundErr));
        unsigned actual = 0;
        for (unsigned i = 0; i < count; ++i) {
            assert(usages[i] == 0x30 || usages[i] == 0xe9 || usages[i] == 0xea);
            actual |= usages[i] == 0x30 ? 2 : usages[i] == 0xe9 ? 4 : 8;
        }
        assert(actual == mask);
    }
    // Bit0 must never decode as Consumer Menu/Home even for malformed input.
    uint8_t report[] = {2, 1}; HIDUsage usages[8]; UInt32 count = 8;
    assert(HIDGetButtonsOnPage(kHIDInputReport, 12, 0, usages, &count, parsed, report, 2) == kHIDUsageNotFoundErr && !count);
    assert(!HIDCloseReportDescriptor(parsed));
    puts("PASS original Apple HID parser: ConsumerControl report2/2bytes, all8 power/up/down masks + release, bit0 constant/no Menu/Home");
}
