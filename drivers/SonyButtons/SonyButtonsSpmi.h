// SPDX-License-Identifier: BSD-2-Clause-Patent
#ifndef SONY_BUTTONS_SPMI_H
#define SONY_BUTTONS_SPMI_H
#if defined(SONY_BUTTONS_HOST_TEST)
#include "sony_buttons_iokit.h"
#else
#include <IOKit/IOMemoryDescriptor.h>
#endif
#include "SonyButtonsCore.h"

class SonyButtonsSpmi {
    IOMemoryMap *coreMap = nullptr, *ownerMap = nullptr, *observerMap = nullptr;
    volatile uint32_t *core = nullptr, *owner = nullptr, *observer = nullptr;
    uint32_t ponApid = ~0u, gpioApid = ~0u;
    uint8_t enabled = 0;
    int qualify(uint32_t apid, uint16_t ppid) const;
    static bool map(IOMemoryMap *&, volatile uint32_t *&, uint64_t, uint64_t);
public:
    ~SonyButtonsSpmi();
    int prepare(uint32_t pon, uint32_t gpio);
    static int read(void *context, uint16_t ppid, uint8_t reg, uint8_t *value);
    uint8_t enabledMask() const { return enabled; }
};
#endif
