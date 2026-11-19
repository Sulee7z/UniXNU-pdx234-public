// SPDX-License-Identifier: BSD-2-Clause-Patent
#if !defined(SONY_BUTTONS_HOST_TEST)
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOLib.h>
#endif
#include "SonyButtonsSpmi.h"
extern "C" {
// Reuse the pinned official v7 observer command/wait implementation unchanged.
// br_find/br_write8/reset/SDAM helpers are deliberately never called here.
#include "BootResetCore.h"
}

// Last same-boot precheck and transaction, not an assertion of hardware success:
// version/count/APID_MAP/owner/APID/PPID/result/STATUS/RT_STS/attempts/successes.
extern "C" { volatile uint32_t native_sony_buttons_spmi[12]; }

bool SonyButtonsSpmi::map(IOMemoryMap *&mapping, volatile uint32_t *&va, uint64_t address, uint64_t bytes) {
    IODeviceMemory *memory = IODeviceMemory::withRange(address, bytes);
    mapping = memory ? memory->map(kIOMapAnywhere | kIOMapInhibitCache) : nullptr;
    OSSafeReleaseNULL(memory);
    va = mapping ? reinterpret_cast<volatile uint32_t *>(mapping->getVirtualAddress()) : nullptr;
    return va != nullptr;
}

SonyButtonsSpmi::~SonyButtonsSpmi() {
    OSSafeReleaseNULL(observerMap);
    OSSafeReleaseNULL(ownerMap);
    OSSafeReleaseNULL(coreMap);
}

int SonyButtonsSpmi::qualify(uint32_t apid, uint16_t ppid) const {
    native_sony_buttons_spmi[4] = apid;
    native_sony_buttons_spmi[5] = ppid;
    native_sony_buttons_spmi[0] = 0;
    native_sony_buttons_spmi[1] = 0;
    native_sony_buttons_spmi[2] = ~0u;
    native_sony_buttons_spmi[3] = ~0u;
    if (!core || !owner || apid >= 1024) return SonyButtonsNotOwned;
    const uint32_t version = core[0];
    native_sony_buttons_spmi[0] = version;
    if (version < BR_VERSION_V7_MIN || version >= BR_VERSION_V8_MIN) return SonyButtonsNotOwned;
    const uint32_t count = core[BR_FEATURES / 4] & BR_FEATURES_APIDS_MASK;
    native_sony_buttons_spmi[1] = count;
    if (!count || count > 1024 || apid >= count)
        return SonyButtonsNotOwned;
    if (ppid != SONY_BUTTON_PON_PPID && ppid != SONY_BUTTON_GPIO_PPID) return SonyButtonsNotOwned;
    // Only the caller-supplied channel's mapping/owner words are read. No sweep.
    const uint32_t mapping = core[(BR_APID_MAP + 4 * apid) / 4];
    native_sony_buttons_spmi[2] = mapping;
    if (((mapping >> 8) & 0xfffu) != ppid || !(mapping & (1u << 24))) return SonyButtonsNotOwned;
    const uint32_t ownership = owner[(BR_CNFG_OWNER + 4 * apid) / 4];
    native_sony_buttons_spmi[3] = ownership;
    // Bit24 denotes IRQ ownership, NOT observer read permission. Requiring it
    // and EE0 ownership is an extra conservative named-channel selection rule.
    return sony_buttons_qualify_apid(version, count, apid, mapping, ownership, ppid, 0);
}

int SonyButtonsSpmi::prepare(uint32_t pon, uint32_t gpio) {
    if (coreMap || (pon == ~0u && gpio == ~0u)) return SonyButtonsBadArgument;
    // Exact live Sony spmi0 windows; no channels, PDC, interrupt, PBS or PON config.
    if (!map(coreMap, core, 0x0c400000, 0x3000) || !map(ownerMap, owner, 0x0c42d000, 0x4000))
        return SonyButtonsReadFailed;
    if (pon != ~0u) {
        const int result = qualify(pon, SONY_BUTTON_PON_PPID);
        if (result) return result;
        ponApid = pon;
        enabled |= SONY_BUTTON_POWER | SONY_BUTTON_VOLUME_UP;
    }
    if (gpio != ~0u) {
        const int result = qualify(gpio, SONY_BUTTON_GPIO_PPID);
        if (result) return result;
        gpioApid = gpio;
        enabled |= SONY_BUTTON_VOLUME_DOWN;
    }
    if (!map(observerMap, observer, 0x0c440000, 0x80000)) return SonyButtonsReadFailed;
    return 0;
}

int SonyButtonsSpmi::read(void *context, uint16_t ppid, uint8_t reg, uint8_t *value) {
    SonyButtonsSpmi *self = static_cast<SonyButtonsSpmi *>(context);
    if (!self || !value || reg != SONY_BUTTON_RT_STS || !self->observer) return SonyButtonsBadArgument;
    const uint32_t apid = ppid == SONY_BUTTON_PON_PPID ? self->ponApid :
                          ppid == SONY_BUTTON_GPIO_PPID ? self->gpioApid : ~0u;
    const int qualified = self->qualify(apid, ppid);
    if (qualified) {
        native_sony_buttons_spmi[6] = (uint32_t)qualified;
        return qualified; // Revoked ownership: no observer command.
    }
    const br_arbiter arbiter = {self->core, self->owner, 0};
    // br_read8 writes only EXT_READL to this owned observer CMD. It does not
    // write a PMIC register. BR_POLLS=100000 bounds each command's completion.
    const uint32_t attempt = native_sony_buttons_spmi[9] + 1;
    native_sony_buttons_spmi[9] = attempt;
    if (attempt == 1)
        IOLog("[sony-buttons-pre-read] version=%08x count=%u apid=%u ppid=%03x map=%08x owner=%08x observer=%llx command=08000100\n",
            native_sony_buttons_spmi[0], native_sony_buttons_spmi[1], apid, ppid,
            native_sony_buttons_spmi[2], native_sony_buttons_spmi[3],
            0x0c440000ULL + BR_OBS_APID_STRIDE * (uint64_t)apid);
    const int helper = br_read8(self->observer, &arbiter, (int)apid, reg, value);
    const int result = helper ? -100 - helper : 0;
    native_sony_buttons_spmi[6] = (uint32_t)result;
    // Diagnostic read of the same allowed STATUS, never another channel or
    // RDATA on failure. Original helper's final status was not exported.
    native_sony_buttons_spmi[7] = self->observer[(BR_OBS_APID_STRIDE * apid + BR_STATUS) / 4];
    native_sony_buttons_spmi[8] = result ? ~0u : *value;
    if (!result) native_sony_buttons_spmi[10] = native_sony_buttons_spmi[10] + 1;
    if (attempt == 1 || (result && attempt <= 4))
        IOLog("[sony-buttons-read] attempt=%u apid=%u ppid=%03x rc=%d status=%08x rt=%08x\n",
            attempt, apid, ppid, result, native_sony_buttons_spmi[7], native_sony_buttons_spmi[8]);
    return result;
}
