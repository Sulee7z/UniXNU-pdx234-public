// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "SonyButtonsSpmi.h"
#include "BootResetCore.h"
#include <cstdio>
extern "C" volatile uint32_t native_sony_buttons_spmi[12];
int main() {
    using namespace buttons_test;
    constexpr unsigned pon = 560, gpio = 20; // GPIO APID only a model, never a board claim.
    core[0] = 0x70000001; core[1] = 768;
    core[(0x2000+4*pon)/4] = (1u<<24) | (0x13u<<8);
    core[(0x2000+4*gpio)/4] = (1u<<24) | (0x18du<<8);
    uint8_t raw = 0;
    { // Foreign write owner must be rejected before even mapping the observer.
        SonyButtonsSpmi spmi; owner[pon] = 1; assert(spmi.prepare(pon, ~0u) == SonyButtonsNotOwned);
        assert(!observerMaps);
    }
    owner[pon] = 0;
    SonyButtonsSpmi spmi; assert(!spmi.prepare(pon, gpio) && spmi.enabledMask() == 14);
    auto *channel = observer + BR_OBS_APID_STRIDE*pon/4;
    channel[BR_STATUS/4] = 1; channel[BR_RDATA0/4] = 0xc0;
    assert(!SonyButtonsSpmi::read(&spmi, 0x13, 0x10, &raw) && raw == 0xc0);
    assert(channel[BR_CMD/4] == br_cmd(BR_OP_EXT_READL, 0x10, 0));
    assert(native_sony_buttons_spmi[0] == 0x70000001 && native_sony_buttons_spmi[1] == 768);
    assert(native_sony_buttons_spmi[4] == 560 && native_sony_buttons_spmi[5] == 0x13 && native_sony_buttons_spmi[7] == 1);
    assert(native_sony_buttons_spmi[8] == 0xc0 && native_sony_buttons_spmi[10] == 1);
    // Revoke ownership after setup. No observer CMD can be sent afterwards.
    channel[BR_CMD/4] = 0xdeadbeef; owner[pon] = 2;
    assert(SonyButtonsSpmi::read(&spmi, 0x13, 0x10, &raw) == SonyButtonsNotOwned && channel[0] == 0xdeadbeef);
    owner[pon] = 0; core[(0x2000+4*pon)/4] &= ~(1u<<24);
    assert(SonyButtonsSpmi::read(&spmi, 0x13, 0x10, &raw) == SonyButtonsNotOwned && channel[0] == 0xdeadbeef);
    core[(0x2000+4*pon)/4] |= 1u<<24;
    core[(0x2000+4*pon)/4] = (1u<<24) | (0x71u<<8);
    assert(SonyButtonsSpmi::read(&spmi, 0x13, 0x10, &raw) == SonyButtonsNotOwned && channel[0] == 0xdeadbeef);
    assert(native_sony_buttons_spmi[3] == ~0u); // Wrong PPID cannot even reach the owner-word load.
    core[(0x2000+4*pon)/4] = (1u<<24) | (0x13u<<8);
    core[0] = 0x80000000;
    assert(SonyButtonsSpmi::read(&spmi, 0x13, 0x10, &raw) == SonyButtonsNotOwned && channel[0] == 0xdeadbeef);
    assert(native_sony_buttons_spmi[1] == 0 && native_sony_buttons_spmi[2] == ~0u);
    core[0] = 0x70000001; core[1] = 560;
    assert(SonyButtonsSpmi::read(&spmi, 0x13, 0x10, &raw) == SonyButtonsNotOwned && channel[0] == 0xdeadbeef);
    assert(native_sony_buttons_spmi[2] == ~0u && native_sony_buttons_spmi[3] == ~0u);
    core[1] = 768;
    assert(SonyButtonsSpmi::read(&spmi, 0x71, 0x10, &raw) && channel[0] == 0xdeadbeef);
    assert(SonyButtonsSpmi::read(&spmi, 0x13, 0x48, &raw) && channel[0] == 0xdeadbeef);
    channel[BR_STATUS/4] = 0; assert(SonyButtonsSpmi::read(&spmi, 0x13, 0x10, &raw) == -101);
    for (unsigned error : {3u,5u,9u,15u}) {
        channel[BR_STATUS/4] = error;
        assert(SonyButtonsSpmi::read(&spmi, 0x13, 0x10, &raw) == -102);
    }
    auto *gpioChannel = observer+BR_OBS_APID_STRIDE*gpio/4;
    gpioChannel[BR_STATUS/4] = 1; gpioChannel[BR_RDATA0/4] = 0;
    assert(!SonyButtonsSpmi::read(&spmi, 0x18d, 0x10, &raw) && !raw);
    // Core and ownership words stay unchanged; no peripheral write path exists.
    assert(core[0] == 0x70000001 && core[1] == 768 && owner[pon] == 0 && owner[gpio] == 0);
    assert(core[(0x2000+4*pon)/4] == ((1u<<24) | (0x13u<<8)));
    assert(core[(0x2000+4*gpio)/4] == ((1u<<24) | (0x18du<<8)));
    // The manual candidate enables PON560 alone. No provided GPIO APID means
    // no metadata/read for PPID18d, even when its callback is invoked wrongly.
    SonyButtonsSpmi ponOnly; assert(!ponOnly.prepare(560, ~0u) && ponOnly.enabledMask() == 6);
    auto *unselected = observer + 0x20*1023/4; unselected[0] = 0x12345678;
    assert(SonyButtonsSpmi::read(&ponOnly, 0x18d, 0x10, &raw) == SonyButtonsNotOwned && unselected[0] == 0x12345678);
    channel[BR_STATUS/4] = 1; channel[BR_RDATA0/4] = 0x80;
    SonyButtonsReadOps readOps{&ponOnly, SonyButtonsSpmi::read, 6}; uint8_t pressed = 0;
    assert(!sony_buttons_read(&readOps, &pressed) && pressed == SONY_BUTTON_POWER);
    channel[BR_RDATA0/4] = 0x40; assert(!sony_buttons_read(&readOps, &pressed) && pressed == SONY_BUTTON_VOLUME_UP);
    channel[BR_RDATA0/4] = 0; assert(!sony_buttons_read(&readOps, &pressed) && pressed == 0);
    puts("PASS actual SonyButtonsSpmi + official br_read8: exact APIDs/EE, refuse foreign owner before observer mapping, ownership revocation before CMD, only RT_STS, timeout/denied/failure/dropped, no IRQ/PDC/PMIC writes");
}
