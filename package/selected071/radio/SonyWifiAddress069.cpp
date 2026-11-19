/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/*
 * Early 24A446 Wi-Fi identity publication for the Sony069 owner.
 *
 * The address follows the pinned sheng WifiProbe::boardMac FNV-1a contract:
 * eight little-endian bytes of the already-selected /chosen/unique-chip-id,
 * locally administered and unicast. It is a stable software address, not a
 * recovered Sony OTP/vendor MAC. No seed or address is compiled into this file.
 */
#include <stddef.h>
#include <stdint.h>
#ifndef SONY_RADIO_ADDRESS_HOST_TEST
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IORegistryEntry.h>
#include <libkern/c++/OSData.h>
#include <sys/errno.h>
#include <string.h>
#endif

static int wifiAddressFromSeed(const uint8_t *seed, size_t length, uint8_t address[6]) {
    if (!seed || !address || length < sizeof(uint64_t)) return ENOENT;

    uint64_t hash = 0xcbf29ce484222325ULL;
    uint8_t nonzero = 0;
    for (unsigned i = 0; i < sizeof(uint64_t); ++i) {
        nonzero |= seed[i];
        hash = (hash ^ seed[i]) * 0x100000001b3ULL;
    }
    if (!nonzero) return ENOENT;
    for (unsigned i = 0; i < 6; ++i)
        address[i] = static_cast<uint8_t>(hash >> (i * 8));
    address[0] = static_cast<uint8_t>((address[0] & 0xfe) | 0x02);
    return 0;
}

extern "C" int native_sony_wifi_publish(void) {
    IORegistryEntry *chosen = IORegistryEntry::fromPath("/chosen", gIODTPlane);
    if (!chosen) return ENOENT;
    IORegistryEntry *wlan = IORegistryEntry::fromPath("/arm-io/wlan", gIODTPlane);
    if (!wlan) {
        chosen->release();
        return ENOENT;
    }

    OSData *identity = OSDynamicCast(OSData, chosen->getProperty("unique-chip-id"));
    uint8_t address[6];
    int error = identity ? wifiAddressFromSeed(
        static_cast<const uint8_t *>(identity->getBytesNoCopy()), identity->getLength(), address) : ENOENT;
    OSObject *chosenObject = chosen->getProperty("mac-address-wifi0");
    OSObject *wlanObject = wlan->getProperty("local-mac-address");
    OSData *chosenAddress = OSDynamicCast(OSData, chosenObject);
    OSData *wlanAddress = OSDynamicCast(OSData, wlanObject);

    /* Match the same deterministic identity used by WifiProbe::wlan_mac.bin.
     * Existing properties are never replaced; any mismatch fails closed rather
     * than leaving the firmware address and OS-visible interface identity split. */
    if (!error && ((chosenObject && !chosenAddress) || (wlanObject && !wlanAddress) ||
        (chosenAddress && chosenAddress->getLength() != sizeof(address)) ||
        (wlanAddress && wlanAddress->getLength() != sizeof(address)))) {
        error = EINVAL;
    } else if (!error && chosenAddress &&
               memcmp(chosenAddress->getBytesNoCopy(), address, sizeof(address))) {
        error = EINVAL;
    } else if (!error && wlanAddress &&
               memcmp(wlanAddress->getBytesNoCopy(), address, sizeof(address))) {
        error = EINVAL;
    }

    // Set the capability key under /chosen last. A failed write can be retried
    // using the already-matching WLAN property without overwriting anything.
    if (!error && !wlanAddress && !wlan->setProperty("local-mac-address", address, sizeof(address))) error = EIO;
    if (!error && !chosenAddress && !chosen->setProperty("mac-address-wifi0", address, sizeof(address))) error = EIO;
    wlan->release();
    chosen->release();
    return error;
}
