/* Host fixture for the exact production publication code; IOKit is modeled. */
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <vector>

struct OSObject { virtual ~OSObject() = default; };
struct OSData : OSObject {
    std::vector<uint8_t> bytes;
    OSData() = default;
    OSData(const void *data, size_t length) {
        auto at = static_cast<const uint8_t *>(data);
        bytes.assign(at, at + length);
    }
    size_t getLength() const { return bytes.size(); }
    const void *getBytesNoCopy() const { return bytes.data(); }
};
#define OSDynamicCast(type, object) dynamic_cast<type *>(object)

static const void *gIODTPlane = nullptr;
struct IORegistryEntry {
    std::map<std::string, OSData> properties;
    OSObject wrongType;
    const char *wrongKey = nullptr;
    bool present = true;
    bool writeFails = false;
    unsigned held = 0;
    unsigned writes = 0;
    static IORegistryEntry *fromPath(const char *, const void *);
    OSObject *getProperty(const char *key) {
        assert(held);
        if (wrongKey && !strcmp(wrongKey, key)) return &wrongType;
        auto it = properties.find(key);
        return it == properties.end() ? nullptr : &it->second;
    }
    bool setProperty(const char *key, const void *data, size_t length) {
        assert(held && !getProperty(key));
        if (writeFails) return false;
        properties.emplace(key, OSData(data, length));
        ++writes;
        return true;
    }
    void release() { assert(held); --held; }
};
static IORegistryEntry chosen, wlan;
IORegistryEntry *IORegistryEntry::fromPath(const char *path, const void *plane) {
    assert(plane == gIODTPlane);
    IORegistryEntry *entry = !strcmp(path, "/chosen") ? &chosen : &wlan;
    assert(entry == &chosen || !strcmp(path, "/arm-io/wlan"));
    if (!entry->present) return nullptr;
    ++entry->held;
    return entry;
}

#define SONY_RADIO_ADDRESS_HOST_TEST 1
#include "../drivers/SonyWcn/platform069/SonyWifiAddress069.cpp"
#define OSSafeReleaseNULL(object) do { if (object) { (object)->release(); (object) = nullptr; } } while (0)
#include "SonyWifiAddressReference069.h"

// Synthetic test seed, not an ADT or captured device identity.
static const uint8_t seed[] = {0x13, 0x57, 0x9b, 0xdf, 0x24, 0x68, 0xac, 0xe0};
static const char chosenKey[] = "mac-address-wifi0";
static const char wlanKey[] = "local-mac-address";
static const char seedKey[] = "unique-chip-id";

static void reset() {
    assert(!chosen.held && !wlan.held);
    chosen = IORegistryEntry{};
    wlan = IORegistryEntry{};
    chosen.properties.emplace(seedKey, OSData(seed, sizeof seed));
}

int main() {
    // Same little-endian extraction as the pinned boardMac, independently of the
    // production helper's byte loop.
    uint64_t value = 0xe0ac6824df9b5713ULL;
    uint64_t ref = 0xcbf29ce484222325ULL;
    for (unsigned i = 0; i < 8; ++i)
        ref = (ref ^ ((value >> (8 * i)) & 0xff)) * 0x100000001b3ULL;
    std::vector<uint8_t> expected;
    for (unsigned i = 0; i < 6; ++i) expected.push_back(static_cast<uint8_t>(ref >> (8 * i)));
    expected[0] = (expected[0] & 0xfe) | 2;
    assert((expected[0] & 3) == 2);

    reset();
    assert(native_sony_wifi_publish() == 0);
    assert(chosen.properties.at(chosenKey).bytes == expected);
    assert(wlan.properties.at(wlanKey).bytes == expected);
    assert(native_sony_wifi_publish() == 0);
    assert(chosen.writes == 1 && wlan.writes == 1);

    reset();
    wlan.present = false;
    assert(native_sony_wifi_publish() == ENOENT && !chosen.writes);
    wlan.present = true;
    chosen.present = false;
    assert(native_sony_wifi_publish() == ENOENT && !wlan.writes);

    reset();
    chosen.properties.erase(seedKey);
    assert(native_sony_wifi_publish() == ENOENT);
    const uint8_t zero[8] = {};
    chosen.properties.emplace(seedKey, OSData(zero, sizeof zero));
    assert(native_sony_wifi_publish() == ENOENT);
    chosen.properties.at(seedKey) = OSData(seed, sizeof seed - 1);
    assert(native_sony_wifi_publish() == ENOENT && !chosen.writes && !wlan.writes);

    reset();
    auto conflicting = expected;
    conflicting.back() ^= 1;
    chosen.properties.emplace(chosenKey, OSData(conflicting.data(), conflicting.size()));
    assert(native_sony_wifi_publish() == EINVAL);
    assert(chosen.properties.at(chosenKey).bytes == conflicting && !wlan.writes);
    chosen.properties.erase(chosenKey);
    wlan.properties.emplace(wlanKey, OSData(expected.data(), 5));
    assert(native_sony_wifi_publish() == EINVAL && !chosen.writes);
    wlan.properties.erase(wlanKey);
    wlan.wrongKey = wlanKey;
    assert(native_sony_wifi_publish() == EINVAL && !chosen.writes && !wlan.writes);

    reset();
    wlan.writeFails = true;
    assert(native_sony_wifi_publish() == EIO && !chosen.writes && !wlan.writes);
    wlan.writeFails = false;
    chosen.writeFails = true;
    assert(native_sony_wifi_publish() == EIO && !chosen.writes && wlan.writes == 1);
    chosen.writeFails = false;
    assert(native_sony_wifi_publish() == 0);
    assert(chosen.properties.at(chosenKey).bytes == wlan.properties.at(wlanKey).bytes);
    assert(chosen.writes == 1 && wlan.writes == 1 && !chosen.held && !wlan.held);

    // Compare the exact official boardMac body against the actual helper over
    // many synthetic seeds, including extended OSData and zero-first-eight.
    uint64_t random = 0x2545f4914f6cdd1dULL;
    for (unsigned round = 0; round < 10000; ++round) {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        uint8_t bytes[10];
        for (unsigned i = 0; i < 8; ++i) bytes[i] = uint8_t(random >> (8 * i));
        bytes[8] = 0xff; bytes[9] = 0xee;
        reset();
        chosen.properties.at(seedKey) = OSData(bytes, sizeof bytes);
        uint8_t reference[6], result[6];
        assert(officialBoardMac(reference));
        assert(wifiAddressFromSeed(bytes, sizeof bytes, result) == 0);
        assert(!memcmp(reference, result, 6));
        assert(!chosen.held && !wlan.held);
    }
    reset();
    uint8_t extendedZero[9] = {0, 0, 0, 0, 0, 0, 0, 0, 1};
    chosen.properties.at(seedKey) = OSData(extendedZero, sizeof extendedZero);
    uint8_t unused[6];
    assert(!officialBoardMac(unused));
    assert(wifiAddressFromSeed(extendedZero, sizeof extendedZero, unused) == ENOENT);
}
