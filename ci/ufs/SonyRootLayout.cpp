// SPDX-License-Identifier: BSD-2-Clause-Patent
// Exercise the production root selector against captured Sony GPT bytes.
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/sha.h>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>
#include "RootDiagnostics.h"
using IOReturn = uint32_t;
constexpr IOReturn kIOReturnSuccess = 0;
constexpr unsigned kDataMax = 131072;
static UfsRootDiagnostics gRootDiagnostic;
static std::vector<uint8_t> gPrimary, gManifest;
static uint64_t gExpectedStart;
static unsigned gManifestReads;
static IOReturn hostRead4k(uint8_t lun, uint64_t lba, uint32_t blocks, void *out)
{
    assert(lun == 0);
    if (lba == 1 && blocks == 1) {
        memcpy(out, gPrimary.data() + 4096, 4096);
    } else if (lba == 2 && blocks == 4) {
        memcpy(out, gPrimary.data() + 8192, 16384);
    } else if (lba == gExpectedStart && blocks == 1) {
        memcpy(out, gManifest.data(), 4096);
        ++gManifestReads;
    } else {
        // A read of Android userdata, rddata or any undeclared range fails here.
        fprintf(stderr, "Unexpected transport read LBA=%llu count=%u\n",
                static_cast<unsigned long long>(lba), blocks);
        abort();
    }
    return 0;
}
#include "RootLayout.h"

static std::vector<uint8_t> input(const char *path)
{
    std::ifstream stream(path, std::ios::binary);
    assert(stream.good());
    return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}
static void put32(uint8_t *p, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) p[i] = uint8_t(value >> (i * 8));
}
static void put64(uint8_t *p, uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) p[i] = uint8_t(value >> (i * 8));
}
static void rehash()
{
    uint8_t *header = gPrimary.data() + 4096;
    put32(header + 88, rootCrc32(gPrimary.data() + 8192, le32(header + 80) * 128));
    put32(header + 16, rootCrc32(header, 92, true));
}
static bool parsed(uint32_t *status = nullptr)
{
    RootLayout layout;
    const char *why = nullptr;
    const bool ok = findRootLayout(&layout, &why);
    if (ok && status) *status = layout.manifestStatus;
    return ok;
}
int main(int argc, char **argv)
{
    assert(argc == 4);
    const auto original = input(argv[1]), candidate = input(argv[2]);
    gManifest = input(argv[3]);
    assert(original.size() == 24576 && candidate.size() == 24576 && gManifest.size() == 4096);
    const uint8_t *unixnu = candidate.data() + 8192 + 97 * 128;
    gExpectedStart = le64(unixnu + 32);
    const uint64_t expectedLast = le64(unixnu + 40);
    assert(gExpectedStart == 45679360 && expectedLast == 62456575);
    // The captured current disk has only Android userdata; never fall back to it.
    gPrimary = original;
    assert(!parsed() && gManifestReads == 0);
    gPrimary = candidate;
    RootLayout layout;
    const char *why = nullptr;
    assert(findRootLayout(&layout, &why));
    assert(layout.userdataFirst == gExpectedStart && layout.userdataLast == expectedLast);
    assert(layout.manifestStatus == 0 && layout.windows == 2);
    assert(!strcmp(layout.window[0].name, "OS") && !strcmp(layout.window[1].name, "SystemOS"));
    assert(layout.window[0].size == 9537847296ULL && layout.window[1].size == 6012534784ULL);
    // Valid CRC but duplicate label: refuse even when windows do not overlap.
    gPrimary = candidate;
    auto *entry = gPrimary.data() + 8192 + 96 * 128;
    memset(entry + 56, 0, 72);
    const char label[] = "unixnu";
    for (unsigned i = 0; i < sizeof(label); ++i) entry[56 + i * 2] = label[i];
    rehash();
    assert(!parsed());
    gPrimary = candidate;
    // A valid-CRC overlap with rddata is rejected before root media access.
    put64(gPrimary.data() + 8192 + 97 * 128 + 40, 62456827);
    rehash();
    assert(!parsed());
    gPrimary = candidate;
    gPrimary[4096 + 16] ^= 1;
    assert(!parsed());
    gPrimary = candidate;
    // Correctly hashed manifest whose extent exceeds unixnu is rejected.
    put64(gManifest.data() + 16, (expectedLast - gExpectedStart + 1) * 4096ULL + 4096);
    SHA256(gManifest.data(), 4064, gManifest.data() + 4064);
    uint32_t status = 0;
    assert(parsed(&status) && status == 4);
    puts("PASS: captured Sony GPT128/slot98, D27 windows; no userdata fallback; duplicate, overlap, CRC and oversized image refused");
}
