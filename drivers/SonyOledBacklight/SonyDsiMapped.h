// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include "SonyOledBacklight.h"
#ifdef __cplusplus
extern "C" {
#endif
// Boot-long mappings created and owned by the display driver with device-memory
// attributes. No mapping, clock vote, PMIC or PHY initialization is guessed here.
typedef struct SonyDsiMappedOwner {
    volatile uint32_t *host[2];
    uint64_t physical[2];
    uint32_t bytes[2];
    void *owner;
    int (*acquire)(void *, uint64_t *epoch);
    bool (*owned)(void *, uint64_t epoch);
    void (*release)(void *, uint64_t epoch);
} SonyDsiMappedOwner;
int native_sony_oled_bind_mapped(const SonyDsiMappedOwner *, const SonyDsiQualification *);
#ifdef __cplusplus
}
#endif
