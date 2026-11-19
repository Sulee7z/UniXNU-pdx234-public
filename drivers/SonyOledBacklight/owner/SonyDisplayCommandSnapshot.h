// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include "SonyDisplayCommandOwner.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct SonyDisplayOwnerMappings {
    // Pre-existing boot-long device-memory mappings, not created by this unit.
    volatile const uint32_t *dsi[2], *intf[2], *mdss;
    uint64_t dsi_physical[2], intf_physical[2], mdss_physical;
    uint32_t dsi_bytes[2], intf_bytes[2], mdss_bytes;
    void *physical_owner;
    bool (*physical_access_held)(void *);
} SonyDisplayOwnerMappings;
bool native_sony_display_command_snapshot(void *, SonyDisplaySnapshot *);
#ifdef __cplusplus
}
#endif
