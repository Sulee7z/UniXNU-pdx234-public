// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "SonyDisplayCommandSnapshot.h"

extern "C" bool native_sony_display_command_snapshot(void *context,SonyDisplaySnapshot *out) {
    const auto maps=static_cast<const SonyDisplayOwnerMappings *>(context);
    if(!maps || !out || !maps->physical_access_held ||
       !maps->physical_access_held(maps->physical_owner))return false;
    if(!maps->mdss || maps->mdss_physical!=0xae00000 || maps->mdss_bytes<0x14)return false;
    for(unsigned h=0;h<2;++h) {
        if(!maps->dsi[h] || !maps->intf[h] ||
           ((uintptr_t)maps->dsi[h]&3) || ((uintptr_t)maps->intf[h]&3) ||
           maps->dsi_physical[h]!=SONY_DSI0_BASE+h*0x2000 || maps->dsi_bytes[h]!=0x1000 ||
           maps->intf_physical[h]!=0xae36000+h*0x1000 || maps->intf_bytes[h]!=0x300)return false;
    }
    if((uintptr_t)maps->mdss&3)return false;
    // Read-only callback; no register clear, clock vote, ULPS transition, GPIO,
    // PMIC, reset, GIC action or DSI command is performed by this unit.
    __asm__ volatile("dmb oshld" ::: "memory");
    for(unsigned h=0;h<2;++h) {
        for(unsigned i=0;i<OwnerFieldCount;++i)
            out->host[h][i]=maps->dsi[h][sony_display_owner_host_register(i)/4];
        // Exact OEM MDSS INTF1/2 TEAR block at INTF+0x280, AUTOREFRESH+0x34.
        out->autorefresh[h]=maps->intf[h][0x2b4/4];
    }
    out->mdss_interrupt=maps->mdss[0x10/4];
    __asm__ volatile("dmb oshld" ::: "memory");
    return maps->physical_access_held(maps->physical_owner);
}
