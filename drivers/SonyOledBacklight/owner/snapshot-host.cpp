// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "SonyDisplayCommandSnapshot.h"
#include <cassert>
#include <cstdio>
#include <sys/mman.h>
#include <unistd.h>

static bool accessHeld;
static bool held(void *) {return accessHeld;}
int main() {
    const size_t page=(size_t)sysconf(_SC_PAGESIZE);
    auto noAccess=static_cast<uint32_t *>(mmap(nullptr,page,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0));
    assert(noAccess!=MAP_FAILED);
    SonyDisplayOwnerMappings maps={};maps.physical_access_held=held;
    maps.dsi[0]=maps.dsi[1]=maps.intf[0]=maps.intf[1]=maps.mdss=noAccess;
    SonyDisplaySnapshot out={};
    assert(!native_sony_display_command_snapshot(&maps,&out));
    accessHeld=true;
    assert(!native_sony_display_command_snapshot(&maps,&out)); // invalid metadata, zero reads
    alignas(8) uint32_t dsi[2][0x1000/4]={},intf[2][0x300/4]={},mdss[0x1000/4]={};
    maps.mdss=mdss;maps.mdss_physical=0xae00000;maps.mdss_bytes=sizeof(mdss);
    for(unsigned h=0;h<2;++h) {
        maps.dsi[h]=dsi[h];maps.dsi_physical[h]=SONY_DSI0_BASE+h*0x2000;maps.dsi_bytes[h]=0x1000;
        maps.intf[h]=intf[h];maps.intf_physical[h]=0xae36000+h*0x1000;maps.intf_bytes[h]=0x300;
        for(unsigned f=0;f<OwnerFieldCount;++f)dsi[h][sony_display_owner_host_register(f)/4]=f+0x100*h;
        intf[h][0x2b4/4]=h+0x123456;
    }
    mdss[0x10/4]=0x45;
    assert(native_sony_display_command_snapshot(&maps,&out));
    for(unsigned h=0;h<2;++h) {
        for(unsigned f=0;f<OwnerFieldCount;++f)assert(out.host[h][f]==f+0x100*h);
        assert(out.autorefresh[h]==h+0x123456);
    }
    assert(out.mdss_interrupt==0x45);
    maps.intf[1]=noAccess;maps.intf_physical[1]++;
    assert(!native_sony_display_command_snapshot(&maps,&out)); // metadata checked before all registers
    assert(!munmap(noAccess,page));
    puts("PASS actual snapshot helper: no hold/invalid metadata->zero reads; exact documented DSI/INTF/MDSS reads");
}
