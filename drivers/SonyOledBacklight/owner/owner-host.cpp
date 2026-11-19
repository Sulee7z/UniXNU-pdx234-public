// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "SonyDisplayCommandOwner.h"
#include <atomic>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

struct Physical {
    SonyDisplaySnapshot value={};
    std::atomic<bool> hold{false};
    bool available=true,lost=false,failSnapshot=false;
    unsigned heldCalls=0,drops=0,snapshots=0;
    uint64_t token=0;
};
static int hold(void *context,uint64_t *token) {
    auto p=static_cast<Physical *>(context);
    if(!p->available || p->hold.exchange(true))return 1;
    *token=++p->token;return 0;
}
static bool held(void *context,uint64_t token) {
    auto p=static_cast<Physical *>(context);p->heldCalls++;
    return p->hold && !p->lost && token==p->token;
}
static void drop(void *context,uint64_t token) {
    auto p=static_cast<Physical *>(context);assert(p->hold && token==p->token);p->drops++;p->hold=false;
}
static bool snapshot(void *context,SonyDisplaySnapshot *s) {
    auto p=static_cast<Physical *>(context);assert(p->hold);p->snapshots++;*s=p->value;return !p->failSnapshot;
}
static void setup(Physical &p,SonyDisplayCommandOwner &owner) {
    for(unsigned h=0;h<2;++h) {
        auto r=p.value.host[h];r[OwnerVersion]=0x20070000;r[OwnerControl]=0x1f5;
        r[OwnerStreamTotal]=0xf000112;r[OwnerLaneStatus]=0x1f1f;
        r[OwnerClockControl]=0x3b;r[OwnerClockStatus]=0x155;
    }
    SonyDisplayPhysicalAccess access={&p,hold,held,drop,snapshot};assert(!sony_display_owner_init(&owner,&access));
}
int main() {
    Physical p;SonyDisplayCommandOwner owner;setup(p,owner);
    assert(sony_display_owner_snapshot_check(&p.value)==0);
    assert(!sony_display_owner_start(&owner) && p.snapshots==2 && !p.hold);
    assert(!sony_display_owner_producer_enter(&owner));uint64_t epoch=0;
    assert(sony_display_command_acquire(&owner,&epoch)==SonyOwnerBusy && !p.hold);
    assert(sony_display_owner_stop(&owner)==SonyOwnerBusy);
    sony_display_owner_producer_leave(&owner);
    assert(!sony_display_command_acquire(&owner,&epoch) && p.hold);
    assert(sony_display_command_owned(&owner,epoch));
    assert(sony_display_owner_producer_enter(&owner)==SonyOwnerBusy);
    assert(sony_display_owner_stop(&owner)==SonyOwnerBusy);
    const auto drops=p.drops;sony_display_command_release(&owner,epoch+1);assert(p.drops==drops);
    sony_display_command_release(&owner,epoch);assert(!p.hold && !sony_display_command_owned(&owner,epoch));
    assert(!sony_display_owner_stop(&owner));
    assert(sony_display_command_acquire(&owner,&epoch)==SonyOwnerStopped);
    assert(!sony_display_owner_start(&owner));
    // Concrete, per-register predicates all reject without any write callback.
    auto baseline=p.value;
    struct Test {unsigned field;uint32_t value;int expected;};
    const Test cases[]={
        {OwnerVersion,0,SonyOwnerBadSnapshot},
        {OwnerControl,0x1f7,SonyOwnerBadSnapshot},
        {OwnerStatus,4,SonyOwnerBusy}, {OwnerInterrupt,2,SonyOwnerIrqEnabled},
        {OwnerInterrupt,8,SonyOwnerIrqEnabled},{OwnerInterrupt,1u<<27,SonyOwnerIrqEnabled},
        {OwnerLaneStatus,0xf1f,SonyOwnerUlps},{OwnerLaneStatus,0x1f1e,SonyOwnerUlps},
        {OwnerLaneControl,1,SonyOwnerUlps},{OwnerClockStatus,0x55,SonyOwnerClock},
        {OwnerClockControl,0,SonyOwnerClock},{OwnerAckError,1,SonyOwnerBadSnapshot},
        {OwnerSchedule,0x10000000,SonyOwnerBadSnapshot},{OwnerReadDisable,0x10,SonyOwnerBadSnapshot},
        {OwnerSecure,1,SonyOwnerBadSnapshot},{OwnerTpg,6,SonyOwnerBadSnapshot}
    };
    for(const auto &c:cases) {
        p.value=baseline;p.value.host[1][c.field]=c.value;
        assert(sony_display_command_acquire(&owner,&epoch)==c.expected && !p.hold);
    }
    p.value=baseline;p.value.autorefresh[0]=0x80000001;
    assert(sony_display_command_acquire(&owner,&epoch)==SonyOwnerAutoRefresh&&!p.hold);
    p.value=baseline;p.value.mdss_interrupt=0x10;
    assert(sony_display_command_acquire(&owner,&epoch)==SonyOwnerIrqEnabled&&!p.hold);
    p.value=baseline;p.value.mdss_interrupt=UINT32_MAX;
    assert(sony_display_command_acquire(&owner,&epoch)==SonyOwnerBadSnapshot&&!p.hold);
    p.value=baseline;p.value.host[0][OwnerStreamTotal]++;
    assert(sony_display_command_acquire(&owner,&epoch)==SonyOwnerChanged&&!p.hold);
    p.value=baseline;p.available=false;const auto snapshots=p.snapshots;
    assert(sony_display_command_acquire(&owner,&epoch)==SonyOwnerNoPhysicalAccess && p.snapshots==snapshots);
    p.available=true;p.failSnapshot=true;
    assert(sony_display_command_acquire(&owner,&epoch)==SonyOwnerBadSnapshot&&!p.hold);
    p.failSnapshot=false;assert(!sony_display_command_acquire(&owner,&epoch));
    p.value.host[0][OwnerLaneStatus]=0;
    sony_display_command_release(&owner,epoch);assert(p.hold && owner.last_error==SonyOwnerUlps);
    assert(sony_display_owner_stop(&owner)==SonyOwnerPoisoned);
    assert(sony_display_command_acquire(&owner,&epoch)==SonyOwnerPoisoned);
    // Concurrent presenter reservations vs lease transition. Physical calls are
    // only on the command thread; producer counters exclude it atomically.
    Physical p2;SonyDisplayCommandOwner shared;setup(p2,shared);assert(!sony_display_owner_start(&shared));
    std::atomic<bool> quit{false};std::atomic<unsigned> users{0};
    std::vector<std::thread> workers;
    for(unsigned t=0;t<4;++t)workers.emplace_back([&]{
        while(!quit.load())if(!sony_display_owner_producer_enter(&shared)) {
            users.fetch_add(1);users.fetch_sub(1);sony_display_owner_producer_leave(&shared);
        }
    });
    unsigned leases=0;
    for(unsigned i=0;i<50000;++i)if(!sony_display_command_acquire(&shared,&epoch)) {
        assert(users.load()==0 && sony_display_command_owned(&shared,epoch));leases++;
        sony_display_command_release(&shared,epoch);
    }
    quit=true;for(auto &thread:workers)thread.join();assert(!p2.hold && shared.users==0 && leases);
    puts("PASS command-owner real snapshots/ULPS/clocks/IRQ/autorefresh/epoch/poison; 50000 four-producer lease races");
}
