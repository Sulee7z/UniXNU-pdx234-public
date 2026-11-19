// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "SonyDisplayCommandOwner.h"
#include <string.h>

enum { GateStopped, GateRunning, GateDraining, GateCommand, GatePoisoned };
// gate and users form a two-word reservation protocol. Their operations must
// participate in one SC order: acquire/release alone permits the store-buffer
// outcome where the producer sees Running and the command side sees users=0.
#define ORDER __ATOMIC_SEQ_CST
static const uint16_t registers[OwnerFieldCount]={
    0x000,0x004,0x008,0x00c,0x03c,0x05c,0x068,0x084,0x0a8,0x0ac,
    0x0b4,0x0c0,0x100,0x104,0x110,0x11c,0x120,0x15c,0x12c,0x118,0x2b8,0x2cc
};
uint32_t sony_display_owner_host_register(unsigned field) {
    return field<OwnerFieldCount?registers[field]:UINT32_MAX;
}

int sony_display_owner_snapshot_check(const SonyDisplaySnapshot *s) {
    if(!s)return SonyOwnerArgument;
    if(s->mdss_interrupt==UINT32_MAX || s->autorefresh[0]==UINT32_MAX || s->autorefresh[1]==UINT32_MAX)
        return SonyOwnerBadSnapshot;
    // MDSS_HW_INTR_STATUS DSI0/DSI1: do not adopt a pending interrupt from an
    // unidentified prior owner. No status write/clear is used to make it pass.
    if(s->mdss_interrupt&0x30)return SonyOwnerIrqEnabled;
    for(unsigned h=0;h<2;++h) {
        const uint32_t *r=s->host[h];
        for(unsigned i=0;i<OwnerFieldCount;++i)if(r[i]==UINT32_MAX)return SonyOwnerBadSnapshot;
        // DT compatible "hw-v2.7" is a driver operations revision, NOT evidence
        // that HW_VERSION must read0x20070000. Record the actual nonzero version
        // at start and require it unchanged in same_config below.
        // CTRL: DSI+command engine, no video, four data lanes and clock lane.
        if(!r[OwnerVersion] ||
           (r[OwnerControl]&0x1f7)!=0x1f5 ||
           (r[OwnerControl]&0x30010000) || !r[OwnerStreamTotal])return SonyOwnerBadSnapshot;
        // OEM HAL also documents DMA_POST_START(bit3) and DYNAMIC_BLANKING(bit27)
        // enables; the common Linux mask alone is not a complete IRQ audit.
        if(r[OwnerInterrupt]&0xaa22aa0a)return SonyOwnerIrqEnabled;
        // Read-only lower-segment owner does not try to stop hardware refresh.
        // INTF1/2 TEAR_AUTOREFRESH_CONFIG.ENABLE bit31 is an independent hardware
        // command producer; a momentarily idle DSI_STATUS alone is insufficient.
        if(s->autorefresh[h]&0x80000000)return SonyOwnerAutoRefresh;
        if(r[OwnerStatus]&0x800383ff)return SonyOwnerBusy;
        if((r[OwnerLaneStatus]&0x1f1f)!=0x1f1f ||
           (r[OwnerLaneStatus]&0x30000) || (r[OwnerLaneControl]&0x001f1f1f))return SonyOwnerUlps;
        // Require inherited AON paths+explicit clock enables; dynamic gating
        // clear does not prove all clocks are physically absent. This strict
        // predicate may reject good hardware rather than enabling unknown gates.
        if((r[OwnerClockStatus]&0x155)!=0x155 || (r[OwnerClockStatus]&0x10000) ||
           (r[OwnerClockControl]&0x3b)!=0x3b || (r[OwnerClockControl]&0x400000))return SonyOwnerClock;
        if((r[OwnerAckError]&0x0193ffff) || (r[OwnerFifo]&0xcccc0480) ||
           (r[OwnerPhyError]&0x11111) || (r[OwnerTimeout]&0x111) ||
           (r[OwnerInterrupt]&0x55100005) || r[OwnerTpg] || r[OwnerSchedule] || r[OwnerWindow] ||
           (r[OwnerPhyReset]&0x1010101) || (r[OwnerSoftReset]&1) ||
           (r[OwnerReadDisable]&0x11) || r[OwnerSecure])return SonyOwnerBadSnapshot;
    }
    return SonyOwnerOK;
}

static int capture(SonyDisplayCommandOwner *s,SonyDisplaySnapshot *out) {
    if(!s->access.held(s->access.context,s->token))return SonyOwnerNoPhysicalAccess;
    return s->access.snapshot(s->access.context,out)?sony_display_owner_snapshot_check(out):SonyOwnerBadSnapshot;
}
static bool same_config(const SonyDisplaySnapshot *a,const SonyDisplaySnapshot *b) {
    const unsigned stable[]={OwnerVersion,OwnerControl,OwnerStreamTotal,OwnerDmaControl,
        OwnerTriggerControl,OwnerLaneControl,OwnerClockControl,OwnerSchedule,OwnerWindow,
        OwnerTpg,OwnerPhyReset,OwnerSoftReset,OwnerReadDisable,OwnerSecure};
    for(unsigned h=0;h<2;++h) {
        for(unsigned i=0;i<sizeof(stable)/sizeof(stable[0]);++i)
            if(a->host[h][stable[i]]!=b->host[h][stable[i]])return false;
        if(a->autorefresh[h]!=b->autorefresh[h])return false;
    }
    return true;
}
int sony_display_owner_init(SonyDisplayCommandOwner *s,const SonyDisplayPhysicalAccess *access) {
    if(!s || !access || !access->try_hold || !access->held || !access->drop || !access->snapshot)return SonyOwnerArgument;
    memset(s,0,sizeof(*s));s->access=*access;s->initialized=1;return SonyOwnerOK;
}
int sony_display_owner_start(SonyDisplayCommandOwner *s) {
    if(!s || !s->initialized)return SonyOwnerArgument;
    uint32_t expected=GateStopped;
    if(!__atomic_compare_exchange_n(&s->gate,&expected,GateDraining,false,ORDER,ORDER))return SonyOwnerBusy;
    int result=s->access.try_hold(s->access.context,&s->token);
    if(result)result=SonyOwnerNoPhysicalAccess;
    else {
        SonyDisplaySnapshot second;
        result=capture(s,&s->inherited);
        if(!result)result=capture(s,&second);
        if(!result && !same_config(&s->inherited,&second))result=SonyOwnerChanged;
        s->access.drop(s->access.context,s->token);
    }
    s->last_error=result;__atomic_store_n(&s->gate,result?GateStopped:GateRunning,ORDER);
    return result;
}
int sony_display_owner_producer_enter(SonyDisplayCommandOwner *s) {
    if(!s || !s->initialized)return SonyOwnerArgument;
    if(__atomic_load_n(&s->gate,ORDER)!=GateRunning)return SonyOwnerBusy;
    __atomic_fetch_add(&s->users,1u,ORDER);
    if(__atomic_load_n(&s->gate,ORDER)==GateRunning)return SonyOwnerOK;
    __atomic_fetch_sub(&s->users,1u,ORDER);return SonyOwnerBusy;
}
void sony_display_owner_producer_leave(SonyDisplayCommandOwner *s) {
    if(!s)return;
    uint32_t users=__atomic_load_n(&s->users,ORDER);
    while(users && !__atomic_compare_exchange_n(&s->users,&users,users-1,false,ORDER,ORDER)){}
}
int sony_display_owner_stop(SonyDisplayCommandOwner *s) {
    if(!s || !s->initialized)return SonyOwnerArgument;
    uint32_t expected=GateRunning;
    if(!__atomic_compare_exchange_n(&s->gate,&expected,GateDraining,false,ORDER,ORDER))
        return expected==GateStopped?SonyOwnerOK:expected==GatePoisoned?SonyOwnerPoisoned:SonyOwnerBusy;
    if(__atomic_load_n(&s->users,ORDER)) {
        __atomic_store_n(&s->gate,GateRunning,ORDER);return SonyOwnerBusy;
    }
    __atomic_store_n(&s->gate,GateStopped,ORDER);return SonyOwnerOK;
}
int sony_display_command_acquire(void *context,uint64_t *epoch) {
    SonyDisplayCommandOwner *s=(SonyDisplayCommandOwner *)context;
    if(!s || !epoch || !s->initialized)return SonyOwnerArgument;
    uint32_t expected=GateRunning;
    if(!__atomic_compare_exchange_n(&s->gate,&expected,GateDraining,false,ORDER,ORDER))
        return expected==GatePoisoned?SonyOwnerPoisoned:expected==GateStopped?SonyOwnerStopped:SonyOwnerBusy;
    int result=SonyOwnerBusy;
    if(__atomic_load_n(&s->users,ORDER))goto busy;
    if(s->generation==UINT64_MAX){result=SonyOwnerPoisoned;goto busy;}
    result=s->access.try_hold(s->access.context,&s->token);
    if(result){result=SonyOwnerNoPhysicalAccess;goto busy;}
    {
        SonyDisplaySnapshot first,second;
        result=capture(s,&first);
        if(!result)result=capture(s,&second);
        if(!result && (!same_config(&first,&second) || !same_config(&s->inherited,&second)))result=SonyOwnerChanged;
        if(result){s->access.drop(s->access.context,s->token);goto busy;}
    }
    *epoch=++s->generation;s->last_error=SonyOwnerOK;
    __atomic_store_n(&s->gate,GateCommand,ORDER);return SonyOwnerOK;
busy:
    s->last_error=result;__atomic_store_n(&s->gate,GateRunning,ORDER);return result;
}
bool sony_display_command_owned(void *context,uint64_t epoch) {
    SonyDisplayCommandOwner *s=(SonyDisplayCommandOwner *)context;
    return s && __atomic_load_n(&s->gate,ORDER)==GateCommand && epoch==s->generation &&
        s->access.held(s->access.context,s->token);
}
void sony_display_command_release(void *context,uint64_t epoch) {
    SonyDisplayCommandOwner *s=(SonyDisplayCommandOwner *)context;
    if(!s || epoch!=s->generation)return;
    uint32_t expected=GateCommand;
    if(!__atomic_compare_exchange_n(&s->gate,&expected,GateDraining,false,ORDER,ORDER))return;
    SonyDisplaySnapshot after;int result=capture(s,&after);
    if(!result && !same_config(&s->inherited,&after))result=SonyOwnerChanged;
    if(result){s->last_error=result;__atomic_store_n(&s->gate,GatePoisoned,ORDER);return;}
    s->access.drop(s->access.context,s->token);__atomic_store_n(&s->gate,GateRunning,ORDER);
}
void sony_display_command_poison(SonyDisplayCommandOwner *s) {
    if(s && __atomic_load_n(&s->gate,ORDER)==GateCommand)
        __atomic_store_n(&s->gate,GatePoisoned,ORDER);
}
