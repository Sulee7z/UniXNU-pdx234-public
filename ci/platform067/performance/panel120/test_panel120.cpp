// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "SonyPanel120.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#define CHECK(x) do{if(!(x)){std::fprintf(stderr,"%d: %s\n",__LINE__,#x);std::abort();}}while(0)
static unsigned tests;
static SonyPanel120Snapshot fixture(unsigned id=1) {
    const auto *f=sony_panel120_mode(id);CHECK(f);
    return {12,SonyPanel120RequiredQualification,id,f->width_per_link*f->links,f->height,
            {f->bit_clock_hz,f->bit_clock_hz},f->mdp_transfer_us,0};
}
static unsigned check_packets(const uint8_t *raw,size_t bytes,unsigned full_width,unsigned height) {
    size_t at=0;unsigned packets=0;
    while(at<bytes) {
        CHECK(bytes-at>=7);
        const unsigned size=(unsigned(raw[at+5])<<8)|raw[at+6];
        CHECK(size>0 && size<=bytes-at-7 && raw[at+1]==1 && raw[at+2]==0 && raw[at+3]==0);
        if(packets==1)CHECK(size==3 && raw[at+7]==0x60 && raw[at+8]==(full_width==1096?4:0) && raw[at+9]==0);
        if(packets==3)CHECK(size==5 && raw[at+7]==0x2a &&
                           ((unsigned(raw[at+10])<<8)|raw[at+11])==full_width-1);
        if(packets==4)CHECK(size==5 && raw[at+7]==0x2b &&
                           ((unsigned(raw[at+10])<<8)|raw[at+11])==height-1);
        if(packets==6)CHECK(raw[at]==5 && size==1 && raw[at+7]==0x29);
        at+=7+size;++packets;
    }
    return packets;
}
int main() {
    SonyPanel120Plan plan={};auto in=fixture();
    CHECK(native_sony_panel120_prepare(nullptr,0,&plan)==SonyPanel120Disabled);++tests;
    CHECK(native_sony_panel120_prepare(&in,2,&plan)==SonyPanel120Argument);++tests;
    CHECK(native_sony_panel120_prepare(nullptr,1,&plan)==SonyPanel120Argument);++tests;
    CHECK(native_sony_panel120_prepare(&in,1,nullptr)==SonyPanel120Argument);++tests;
    for(unsigned bit=0;bit<11;++bit) {
        auto bad=in;bad.qualification^=1u<<bit;std::memset(&plan,0xff,sizeof(plan));
        CHECK(native_sony_panel120_prepare(&bad,1,&plan)==SonyPanel120UnqualifiedOwner);
        CHECK(plan.owner_epoch==0 && !plan.hs_switch && !plan.executable_backend_bound);++tests;
    }
    auto bad=in;bad.owner_epoch=0;CHECK(native_sony_panel120_prepare(&bad,1,&plan)==SonyPanel120UnqualifiedOwner);++tests;
    bad=in;bad.reserved=1;CHECK(native_sony_panel120_prepare(&bad,1,&plan)==SonyPanel120UnqualifiedOwner);++tests;
    bad=in;bad.current_mode=4;CHECK(native_sony_panel120_prepare(&bad,1,&plan)==SonyPanel120UnknownInheritedMode);++tests;
    bad=in;bad.gop_width=1096;CHECK(native_sony_panel120_prepare(&bad,1,&plan)==SonyPanel120UnknownInheritedMode);++tests;
    bad=in;bad.bit_clock_hz[1]=1000000000;CHECK(native_sony_panel120_prepare(&bad,1,&plan)==SonyPanel120UnknownInheritedMode);++tests;
    bad=in;bad.mdp_transfer_us=7680;CHECK(native_sony_panel120_prepare(&bad,1,&plan)==SonyPanel120UnknownInheritedMode);++tests;
    for(unsigned id=0;id<2;++id) {
        in=fixture(id);CHECK(native_sony_panel120_prepare(&in,1,&plan)==SonyPanel120PlanReady);
        CHECK(plan.from_mode==id && plan.to_mode==id+2 && plan.target_hz==120);
        CHECK(plan.mdp_transfer_us==7680 && plan.update_mdp_budget==(id==1));
        CHECK(plan.preserve_bit_clock && plan.preserve_phy && plan.preserve_dsc_and_pps);
        CHECK(plan.host_timing_update_required && plan.synchronized_dual_host && plan.external_te_proof_required);
        CHECK(plan.executable_backend_bound==0 && plan.hs_switch_bytes==72 && plan.packet_count==7);
        CHECK(check_packets(plan.hs_switch,plan.hs_switch_bytes,in.gop_width,in.gop_height)==7);++tests;
    }
    for(unsigned id=2;id<4;++id) {
        in=fixture(id);CHECK(native_sony_panel120_prepare(&in,1,&plan)==SonyPanel120AlreadyRequestedMode);
        CHECK(!plan.hs_switch);++tests;
    }
    CHECK(!sony_panel120_mode(UINT32_MAX));++tests;
    in=fixture();CHECK(native_sony_panel120_prepare(&in,1,&plan)==SonyPanel120PlanReady);
    SonyPanel120TeSample te={plan.owner_epoch,1000000,{120,120},{8333,8333},{8334,8334},1,1,1,1};
    CHECK(sony_panel120_verify_external_te(&plan,&te)==SonyPanel120Sample120);++tests;
    for(unsigned bit=0;bit<4;++bit) {
        auto x=te;uint8_t *flags=&x.external_source_verified;flags[bit]=0;
        CHECK(sony_panel120_verify_external_te(&plan,&x)==SonyPanel120Unmeasured);++tests;
    }
    auto x=te;x.owner_epoch++;CHECK(sony_panel120_verify_external_te(&plan,&x)==SonyPanel120Unmeasured);++tests;
    x=te;x.elapsed_us=999999;CHECK(sony_panel120_verify_external_te(&plan,&x)==SonyPanel120Unmeasured);++tests;
    x=te;x.elapsed_us=UINT64_MAX;CHECK(sony_panel120_verify_external_te(&plan,&x)==SonyPanel120Unmeasured);++tests;
    x=te;x.external_te_events[1]=60;x.min_period_us[1]=16666;x.max_period_us[1]=16667;
    CHECK(sony_panel120_verify_external_te(&plan,&x)==SonyPanel120Not120);++tests;
    x=te;x.external_te_events[0]=0;CHECK(sony_panel120_verify_external_te(&plan,&x)==SonyPanel120Not120);++tests;
    x=te;x.min_period_us[0]=0;CHECK(sony_panel120_verify_external_te(&plan,&x)==SonyPanel120Not120);++tests;
    x=te;x.max_period_us[0]=17000;CHECK(sony_panel120_verify_external_te(&plan,&x)==SonyPanel120Not120);++tests;
    x=te;x.min_period_us[0]=8500;CHECK(sony_panel120_verify_external_te(&plan,&x)==SonyPanel120Not120);++tests;
    x=te;x.external_te_events[0]=UINT32_MAX;CHECK(sony_panel120_verify_external_te(&plan,&x)==SonyPanel120Not120);++tests;
    CHECK(sony_panel120_verify_external_te(nullptr,&te)==SonyPanel120Argument);++tests;
    CHECK(sony_panel120_verify_external_te(&plan,nullptr)==SonyPanel120Argument);++tests;
    std::printf("PASS %u pure panel preflight/packet/dual-TE checks; no hardware backend or MMIO\n",tests);
}
