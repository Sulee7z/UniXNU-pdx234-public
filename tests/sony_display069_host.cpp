// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "Display069.h"
#include "Resources069.h"
#include "SonyDisplay069.generated.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <map>
#include <vector>
struct Model {
    std::map<uint64_t,uint32_t> regs;
    struct Write {unsigned region;uint32_t offset,value;};std::vector<Write> writes;
    uint64_t time=0,next_te=16667,mdpBusyUntil=0;uint32_t hz=60;
    bool held=false,resourceFail=false,releaseFail=false,timeout=false,controllerError=false,noTe=false,configLockFail=false;
    uint64_t teOffset[2]={};unsigned noTeMask=0;
    unsigned configLocks=0,configUnlocks=0;
    uint32_t fifo[2][6]={},words[2]={},packets[2]={};unsigned order=0;
    uint32_t read(unsigned r,uint32_t o){
        if((r==D69Dsi0||r==D69Dsi1)&&o==8&&time<mdpBusyUntil)return regs[(uint64_t)r<<32|o]|(1u<<2);
        return regs[(uint64_t)r<<32|o];
    }
    void advance(unsigned us){
        const uint64_t target=time+us;
        while(!noTe&&next_te<=target){
            for(unsigned h=0;h<2;++h){if(noTeMask&(1u<<h))continue;const uint64_t ts=next_te*192/10+teOffset[h];regs[(uint64_t)D69Mdss<<32|kD69_intf[h]+0x214]=(uint32_t)ts;regs[(uint64_t)D69Mdss<<32|kD69_intf[h]+0x218]=(uint32_t)(ts>>32);}
            next_te+=1000000/hz;
        }
        time=target;
    }
};
static uint32_t read(void *p,unsigned r,uint32_t o){return static_cast<Model *>(p)->read(r,o);}
static void write(void *p,unsigned r,uint32_t o,uint32_t v){
    auto m=static_cast<Model *>(p);m->writes.push_back({r,o,v});
    if(r==D69Dsi0||r==D69Dsi1){assert(m->held);unsigned h=r-D69Dsi0;
        if(o==0x1ec&&v)m->words[h]=0;
        if(o==4&&(v&(1u<<2))&&m->mdpBusyUntil==0)m->mdpBusyUntil=m->time+16300;
        if(o==0x17c){assert(m->words[h]<6);m->fifo[h][m->words[h]++]=v;}
        if(o==0x110){m->regs[(uint64_t)r<<32|o]=(m->read(r,o)&0x55115505&~v)|(v&0xaa22aa0a);return;}
        if(o==0x90){
            assert(m->words[0]&&m->words[1]);assert(h==(m->order%2?0:1));++m->order;++m->packets[h];
            if(!m->timeout)m->regs[(uint64_t)r<<32|0x110]|=1;else m->regs[(uint64_t)r<<32|8]=2;
            if(m->controllerError)m->regs[(uint64_t)r<<32|0x110]|=1u<<24;
            if((m->fifo[h][0]&0x3f0000)==0x50000&&(m->fifo[h][0]&255)==0x29){m->hz=120;m->next_te=m->time+8333;}
        }
    }
    m->regs[(uint64_t)r<<32|o]=v;
}
static uint64_t now(void *p){return static_cast<Model *>(p)->time;}
static void delay(void *p,uint32_t us){static_cast<Model *>(p)->advance(us);}
static int hold(void *p){auto m=static_cast<Model *>(p);if(m->resourceFail)return -1;assert(!m->held);m->held=true;return 0;}
static int release(void *p){auto m=static_cast<Model *>(p);if(m->releaseFail)return -1;assert(m->held);m->held=false;return 0;}
static bool held(void *p){return static_cast<Model *>(p)->held;}
static void critical(void *,bool){}
static int configLock(void *p){auto m=static_cast<Model *>(p);if(m->configLockFail)return -1;++m->configLocks;return 0;}
static void configUnlock(void *p){++static_cast<Model *>(p)->configUnlocks;}
struct ResourceModel {Model io;bool voteHeld=false;int voteError=0;unsigned votes=0;};
static int powerVote(void *p,const char *,const D69VoteSpec *,unsigned count,uint64_t *token){
    auto r=static_cast<ResourceModel *>(p);assert(count==D69Rails);++r->votes;if(r->voteError)return r->voteError;r->voteHeld=true;*token=0x69;return 0;
}
static int powerRelease(void *p,uint64_t token){auto r=static_cast<ResourceModel *>(p);assert(token==0x69);r->voteHeld=false;return 0;}
static bool powerHeld(void *p,uint64_t token){auto r=static_cast<ResourceModel *>(p);return token==0x69&&r->voteHeld;}
static void resourceTests(){
    auto init=[](ResourceModel &r,D69Resources &resources){
        r.io.regs[(uint64_t)D69Dispcc<<32|0x9004]=1u<<16;
        r.io.regs[(uint64_t)D69Dispcc<<32|0xb004]=1u<<16;
        D69Io io={&r.io,read,write,now,delay,hold,release,held,critical,configLock,configUnlock};
        D69SharedPower power={1,sizeof(D69SharedPower),&r,powerVote,powerRelease,powerHeld};
        assert(d69_resources_init(&resources,&io,&power,kD69Votes)==D69OK);
    };
    ResourceModel ok;D69Resources heldResources;init(ok,heldResources);
    assert(d69_resources_hold(&heldResources)==D69OK&&d69_resources_held(&heldResources));
    assert(ok.votes==1&&ok.io.configLocks==1&&ok.io.configUnlocks==1);
    assert(d69_resources_hold(&heldResources)==D69OK&&ok.votes==1);
    assert(d69_resources_release(&heldResources)==D69OK&&ok.votes==1);

    ResourceModel uncertain;uncertain.voteError=-5;D69Resources poisoned;init(uncertain,poisoned);
    assert(d69_resources_hold(&poisoned)==D69Poisoned&&poisoned.pinned&&poisoned.last_error==-5);
    assert(d69_resources_hold(&poisoned)==D69Poisoned&&uncertain.votes==1);

    ResourceModel badBranch;D69Resources branchFailure;init(badBranch,branchFailure);
    badBranch.io.regs[(uint64_t)D69Dispcc<<32|0x8004]=UINT32_MAX;
    assert(d69_resources_hold(&branchFailure)==D69Poisoned&&branchFailure.pinned);
    assert(badBranch.io.configLocks==1&&badBranch.io.configUnlocks==1);
    const unsigned writes=badBranch.io.writes.size();
    assert(d69_resources_hold(&branchFailure)==D69Poisoned&&badBranch.votes==1&&badBranch.io.writes.size()==writes);

    ResourceModel collapsed;D69Resources gdscOff;init(collapsed,gdscOff);
    collapsed.io.regs[(uint64_t)D69Dispcc<<32|0xb004]=0;
    assert(d69_resources_hold(&gdscOff)==D69Poisoned&&gdscOff.pinned&&gdscOff.last_error==D69Resource);
    for(const auto &w:collapsed.io.writes)assert(w.region!=D69Mdss&&w.region!=D69Dsi0&&w.region!=D69Dsi1);
    assert(collapsed.io.writes.size()==4&&collapsed.io.writes.back().offset==0xc004);

    ResourceModel lockFailure;D69Resources lockPoison;init(lockFailure,lockPoison);lockFailure.io.configLockFail=true;
    assert(d69_resources_hold(&lockPoison)==D69Poisoned&&lockPoison.pinned&&lockPoison.last_error==-1);
    assert(d69_resources_hold(&lockPoison)==D69Poisoned&&lockFailure.votes==1);
}
static void setup(Model &m,D69Display &s){
    D69Io io={&m,read,write,now,delay,hold,release,held,critical,configLock,configUnlock};D69Board b={};
    memcpy(b.ctl,kD69_ctl,sizeof b.ctl);memcpy(b.dsc,kD69_dsc,sizeof b.dsc);memcpy(b.dsc_enc,kD69_dsc_enc,sizeof b.dsc_enc);memcpy(b.pp,kD69_pp,sizeof b.pp);memcpy(b.intf,kD69_intf,sizeof b.intf);
    b.width=1644;b.height=3840;b.vsync_hz=19200000;b.timestamp_hz=19200000;b.pll_ref_hz=19200000;b.bit_clock_hz=1191321360;
    b.mdp_budget_60_us=15300;b.mdp_budget_120_us=7680;b.mdp_idle_timeout_us=200000;memcpy(b.phy,kD69Phy,sizeof b.phy);
    assert(!d69_init(&s,&io,&b));
    auto set=[&](unsigned r,uint32_t o,uint32_t v){m.regs[(uint64_t)r<<32|o]=v;};
    set(D69Mdss,b.ctl[2]+0xf4,6);set(D69Mdss,b.ctl[2]+0xe8,3);set(D69Mdss,b.ctl[2]+0x14,1u<<17);
    for(unsigned h=0;h<2;++h){set(D69Dsi0+h,0,0x10040000);set(D69Dsi0+h,4,0x1f5);set(D69Dsi0+h,0xa8,0x1f1f);set(D69Dsi0+h,0x5c,3840u<<16|137);
        set(D69Dsi0+h,0x84,0x80000004);
        set(D69Mdss,b.intf[h]+0x288,1u<<20|1u<<19|79);set(D69Mdss,b.intf[h]+0x284,1);set(D69Mdss,b.intf[h]+0x2b4,0x80000001);
        for(unsigned i=0;i<14;++i)set(D69Phy0+h,0xb4+4*i,kD69Phy[i]);
        set(D69Pll0+h,0x1b0,1);set(D69Pll0+h,0xe0,31);set(D69Pll0+h,0xe4,0x92);set(D69Pll0+h,0xe8,0x18);set(D69Pll0+h,0xec,0);
        set(D69Phy0+h,0x10,1);
        set(D69Mdss,b.dsc[h]+b.dsc_enc[h]+0x30,8|128u<<10|1u<<20);
        set(D69Mdss,b.dsc[h]+b.dsc_enc[h]+0x34,822|3840u<<16);set(D69Mdss,b.dsc[h]+b.dsc_enc[h]+0x38,822|32u<<16);
    }
    assert(!d69_probe(&s)&&!m.held&&s.ready);
}
static int finish(Model &m,D69Display &s,unsigned max=2000){
    int result=D69Pending;
    for(unsigned i=0;i<max&&result==D69Pending;++i){m.advance(500);result=d69_step(&s);}
    return result;
}
int main(){
    resourceTests();
    uint32_t words[5];unsigned bytes;D69Packet p={};p.type=0x39;p.length=3;p.data[0]=0x51;p.data[1]=1;p.data[2]=0x23;
    assert(!d69_pack(&p,words,&bytes)&&bytes==8&&words[0]==0xc0390003&&words[1]==0xff230151);
    for(unsigned i=0;i<4096;++i)assert(d69_sdr_dbv(i)<=2047);
    Model m;D69Display s;setup(m,s);
    assert(!d69_producer_enter(&s));assert(d69_brightness(&s,3000)==D69Busy);d69_producer_leave(&s);
    assert(d69_brightness(&s,1024)==D69Pending);assert(finish(m,s)==0&&s.transmitted==1024&&s.current_verified==UINT32_MAX);
    assert(m.packets[0]==1&&m.packets[1]==1&&!m.held);
    assert(s.tx.mdp_over_budget);
    assert(m.read(D69Mdss,kD69_intf[0]+0x2b4)==0x80000001);
    Model fps;D69Display f;setup(fps,f);assert(d69_switch120(&f)==D69Pending);
    const int fps_result=finish(fps,f,6000);
    if(fps_result||f.observed_hz!=120)std::fprintf(stderr,"FPSresult%d state%u index%u sent%u hz%u/%u events%u/%u periods%llu/%llu time%llu\n",fps_result,f.tx.state,f.tx.index,f.packets_sent,f.observed_hz,fps.hz,f.tx.te_events[0],f.tx.te_events[1],(unsigned long long)f.tx.te_period_min[0],(unsigned long long)f.tx.te_period_max[0],(unsigned long long)fps.time);
    assert(fps_result==0&&f.observed_hz==120&&!fps.held&&f.packets_sent==7);
    assert(fps.packets[0]==7&&fps.packets[1]==7);
    // DistinctCTLandDSCroute chosen byreadback; never fixedCTL0 write.
    for(auto w:fps.writes)if(w.region==D69Mdss)assert(w.offset!=kD69_ctl[0]+0x1c);
    // Both independent physical timestamp registers must change. No fabricated
    // inter-link phase constraint: Sony DT only specifies one external source.
    Model lost;D69Display lostTe;setup(lost,lostTe);lost.noTeMask=2;
    assert(d69_switch120(&lostTe)==D69Pending);assert(finish(lost,lostTe,6000)==D69Te&&!lostTe.poisoned&&!lost.held&&lostTe.packets_sent==0);
    Model internal;D69Display internalTe;setup(internal,internalTe);
    internal.regs[(uint64_t)D69Dsi1<<32|0x84]&=~(1u<<31);
    assert(d69_switch120(&internalTe)==D69Te&&!internalTe.poisoned&&!internal.held);
    Model bad;D69Display t;setup(bad,t);bad.timeout=true;assert(d69_brightness(&t,1)==D69Pending);
    assert(finish(bad,t)==D69Timeout&&t.poisoned&&bad.held);const auto count=bad.writes.size();assert(d69_step(&t)==D69Poisoned&&bad.writes.size()==count);
    Model end;D69Display e;setup(end,e);end.releaseFail=true;assert(d69_brightness(&e,2)==D69Pending);
    assert(finish(end,e)==D69Restore&&e.poisoned&&e.transmitted==0&&end.held);
    Model resource;D69Display r;setup(resource,r);resource.resourceFail=true;const auto old=resource.writes.size();
    assert(d69_brightness(&r,20)==D69Resource&&resource.writes.size()==old);
    puts("PASS Sony069engine/resources-once/poisoned-partial-vote/branch-failure/DTS-MDP-budget/51/7HS/dualTE; hardwareunverified");
}
