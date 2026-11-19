// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "Resources069.h"
#include <string.h>
// Exact Sony67.2A. GCC offset maps and DISPCC branches are indexed in
// display-reference-001; DT places DISPCC GDSCRs at af09000/af0b000. GDSC
// supports-cfg-gdscr polls +4 POWER_UP_COMPLETE(bit16). Never toggle a GDSC.
static const uint32_t gcc_regs[]={0x27004,0x27018,0x2700c};
static const uint32_t disp_regs[]={0xc004,0x80a4,0x800c,0x8018,0x8028,0x802c,0x8030,0x8034,0x8038,0x803c,0x8004,0x8008,0x8024};
static const uint32_t gdsc_cfg_regs[]={0x9004,0xb004};
static uint32_t readr(D69Resources *r,unsigned region,uint32_t reg){return r->io.read(r->io.context,region,reg);}
static void writer(D69Resources *r,unsigned region,uint32_t reg,uint32_t value){r->io.write(r->io.context,region,reg,value);}
int d69_resources_init(D69Resources *r,const D69Io *io,const D69SharedPower *power,const D69VoteSpec votes[D69Rails]){
    if(!r||!io||!power||!votes||!io->read||!io->write||!io->delay_us||!io->now_us||!io->config_lock||!io->config_unlock||
       power->abi_version!=1||power->bytes!=sizeof(*power)||!power->vote||!power->release||!power->held)return D69Argument;
    memset(r,0,sizeof(*r));r->io=*io;r->provider=*power;memcpy(r->votes,votes,sizeof(r->votes));r->ready=true;return D69OK;
}
static int branch(D69Resources *r,unsigned region,uint32_t reg,uint32_t *old,bool delay_only,bool skip){
    *old=readr(r,region,reg);if(*old==UINT32_MAX)return D69Resource;
    writer(r,region,reg,*old|1);
    // Qualcomm clk_branch_wait(): DELAY waits10us; SKIP does not poll. VOTED
    // branches poll on enable as ordinary branches do. CLK_OFF clear is the
    // conservative source-qualified ON test (never a writable status bit).
    if(skip)return D69OK;
    if(delay_only){r->io.delay_us(r->io.context,10);return D69OK;}
    const uint64_t deadline=r->io.now_us(r->io.context)+200;
    for(;;){
        const uint32_t state=readr(r,region,reg);
        if(state==UINT32_MAX)return D69Resource;
        const uint32_t halt_state=state&(UINT32_C(0x80000000)|UINT32_C(0x70000000));
        const bool on=!(state&UINT32_C(0x80000000))||halt_state==UINT32_C(0x20000000);
        if(on)return D69OK;
        if(r->io.now_us(r->io.context)>=deadline)return D69Timeout;
        r->io.delay_us(r->io.context,1);
    }
}
int d69_resources_hold(D69Resources *r){
    if(!r||!r->ready)return D69Resource;if(r->pinned)return D69Poisoned;
    if(r->clocks_on){if(d69_resources_held(r))return D69OK;r->pinned=true;r->last_error=D69Epoch;return D69Poisoned;}
    if(r->voted)return D69Busy;
    const int result=r->provider.vote(r->provider.context,"sony-display069",r->votes,D69Rails,&r->token);
    if(result){r->pinned=true;r->last_error=result;return D69Poisoned;}
    r->voted=true;if(!r->provider.held(r->provider.context,r->token)){r->pinned=true;r->last_error=D69Epoch;return D69Poisoned;}
    // Shared power is acquired BEFORE the first GCC/dispcc/MDSS access. The
    // board native wrapper maps only actual DT regions, no secure aliases.
    for(unsigned i=0;i<3;++i){const int error=branch(r,D69Gcc,gcc_regs[i],&r->original_gcc[i],i!=2,i==2);
        if(error){r->pinned=true;r->last_error=error;return D69Poisoned;}}
    int error=r->io.config_lock(r->io.context);
    if(error){r->pinned=true;r->last_error=error;return D69Poisoned;}
    // Only this source-defined non-GDSC AHB branch is touched before the
    // read-only power-domain gate. Do not access MDSS/DSI clocks if firmware
    // handed us a collapsed/unknown domain state.
    error=branch(r,D69Dispcc,disp_regs[0],&r->original_dispcc[0],false,false);
    if(!error){for(unsigned i=0;i<2;++i){
        r->gdsc_cfg[i]=readr(r,D69Dispcc,gdsc_cfg_regs[i]);
        if(r->gdsc_cfg[i]==UINT32_MAX||!(r->gdsc_cfg[i]&(1u<<16))){error=D69Resource;break;}
    }}
    for(unsigned i=1;!error&&i<13;++i)error=branch(r,D69Dispcc,disp_regs[i],&r->original_dispcc[i],false,false);
    r->io.config_unlock(r->io.context);
    if(error){r->pinned=true;r->last_error=error;return D69Poisoned;}
    r->clocks_on=true;return D69OK;
}
bool d69_resources_held(const D69Resources *r){return r&&r->ready&&r->voted&&r->clocks_on&&r->provider.held(r->provider.context,r->token);}
int d69_resources_release(D69Resources *r){
    if(!r||!r->voted)return D69Resource;if(r->pinned)return D69Poisoned;
    if(!r->provider.held(r->provider.context,r->token)){r->pinned=true;r->last_error=D69Epoch;return D69Poisoned;}
    // Owned board keeps original scanout rails/branches alive for the entire
    // display lifetime; per-transaction release does not turn off the panel.
    // stop-lifecycle needs an explicit dedicated teardown before provider release.
    return D69OK;
}
uint32_t d69_vsync_rate(D69Resources *r,uint32_t xo_hz){
    if(!d69_resources_held(r)||!xo_hz)return 0;
    // DISPCC VSYNC RCG0x80f0 parentmap0 has BI_TCXO select0, no M/N. HID+1/2
    // divider per Qualcomm clk-rcg2. Reject an unknown parent instead of19.2MHz.
    const uint32_t cfg=readr(r,D69Dispcc,0x80f4),command=readr(r,D69Dispcc,0x80f0);
    if(cfg==UINT32_MAX||command==UINT32_MAX||(cfg&0x700)!=0||(cfg&0x3000))return 0;
    return (uint32_t)((uint64_t)xo_hz*2/((cfg&31)+1));
}
