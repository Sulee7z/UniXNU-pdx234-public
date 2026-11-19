// SPDX-License-Identifier: BSD-2-Clause-Patent
// Sony vendor DSI embedded FIFO + shared owner. No read52 is required by OEM.
#include "Display069.h"
#include <string.h>
#define B(n) (UINT32_C(1)<<(n))
#define SC __ATOMIC_SEQ_CST
enum {Idle,Quiesce,WaitPacket,WaitDelay,VerifyTe,VerifyBefore,Poison};
enum {Closed,Running,Exclusive,Stopped};
static uint32_t rd(D69Display *s,unsigned h,uint32_t reg){return s->io.read(s->io.context,D69Dsi0+h,reg);}
static void wr(D69Display *s,unsigned h,uint32_t reg,uint32_t v){s->io.write(s->io.context,D69Dsi0+h,reg,v);}
static uint32_t md(D69Display *s,uint32_t reg){return s->io.read(s->io.context,D69Mdss,reg);}
static void mw(D69Display *s,uint32_t reg,uint32_t v){s->io.write(s->io.context,D69Mdss,reg,v);}
static uint64_t now(D69Display *s){return s->io.now_us(s->io.context);}
static uint32_t errors(D69Display *s,unsigned h){
    return (rd(s,h,0x110)&B(24))|(rd(s,h,0x68)&0x0193ffff)|(rd(s,h,0xc0)&0x111)|
        (rd(s,h,0xb4)&0x11111)|(rd(s,h,0xc)&0xcccc0480)|(rd(s,h,0x120)&B(16))|(rd(s,h,8)&B(31));
}
static bool idle_hosts(D69Display *s){return !(rd(s,0,8)&0x383ff)&&!(rd(s,1,8)&0x383ff);}
static int fail(D69Display *s,int result){
    s->last_error=result;s->failures++;if(result==D69Timeout)s->timeouts++;
    s->poisoned=1;s->tx.state=Poison;s->ready=0;
    // A timed-out command or partial DDIC transaction pins resources and owner.
    // No reset, rollback fiction, IRQ disable or re-use of an active FIFO.
    return result;
}
uint16_t d69_sdr_dbv(uint32_t level){
    if(!level)return 0;if(level>4095)level=4095;
    const uint32_t input=(level*1720+2047)/4095;
    return input<=9?4:(uint16_t)(4+(input-9)*2043/1711);
}
int d69_pack(const D69Packet *p,uint32_t words[5],unsigned *bytes){
    if(!p||!words||!bytes||p->vc||!p->length||p->length>D69MaxPacket||
       (p->type!=0x39&&p->type!=0x15&&p->type!=0x05)||
       (p->type==0x15&&p->length!=2)||(p->type==0x05&&p->length!=1))return D69Argument;
    uint8_t out[20];memset(out,0xff,sizeof(out));
    out[2]=p->type;out[3]=0x80;
    if(p->type==0x39){out[0]=p->length;out[1]=0;out[3]|=0x40;memcpy(out+4,p->data,p->length);*bytes=(p->length+7)&~3u;}
    else {out[0]=p->data[0];out[1]=p->length==2?p->data[1]:0;*bytes=4;}
    for(unsigned i=0;i<*bytes/4;++i)words[i]=out[4*i]|((uint32_t)out[4*i+1]<<8)|((uint32_t)out[4*i+2]<<16)|((uint32_t)out[4*i+3]<<24);
    return D69OK;
}
int d69_init(D69Display *s,const D69Io *io,const D69Board *board){
    if(!s||!io||!board||!io->read||!io->write||!io->now_us||!io->delay_us||!io->hold||!io->release||!io->held||!io->critical||!io->config_lock||!io->config_unlock)return D69Argument;
    if(!((board->width==1096&&board->height==2560)||(board->width==1644&&board->height==3840))||!board->vsync_hz||
       !board->mdp_budget_60_us||!board->mdp_budget_120_us||!board->mdp_idle_timeout_us||
       board->mdp_budget_60_us>board->mdp_idle_timeout_us||board->mdp_budget_120_us>board->mdp_idle_timeout_us)return D69Mode;
    memset(s,0,sizeof(*s));s->io=*io;s->board=*board;s->initialized=1;s->current_verified=UINT32_MAX;return D69OK;
}
static int resource_lock(D69Display *s){
    if(!s||!s->initialized)return D69Argument;if(s->poisoned)return D69Poisoned;
    uint32_t expected=Running;
    if(!__atomic_compare_exchange_n(&s->gate,&expected,Exclusive,false,SC,SC))return D69Busy;
    if(__atomic_load_n(&s->producers,SC)){__atomic_store_n(&s->gate,Running,SC);return D69Busy;}
    int result=s->io.hold(s->io.context);
    if(result){if(result==D69Poisoned)return fail(s,D69Poisoned);__atomic_store_n(&s->gate,Running,SC);return D69Resource;}
    if(!s->io.held(s->io.context))return fail(s,D69Resource);
    memset(&s->tx,0,sizeof(s->tx));s->tx.epoch=++s->generation;return D69OK;
}
static int unlock_unstarted(D69Display *s,int result){
    if(s->tx.timestamp_touched){
        for(unsigned h=0;h<2;++h){mw(s,s->board.intf[h]+0x210,s->tx.saved_timestamp[h]);
            if(md(s,s->board.intf[h]+0x210)!=s->tx.saved_timestamp[h])return fail(s,D69Restore);}
        s->tx.timestamp_touched=false;
    }
    const int release=s->io.release(s->io.context);if(release)return fail(s,D69Restore);
    s->tx.state=Idle;__atomic_store_n(&s->gate,Running,SC);return result;
}
// Route comes from actual CTL active masks, never fixed CTL0. DT supplies block
// locations, not current selection. All involved CTLs must be command mode.
static int route(D69Display *s){
    s->tx.ctl_mask=0;s->tx.dsc_mask=0;uint32_t covered=0;
    for(unsigned i=0;i<D69CtlCount;++i){const uint32_t base=s->board.ctl[i];
        const uint32_t active=md(s,base+0xf4);if(!(active&6))continue;
        if(active&~6u || !(md(s,base+0x14)&B(17)) || md(s,base+0x30)&1)return D69Route;
        s->tx.ctl_mask|=B(i);covered|=active;s->tx.dsc_mask|=md(s,base+0xe8);
    }
    if(covered!=6||!s->tx.ctl_mask||!s->tx.dsc_mask)return D69Route;
    if(s->tx.dsc_mask&~15u)return D69Route;
    return D69OK;
}
static int snapshot(D69Display *s){
    if(!s->io.held(s->io.context))return D69Resource;
    int result=route(s);if(result)return result;
    uint32_t broadcast_master=0;
    for(unsigned h=0;h<2;++h){
        const uint32_t version=rd(s,h,0),control=rd(s,h,4),lane=rd(s,h,0xa8);
        if(!version||version==UINT32_MAX||control==UINT32_MAX||(control&0x1f3)!=0x1f1||control&0x30010000||rd(s,h,0x2cc)&1)return D69Mode;
        if(rd(s,h,0x110)&0xaa22aa0a)return D69Controller; // no owned IRQ route yet; never disable it
        if(errors(s,h))return D69Controller;
        if((lane&0x1f00)!=0x1f00 || rd(s,h,0xac)&0x1f1f)return D69Mode;
        if(rd(s,h,0x15c)||rd(s,h,0x100)||rd(s,h,0x104))return D69Busy;
        s->tx.saved_ctrl[h]=control;s->tx.saved_clk[h]=rd(s,h,0x11c);
        s->tx.saved_dma[h]=rd(s,h,0x3c);s->tx.saved_trigger[h]=rd(s,h,0x84);
        s->tx.saved_int[h]=rd(s,h,0x110)&0xaa22aa0a;s->tx.saved_length[h]=rd(s,h,0x4c);
        if(s->tx.saved_dma[h]&B(30))broadcast_master|=B(h);
        const uint32_t in=s->board.intf[h];
        s->tx.saved_autorefresh[h]=md(s,in+0x2b4);s->tx.saved_te_enable[h]=md(s,in+0x284);
        s->tx.saved_te_config[h]=md(s,in+0x288);s->tx.saved_timestamp[h]=md(s,in+0x210);
    }
    s->tx.master=broadcast_master==2?1:0; // default DSI0 matches Sony cmd master DT order when broadcast inactive
    if(broadcast_master==3)return D69Route;
    return D69OK;
}
static int dms_readback(D69Display *s){
    unsigned dscs=0;
    for(unsigned i=0;i<D69DscCount;++i)if(s->tx.dsc_mask&B(i)){
        const uint32_t base=s->board.dsc[i]+s->board.dsc_enc[i];
        const uint32_t config=md(s,base+0x30),picture=md(s,base+0x34),slice=md(s,base+0x38);
        if((config&15)!=8||((config>>10)&0x3ff)!=128||!(config&B(20))||
           (picture>>16)!=s->board.height||(picture&65535)!=s->board.width/2||
           (slice>>16)!=32||(slice&65535)!=s->board.width/2)return D69Mode;
        ++dscs;
    }
    if(dscs!=2)return D69Mode;
    for(unsigned h=0;h<2;++h){
        for(unsigned i=0;i<14;++i)if((s->io.read(s->io.context,D69Phy0+h,0xb4+4*i)&255)!=s->board.phy[i])return D69Mode;
        // In bonded mode slave can source master's PLL. PHY_CMN_CLK_CFG1 bit2
        // selects external clock; follow that actual setting rather than assume
        // each PLL enabled. PLL fractional divider is fixed18bits in Sony4nm.
        const unsigned source=(s->io.read(s->io.context,D69Phy0+h,0x14)&4)?0:h;
        if(!(s->io.read(s->io.context,D69Pll0+source,0x1b0)&1))return D69Mode;
        const uint32_t dec=s->io.read(s->io.context,D69Pll0+source,0xe0)&255;
        const uint32_t frac=(s->io.read(s->io.context,D69Pll0+source,0xe4)&255)|
            ((s->io.read(s->io.context,D69Pll0+source,0xe8)&255)<<8)|((s->io.read(s->io.context,D69Pll0+source,0xec)&3)<<16);
        const uint32_t shift=s->io.read(s->io.context,D69Pll0+source,0x154);
        const uint32_t phy_div=s->io.read(s->io.context,D69Phy0+source,0x10)&15;
        if(shift>3||!phy_div||!s->board.pll_ref_hz)return D69Mode;
        const uint64_t bitclk=((uint64_t)s->board.pll_ref_hz*2*(((uint64_t)dec<<18)|frac)) / ((UINT64_C(1)<<18)*(1u<<shift)*phy_div);
        const uint32_t wanted=s->board.bit_clock_hz;
        if(bitclk<wanted-20000u||bitclk>wanted+20000u)return D69Mode;
        const uint32_t stream=rd(s,h,0x5c);
        // DSC/widebus changes compressed stream width; height remains exact.
        if((stream>>16)!=s->board.height||!(stream&65535))return D69Mode;
    }
    return D69OK;
}
static void quiesce(D69Display *s){
    if(!s->tx.mdp_budget)s->tx.mdp_budget=s->board.mdp_budget_60_us>s->board.mdp_budget_120_us?s->board.mdp_budget_60_us:s->board.mdp_budget_120_us;
    for(unsigned h=0;h<2;++h){const uint32_t in=s->board.intf[h];
        // Sony sde_hw_intf_setup_autorefresh_config/enable_te. Disable TE first,
        // then hardware auto-refresh, then drain existing DSI MDP commands.
        mw(s,in+0x284,0);mw(s,in+0x2b4,s->tx.saved_autorefresh[h]&~B(31));
        wr(s,h,0x11c,s->tx.saved_clk[h]|0x100a00);wr(s,h,4,s->tx.saved_ctrl[h]|4);
    }
    s->tx.command_touched=true;s->tx.wait_until=now(s)+s->tx.mdp_budget;
    s->tx.deadline=now(s)+s->board.mdp_idle_timeout_us;s->tx.state=Quiesce;
}
static int stage(D69Display *s){
    const D69Packet *p=&s->tx.packet[s->tx.index];uint32_t words[5];unsigned bytes=0;
    int result=d69_pack(p,words,&bytes);if(result)return result;
    for(unsigned h=0;h<2;++h){
        if(errors(s,h))return D69Controller;
        wr(s,h,0x110,s->tx.saved_int[h]|1); // command DONE W1C only
        wr(s,h,0x15c,0);wr(s,h,0x1ec,1);s->io.delay_us(s->io.context,1);wr(s,h,0x1ec,0);
        wr(s,h,0x15c,0x30006);
        for(unsigned i=0;i<bytes/4;++i)wr(s,h,0x17c,words[i]);
        if((bytes/4)&1)wr(s,h,0x17c,0);
        const uint32_t dma=(s->tx.saved_dma[h]&~0xf5000000u)|B(31)|B(28)|(h==s->tx.master?B(30):0);
        wr(s,h,0x3c,dma);wr(s,h,0x84,(s->tx.saved_trigger[h]&~0x1000fu)|4);wr(s,h,0x4c,bytes);
    }
    wr(s,1-s->tx.master,0x90,1);wr(s,s->tx.master,0x90,1);
    s->tx.ddic_touched=true;s->tx.done_mask=0;s->tx.deadline=now(s)+25000;s->tx.state=WaitPacket;return D69Pending;
}
static uint64_t timestamp(D69Display *s,unsigned h);
static void reset_te(D69Display *s){
    s->tx.te_since=now(s);s->tx.deadline=s->tx.te_since+1600000;
    for(unsigned h=0;h<2;++h){s->tx.te_first[h]=0;s->tx.te_last[h]=timestamp(s,h);s->tx.te_events[h]=0;
        s->tx.te_last_seen[h]=s->tx.te_since;s->tx.te_period_min[h]=s->tx.te_period_max[h]=0;}
}
static int begin(D69Display *s){
    int result=snapshot(s);if(result)return unlock_unstarted(s,result);
    if(s->tx.switching){
        result=dms_readback(s);if(result)return unlock_unstarted(s,result);
        for(unsigned h=0;h<2;++h){const uint32_t in=s->board.intf[h];
            // Enable external timestamp capture normally. Observe inherited
            // rate before issuing the FPS command, no prior successcertificate.
            if(!(md(s,in+0x288)&B(20))||md(s,in+0x284)!=1||
               (md(s,in+0x280)&15)!=0||!(rd(s,h,0x84)&B(31)))return unlock_unstarted(s,D69Te);
        }
        s->tx.timestamp_touched=true;
        for(unsigned h=0;h<2;++h)mw(s,s->board.intf[h]+0x210,1);
        reset_te(s);s->tx.state=VerifyBefore;return D69Pending;
    }
    quiesce(s);return D69Pending;
}
int d69_probe(D69Display *s){
    if(!s||!s->initialized)return D69Argument;
    if(s->ready)return D69OK;
    uint32_t expected=Closed;
    if(!__atomic_compare_exchange_n(&s->gate,&expected,Running,false,SC,SC)&&expected!=Running)return D69Busy;
    int result=resource_lock(s);if(result)return result;
    result=snapshot(s);if(!result)s->ready=1;return unlock_unstarted(s,result);
}
int d69_producer_enter(D69Display *s){
    if(!s||!s->initialized)return D69OK;
    if(__atomic_load_n(&s->gate,SC)!=Running)return D69Busy;
    __atomic_fetch_add(&s->producers,1u,SC);
    if(__atomic_load_n(&s->gate,SC)==Running)return D69OK;
    __atomic_fetch_sub(&s->producers,1u,SC);return D69Busy;
}
void d69_producer_leave(D69Display *s){if(s&&s->initialized)__atomic_fetch_sub(&s->producers,1u,SC);}
int d69_brightness(D69Display *s,uint32_t level){
    if(!s||!s->ready)return D69Resource;if(level>4095)level=4095;s->requested=level;
    int result=resource_lock(s);if(result)return result;
    s->sending=level;s->tx.mdp_budget=s->observed_hz==120?s->board.mdp_budget_120_us:
        (s->board.mdp_budget_60_us>s->board.mdp_budget_120_us?s->board.mdp_budget_60_us:s->board.mdp_budget_120_us);
    D69Packet *p=&s->tx.packet[0];p->type=0x39;p->length=3;const uint16_t dbv=d69_sdr_dbv(level);
    p->data[0]=0x51;p->data[1]=(uint8_t)(dbv>>8);p->data[2]=(uint8_t)dbv;s->tx.count=1;
    return begin(s);
}
int d69_switch120(D69Display *s){
    if(!s||!s->ready)return D69Resource;int result=resource_lock(s);if(result)return result;
    // Exact DT 120Hz HS packets for same-resolution FPS DMS. No sleep-out,
    // PLL/PHY/PPS rewrite. Host/DSC mode compatibility checked before firstpacket.
    const uint8_t commands[7][5]={{0xf0,0x5a,0x5a},{0x60,0,0},{0xf0,0xa5,0xa5},
        {0x2a,0,0,0,0},{0x2b,0,0,0,0},{0x44,0,0},{0x29}};
    const uint8_t lengths[7]={3,3,3,5,5,3,1};
    for(unsigned i=0;i<7;++i){D69Packet *p=&s->tx.packet[i];p->type=i==6?0x05:0x39;p->length=lengths[i];memcpy(p->data,commands[i],lengths[i]);}
    const unsigned endx=s->board.width-1,endy=s->board.height-1;
    s->tx.packet[3].data[3]=(uint8_t)(endx>>8);s->tx.packet[3].data[4]=(uint8_t)endx;
    s->tx.packet[4].data[3]=(uint8_t)(endy>>8);s->tx.packet[4].data[4]=(uint8_t)endy;
    if(s->board.width==1096)s->tx.packet[1].data[1]=4;
    s->tx.count=7;s->tx.switching=true;s->tx.mdp_budget=s->board.mdp_budget_60_us;return begin(s);
}
static int restore(D69Display *s){
    if(!idle_hosts(s))return D69Busy;
    for(unsigned h=0;h<2;++h){if(errors(s,h))return D69Controller;
        wr(s,h,0x15c,0);wr(s,h,0x1ec,1);s->io.delay_us(s->io.context,1);wr(s,h,0x1ec,0);
        wr(s,h,0x3c,s->tx.saved_dma[h]);wr(s,h,0x84,s->tx.saved_trigger[h]);wr(s,h,0x4c,s->tx.saved_length[h]);
        wr(s,h,4,s->tx.saved_ctrl[h]);wr(s,h,0x11c,s->tx.saved_clk[h]);wr(s,h,0x110,s->tx.saved_int[h]);
        const uint32_t in=s->board.intf[h];
        if(!s->tx.switching){mw(s,in+0x288,s->tx.saved_te_config[h]);mw(s,in+0x210,s->tx.saved_timestamp[h]);}
        mw(s,in+0x284,s->tx.switching?1:s->tx.saved_te_enable[h]);
        mw(s,in+0x2b4,s->tx.saved_autorefresh[h]);
    }
    const int release=s->io.release(s->io.context);if(release)return D69Restore;
    s->tx.state=Idle;__atomic_store_n(&s->gate,Running,SC);return D69OK;
}
static int tear120(D69Display *s){
    // vtotal from actual panel mode: height+VFP180+VBP8+VSW8. No hardcoded XO
    // frequency: native derives vsync clock from the retained DISPCC RCG.
    // Sony timing@N uses VSW=8,VBP=8,VFP=180. SDE's tear count divides
    // actual VSYNC clock by vtotal*requested refresh; DT timing is selected
    // by resolution and the already-qualified active TE input.
    const uint32_t vtotal=s->board.height+8+8+180;
    const uint32_t count=s->board.vsync_hz/(vtotal*120);
    if(!count||count>0x7ffff)return D69Mode;
    for(unsigned h=0;h<2;++h){const uint32_t in=s->board.intf[h];
        s->io.critical(s->io.context,true);
        const uint32_t original_te=s->tx.saved_te_config[h];
        const uint32_t requested_source=original_te&B(20);
        if(!requested_source)return D69Te;
        mw(s,in+0x288,count|requested_source);mw(s,in+0x28c,0xfff0);mw(s,in+0x294,s->board.height);
        mw(s,in+0x2a4,s->board.height+1);mw(s,in+0x2a8,1);mw(s,in+0x2a0,s->board.height);
        mw(s,in+0x29c,0x40004);mw(s,in+0x288,count|B(19));mw(s,in+0x290,s->board.height+5);
        s->io.critical(s->io.context,false);
        // Keep the source from the inherited GDSC/INTF snapshot; timestamp
        // capture does not change the selector and both links must read back.
        mw(s,in+0x288,count|requested_source|B(19));mw(s,in+0x210,1);mw(s,in+0x284,1);
        if(md(s,in+0x288)!=(count|requested_source|B(19))||
           !(rd(s,h,0x84)&B(31))||!(md(s,in+0x210)&B(0)))return D69Restore;
    }
    reset_te(s);s->tx.state=VerifyTe;return D69Pending;
}
static uint64_t timestamp(D69Display *s,unsigned h){
    const uint32_t in=s->board.intf[h];uint32_t high=md(s,in+0x218),low=md(s,in+0x214),again=md(s,in+0x218);
    if(high!=again){high=again;low=md(s,in+0x214);}return ((uint64_t)high<<32)|low;
}
static uint32_t dsi_external_te_mode(D69Display *s,unsigned h){
    // Qualcomm DSI TRIG_CTRL bit31 is TE_ON_EXT_PIN. A command-mode host with
    // this bit clear cannot be treated as an external-panel-TE measurement.
    return rd(s,h,0x84)&B(31);
}
int d69_step(D69Display *s){
    if(!s||!s->initialized)return D69Argument;if(s->poisoned)return D69Poisoned;if(s->tx.state==Idle)return D69OK;
    if(!s->io.held(s->io.context)||s->tx.epoch!=s->generation)return fail(s,D69Epoch);
    const uint64_t time=now(s);
    for(unsigned h=0;h<2;++h)if(errors(s,h))return fail(s,D69Controller);
    if(s->tx.state==Quiesce){if(!idle_hosts(s)){if(time>=s->tx.wait_until)s->tx.mdp_over_budget=true;
            return time>=s->tx.deadline?fail(s,D69Timeout):D69Pending;}return stage(s);}
    if(s->tx.state==WaitPacket){
        for(unsigned h=0;h<2;++h)if(rd(s,h,0x110)&1)s->tx.done_mask|=B(h);
        if(s->tx.done_mask!=3||!idle_hosts(s))return time>=s->tx.deadline?fail(s,D69Timeout):D69Pending;
        s->packets_sent++;const D69Packet *p=&s->tx.packet[s->tx.index];
        for(unsigned h=0;h<2;++h){wr(s,h,0x110,1);wr(s,h,0x15c,0);}
        s->tx.wait_until=time+(uint64_t)p->wait_ms*1000;++s->tx.index;s->tx.state=WaitDelay;
    }
    if(s->tx.state==WaitDelay){if(time<s->tx.wait_until)return D69Pending;
        if(s->tx.index<s->tx.count)return stage(s);
        if(s->tx.switching)return tear120(s);
        const int result=restore(s);if(result)return fail(s,result);
        s->transmitted=s->sending;s->current_verified=UINT32_MAX;return D69OK;
    }
    if(s->tx.state==VerifyTe||s->tx.state==VerifyBefore){
        const bool before=s->tx.state==VerifyBefore;
        for(unsigned h=0;h<2;++h){const uint32_t in=s->board.intf[h];
            if(!dsi_external_te_mode(s,h)||!(md(s,in+0x288)&B(20))||md(s,in+0x284)!=1||
               (md(s,in+0x280)&15)!=0)return before?unlock_unstarted(s,D69Te):fail(s,D69Te);}
        for(unsigned h=0;h<2;++h){const uint64_t sample=timestamp(s,h);if(!sample||sample==s->tx.te_last[h])continue;
            if(sample<s->tx.te_last[h])return before?unlock_unstarted(s,D69Te):fail(s,D69Te);
            if(s->tx.te_last[h]&&s->tx.te_first[h]){const uint64_t delta=sample-s->tx.te_last[h];
                const uint64_t us=s->board.timestamp_hz?delta*1000000/s->board.timestamp_hz:time-s->tx.te_last_seen[h];
                if((!before&&(us<7000||us>10000))||(before&&(us<7000||us>19000)))return before?unlock_unstarted(s,D69Te):fail(s,D69Te);
                if(!s->tx.te_period_min[h]||us<s->tx.te_period_min[h])s->tx.te_period_min[h]=us;
                if(us>s->tx.te_period_max[h])s->tx.te_period_max[h]=us;
                s->tx.te_events[h]++;
            } else s->tx.te_first[h]=sample;s->tx.te_last[h]=sample;s->tx.te_last_seen[h]=time;
        }
        if(time-s->tx.te_since>=1000000){
            const uint64_t elapsed=time-s->tx.te_since;
            unsigned hz[2];
            for(unsigned h=0;h<2;++h)hz[h]=(unsigned)((uint64_t)s->tx.te_events[h]*1000000/elapsed);
            if(before){
                if(hz[0]>=118&&hz[0]<=122&&hz[1]>=118&&hz[1]<=122){const int result=unlock_unstarted(s,D69OK);if(!result)s->observed_hz=120;return result;}
                if(hz[0]<58||hz[0]>62||hz[1]<58||hz[1]>62)return unlock_unstarted(s,D69Te);
                s->tx.mode_before=60;s->tx.mdp_budget=s->board.mdp_budget_60_us;quiesce(s);return D69Pending;
            }
            if(hz[0]<118||hz[0]>122||hz[1]<118||hz[1]>122)return fail(s,D69Te);
            const int result=restore(s);if(result)return fail(s,result);s->observed_hz=120;return D69OK;
        }
        return time>=s->tx.deadline?(before?unlock_unstarted(s,D69Te):fail(s,D69Te)):D69Pending;
    }
    return D69Pending;
}
bool d69_busy(const D69Display *s){return s&&s->tx.state!=Idle;}
int d69_stop(D69Display *s){if(!s||!s->initialized)return D69OK;if(s->poisoned)return D69Poisoned;
    uint32_t expected=Running;if(!__atomic_compare_exchange_n(&s->gate,&expected,Stopped,false,SC,SC))return D69Busy;
    if(__atomic_load_n(&s->producers,SC)){__atomic_store_n(&s->gate,Running,SC);return D69Busy;}s->ready=0;return D69OK;}
int d69_resume(D69Display *s){
    if(!s||!s->initialized)return D69Argument;if(s->poisoned)return D69Poisoned;
    if(s->tx.state!=Idle)return D69Busy;
    uint32_t expected=Stopped;
    if(!__atomic_compare_exchange_n(&s->gate,&expected,Closed,false,SC,SC)&&expected!=Running)return D69Busy;
    return d69_probe(s);
}
