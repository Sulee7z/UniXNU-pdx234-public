// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "SonyDsi.h"
#include "SonyOledPolicy.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

typedef struct Model {
    uint32_t reg[2][SonyDsiHostBytes/4];
    uint32_t fifo[2][2], words[2], writes, acquired, released, triggers[2];
    uint16_t dbv[2];
    unsigned trigger_order[4096], order_count;
    bool lease, busy, lost, never_done, mismatch, malformed, bad_ecc, error;
    uint64_t epoch;
} Model;

static uint32_t read_reg(void *p,unsigned h,uint32_t reg) {
    Model *m=p; assert(h<2 && !(reg&3) && reg<SonyDsiHostBytes);
    return m->reg[h][reg/4];
}
static void complete(Model *m,unsigned h) {
    const uint32_t *f=m->fifo[h];
    if(f[0]==UINT32_C(0xc0390003)) {
        assert((f[1]&255)==0x51); m->dbv[h]=(uint16_t)(((f[1]>>8&255)<<8)|(f[1]>>16&255));
    } else {
        assert(f[0]==UINT32_C(0x00370002) && f[1]==UINT32_C(0xa0060052));
        uint16_t dbv=m->dbv[h]; if(m->mismatch && h)dbv^=1;
        m->reg[h][SonyDsiReadControl/4]=4u<<16;
        const uint8_t type=m->malformed?0x21:0x22;
        m->reg[h][SonyDsiReadData/4]=((uint32_t)type<<24)|((uint32_t)dbv<<8)|
            sony_dsi_header_ecc(type,(uint8_t)(dbv>>8),(uint8_t)dbv);
        if(m->bad_ecc)m->reg[h][SonyDsiReadData/4]^=1;
    }
    m->reg[h][SonyDsiStatus/4]=0;
    m->reg[h][SonyDsiInterrupt/4]|=1;
    if(m->error)m->reg[h][SonyDsiInterrupt/4]|=1u<<24;
}
static void write_reg(void *p,unsigned h,uint32_t reg,uint32_t value) {
    Model *m=p; assert(m->lease && h<2 && !(reg&3) && reg<SonyDsiHostBytes); m->writes++;
    if(reg==SonyDsiTpgData) {
        assert(m->words[h]<2); m->fifo[h][m->words[h]++]=value;
    } else if(reg==SonyDsiFifoReset && value) m->words[h]=0;
    else if(reg==SonyDsiInterrupt) {
        const uint32_t status=UINT32_C(0x51115501),mask=UINT32_C(0xa222aa02);
        m->reg[h][reg/4]=(m->reg[h][reg/4]&status&~value)|(value&mask);return;
    } else if(reg==SonyDsiTrigger) {
        assert(value==1 && m->words[h]==2);
        assert(m->order_count<4096);m->trigger_order[m->order_count++]=h;m->triggers[h]++;
        if(!m->never_done)complete(m,h);else m->reg[h][SonyDsiStatus/4]=2;
    } else if(reg==SonyDsiReadControl && value) {
        m->reg[h][SonyDsiReadData/4]=0;
    }
    m->reg[h][reg/4]=value;
}
static void delay_us(void *p,uint32_t us) { (void)p;assert(us==1); }
static int acquire(void *p,uint64_t *epoch) {
    Model *m=p; if(m->busy)return SonyDsiBusy;
    assert(!m->lease);m->lease=true;m->acquired++;*epoch=++m->epoch;return 0;
}
static bool owned(void *p,uint64_t epoch) { Model *m=p;return m->lease && !m->lost && epoch==m->epoch; }
static void release(void *p,uint64_t epoch) {
    Model *m=p;assert(m->lease && epoch==m->epoch);m->lease=false;m->released++;
}
static SonyDsiQualification qualification(void) {
    const SonyDsiQualification q={SonyDsiQualificationAll,{0x20070000,0x20070000},{0xf000336,0xf000336},0,false};return q;
}
static void setup(Model *m,SonyDsi *s) {
    memset(m,0,sizeof(*m));
    for(unsigned h=0;h<2;++h) {
        m->reg[h][SonyDsiVersion/4]=0x20070000;
        m->reg[h][SonyDsiControl/4]=5;
        m->reg[h][SonyDsiStreamTotal/4]=0xf000336;
        m->reg[h][SonyDsiDmaControl/4]=0x14000000;
        m->reg[h][SonyDsiDmaLength/4]=0x20;
        m->reg[h][SonyDsiTriggerControl/4]=0x100004;
        m->reg[h][SonyDsiInterrupt/4]=0xa222aa02;
        m->dbv[h]=100;
    }
    const SonyDsiIo io={m,read_reg,write_reg,delay_us,acquire,owned,release};
    const SonyDsiQualification q=qualification();assert(!sony_dsi_init(s,&io,&q));
}
static int finish(SonyDsi *s) {
    int result=SonyDsiPending;for(unsigned i=1;i<8 && result==SonyDsiPending;++i)result=sony_dsi_step(s,i*1000);
    return result;
}
#ifdef SONY_OLED_VENDOR_DIFF
extern uint16_t sony_oled_vendor_reference(uint32_t level);
extern uint8_t sony_oled_vendor_ecc(uint8_t type,uint8_t data0,uint8_t data1);
#endif
static void policy(void) {
    assert(sony_oled_level_for_nits(INT32_MIN)==0 && sony_oled_level_for_nits(0)==0);
    assert(sony_oled_level_for_nits(1)==1 && sony_oled_level_for_nits(INT32_MAX)==4095);
    assert(sony_oled_level_for_nits(500<<16)==4095);
    assert(sony_oled_fade_ms(UINT32_MAX)==5000 && sony_oled_fade_ms(1<<16)==1000);
    assert(sony_oled_fade_level(0,4095,500,1000)==2047);
    assert(sony_oled_fade_level(4095,0,500,1000)==2048);
    assert(sony_oled_fade_level(4095,0,UINT64_MAX,1)==0);
    uint16_t previous=0;
    for(unsigned i=0;i<=4095;++i) {
        const uint16_t value=sony_oled_sdr_dbv(i);assert(value>=previous && value<=2047);previous=value;
#ifdef SONY_OLED_VENDOR_DIFF
        assert(value==sony_oled_vendor_reference(i));
        assert(sony_dsi_header_ecc(0x22,(uint8_t)(i>>8),(uint8_t)i)==sony_oled_vendor_ecc(0x22,(uint8_t)(i>>8),(uint8_t)i));
#endif
        if(i)assert(value>=4);else assert(!value);
        uint8_t bytes[3];sony_oled_encode_dbv((uint16_t)i,bytes);assert(bytes[0]==0x51);
        uint16_t decoded=0;assert(sony_oled_decode_dbv(bytes+1,&decoded)&&decoded==i);
    }
    assert(sony_oled_sdr_dbv(UINT32_MAX)==2047);
    uint32_t words[2];sony_dsi_packet51(0x123,words);
    assert(words[0]==0xc0390003 && words[1]==0xff230151);
    sony_dsi_packet52(words);assert(words[0]==0x00370002 && words[1]==0xa0060052);
}
static void transactions(void) {
    Model m;SonyDsi s;setup(&m,&s);
    assert(sony_dsi_start_read(&s,0)==SonyDsiPending);
    assert(sony_dsi_start_read(&s,0)==SonyDsiBusy);
    assert(finish(&s)==0 && s.observed[0]==100 && s.observed[1]==100 && !m.lease);
    m.order_count=0;
    assert(sony_dsi_start_write(&s,0x123,0)==SonyDsiPending);
    assert(m.trigger_order[0]==1 && m.trigger_order[1]==0);
    assert(finish(&s)==0 && s.completed==2 && m.dbv[0]==0x123 && m.dbv[1]==0x123);
    assert(m.reg[0][SonyDsiDmaControl/4]==0x14000000 && m.reg[1][SonyDsiTriggerControl/4]==0x100004);
    assert(m.reg[0][SonyDsiDmaLength/4]==0x20 && m.reg[1][SonyDsiDmaLength/4]==0x20);
    assert(m.reg[0][SonyDsiInterrupt/4]==0xa222aa02 && m.acquired==m.released);
    assert(sony_dsi_start_write(&s,2048,0)==SonyDsiArgument && !m.lease);
    setup(&m,&s);m.busy=true;
    assert(sony_dsi_start_write(&s,1,0)==SonyDsiBusy && m.writes==0 && !m.lease);
    setup(&m,&s);m.reg[1][SonyDsiVersion/4]++;
    assert(sony_dsi_start_write(&s,1,0)==SonyDsiInheritedState && m.writes==0 && m.released==1);
    setup(&m,&s);m.reg[1][SonyDsiStatus/4]=2;
    assert(sony_dsi_start_read(&s,0)==SonyDsiInheritedState && !m.writes);
    setup(&m,&s);m.reg[1][SonyDsiDmaSchedule/4]=1u<<28;
    assert(sony_dsi_start_read(&s,0)==SonyDsiInheritedState && !m.writes && !m.lease);
    setup(&m,&s);m.mismatch=true;
    assert(sony_dsi_start_write(&s,15,0)==SonyDsiPending && finish(&s)==SonyDsiMismatch);
    assert(!m.lease && !s.poisoned && s.completed==0);
    setup(&m,&s);m.never_done=true;
    assert(sony_dsi_start_write(&s,16,0)==SonyDsiPending);
    assert(sony_dsi_step(&s,24999)==SonyDsiPending && sony_dsi_step(&s,25000)==SonyDsiTimeout);
    const uint32_t writes=m.writes;assert(s.poisoned && m.lease && !m.released);
    assert(sony_dsi_start_write(&s,1,0)==SonyDsiPoisoned && sony_dsi_step(&s,999999)==SonyDsiPoisoned && writes==m.writes);
    setup(&m,&s);assert(sony_dsi_start_read(&s,0)==SonyDsiPending);m.lost=true;
    assert(sony_dsi_step(&s,1)==SonyDsiOwnershipLost && m.lease);
    setup(&m,&s);m.error=true;assert(sony_dsi_start_write(&s,1,0)==SonyDsiPending);
    assert(sony_dsi_step(&s,1)==SonyDsiControllerError && m.lease && s.completed==0);
    setup(&m,&s);m.malformed=true;assert(sony_dsi_start_read(&s,0)==SonyDsiPending);
    assert(sony_dsi_step(&s,1)==SonyDsiResponse && m.lease);
    setup(&m,&s);m.bad_ecc=true;assert(sony_dsi_start_read(&s,0)==SonyDsiPending);
    assert(sony_dsi_step(&s,1)==SonyDsiResponse && m.lease && !s.completed);
    setup(&m,&s);const SonyDsiIo io=s.io;SonyDsiQualification q=qualification();q.flags=0;
    assert(sony_dsi_init(&s,&io,&q)==SonyDsiUnqualified && m.writes==0);
    assert(sony_dsi_start_read(&s,0)==SonyDsiUnqualified);
    assert(sony_dsi_start_read(NULL,0)==SonyDsiUnqualified);
    assert(sony_dsi_start_write(NULL,1,UINT64_MAX)==SonyDsiArgument);
    // Deterministic fuzz of actual engine: malformed physical replies never
    // increment completed; no future request can overwrite a poisoned host.
    for(unsigned i=0;i<10000;++i) {
        setup(&m,&s);m.dbv[0]=m.dbv[1]=(uint16_t)(i&4095);m.malformed=(i&1)!=0;
        assert(sony_dsi_start_read(&s,0)==SonyDsiPending);
        const int result=finish(&s);
        assert(result==(m.malformed?SonyDsiResponse:SonyDsiOK));
        assert(s.completed==(m.malformed?0u:1u));
    }
}
int main(void) {policy();transactions();puts("PASS Sony OLED: 4096 DBV/policy, dual-host FIFO51/read52, ordering/lease/state/error/timeout/poison,10000 replies");return 0;}
