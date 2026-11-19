/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "Sw82907.h"
#include "GeniI2c.h"
#include "HidTouchReport.h"
#include "GeniInit.h"
#include "SmmuBypass.h"
static void put32(uint8_t *p, uint32_t v) {for(unsigned i=0;i<4;++i)p[i]=(uint8_t)(v>>(i*8));}
static void frame(uint8_t *p,unsigned count) {
    memset(p,0,SW82907_FRAME_BYTES);put32(p,0x6);
    put32(p+4,0x00558060);put32(p+8,count<<8);
}
static void point(uint8_t *p,unsigned slot,unsigned id,unsigned event,unsigned x,unsigned y) {
    p+=12+slot*12;p[0]=(uint8_t)((event<<4)|1);p[1]=(uint8_t)id;
    p[2]=(uint8_t)x;p[3]=(uint8_t)(x>>8);p[4]=(uint8_t)y;p[5]=(uint8_t)(y>>8);
}
static void test_protocol(void) {
    uint8_t raw[SW82907_FRAME_BYTES],command[6];Sw82907FrameData out;
    assert(!sw82907_read_command(0x600,24,command) && command[0]==0x26 && command[1]==0);
    assert(!sw82907_read_command(0x642,4,command) && command[0]==0x06 && command[1]==0x42);
    assert(!sw82907_write_word(0xc03,0x301,command));
    assert(!memcmp(command,(uint8_t[]){0x4c,3,1,3,0,0},6));
    assert(sw82907_read_command(0x1000,1,command)==-1);
    frame(raw,2);point(raw,0,7,1,1644,3840);point(raw,1,2,2,1,2);
    assert(sw82907_decode(raw,36,&out)==0 && out.count==2 && out.contacts[0].id==2 && out.contacts[1].id==7);
    point(raw,0,7,3,1644,3840);assert(!sw82907_decode(raw,36,&out) && out.count==1 && out.contacts[0].id==2);
    frame(raw,0);assert(!sw82907_decode(raw,12,&out) && out.count==0);
    frame(raw,1);point(raw,0,15,1,0,0);assert(!sw82907_decode(raw,24,&out) && out.cancelled && !out.count);
    frame(raw,2);point(raw,0,1,1,1,2);point(raw,1,3,1,3,4);put32(raw+8,(2u<<8)|(1u<<17));
    assert(!sw82907_decode(raw,36,&out) && out.count==1 && out.contacts[0].id==3);
    Sw82907FrameData keep=out;
    for(unsigned count=11;count<=31;++count) {frame(raw,count);assert(sw82907_decode(raw,sizeof(raw),&out)==Sw82907BadCount);}
    frame(raw,2);point(raw,0,1,1,1,2);point(raw,1,1,2,3,4);
    assert(sw82907_decode(raw,36,&out)==Sw82907BadContact && !memcmp(&out,&keep,sizeof(out)));
    for(unsigned n=0;n<36;++n) {int rc=sw82907_decode(raw,n,&out);assert(rc<0);}
    frame(raw,1);point(raw,0,1,1,1645,3);assert(sw82907_decode(raw,24,&out)==Sw82907BadContact);
    frame(raw,1);point(raw,0,1,1,1,3841);assert(sw82907_decode(raw,24,&out)==Sw82907BadContact);
    frame(raw,1);put32(raw,0xffffffff);assert(sw82907_decode(raw,24,&out)==Sw82907BadStatus);
    frame(raw,1);put32(raw+4,0x00558060|(1u<<9));assert(sw82907_decode(raw,24,&out)==Sw82907BadStatus);
    frame(raw,1);put32(raw+4,0x00528060);assert(sw82907_decode(raw,24,&out)==Sw82907Ignored);
    unsigned seed=7;
    for(unsigned n=0;n<100000;++n) {
        for(unsigned i=0;i<sizeof(raw);++i){seed=seed*1664525u+1013904223u;raw[i]=(uint8_t)(seed>>24);}
        (void)sw82907_decode(raw,n%(sizeof(raw)+1),&out);
    }
}
typedef struct {uint32_t regs[4096],tx[256],rx[256];unsigned tx_n,rx_n,rx_at,reads,writes;} Engine;
static void prepare(Engine *,SonyGeniI2c *);
static uint32_t read_reg(void *ctx,uint32_t reg) {
    Engine *e=ctx;++e->reads;assert(reg<sizeof(e->regs));
    assert(reg<0x2000 || reg>0x2008); // protected aliases abort in the reference hardware context
    if(reg==0x610 && !(e->regs[0xe1c/4]&4u))return 0;
    if(reg==0xc40 && !(e->regs[0xe1c/4]&2u))return 0;
    if(reg==0xd40 && !(e->regs[0xe1c/4]&1u))return 0;
    if(reg==0x780){assert(e->rx_at<e->rx_n);return e->rx[e->rx_at++];}
    if(reg==0x804)return e->regs[reg/4];
    return e->regs[reg/4];
}
static void write_reg(void *ctx,uint32_t reg,uint32_t val) {
    Engine *e=ctx;++e->writes;assert(reg<sizeof(e->regs));
    assert(reg<0x2000 || reg>0x2008);
    if(reg==0x700){assert(e->tx_n<256);e->tx[e->tx_n++]=val;return;}
    if(reg==0x618){e->regs[0x610/4]&=~val;return;}
    if(reg==0xc44){e->regs[0xc40/4]&=~val;return;}
    if(reg==0xd44){e->regs[0xd40/4]&=~val;return;}
    e->regs[reg/4]=val;
}
static void test_init(const char *path) {
    FILE *file=fopen(path,"rb");assert(file);
    uint8_t bytes[2048];size_t size=fread(bytes,1,sizeof(bytes),file);fclose(file);assert(size==1585);
    SonyGeniFirmware fw;assert(!sony_geni_firmware_parse(bytes,size,&fw));
    assert(fw.words==303 && fw.pairs==69 && fw.core_version==0x30090000);
    Engine se={0},wrap={0};SonyGeniIo io={read_reg,write_reg,&se},wrapper={read_reg,write_reg,&wrap};unsigned loaded=99;
    wrap.regs[1]=0x300a0000;se.regs[0x64/4]=1;se.regs[0x68/4]=0x303;
    assert(!sony_geni_firmware_init(&io,&wrapper,bytes,size,&loaded) && loaded==0);
    assert(se.regs[0x68/4]==0x303 && se.regs[0x64/4]==1 && !se.regs[0xe18/4]);
    assert(!se.regs[0x1000/4] && !se.regs[0x1004/4]);
    const unsigned writes=se.writes;
    assert(!sony_geni_firmware_init(&io,&wrapper,bytes,size,&loaded) && loaded==0 && se.writes-writes<10);
    se.regs[0x24/4]=1;assert(!sony_geni_firmware_init(&io,&wrapper,bytes,size,&loaded));
    assert((se.regs[0x24/4]&0x7f)==0x7f && se.regs[0x20/4]==1);
    se.regs[0x40/4]=1;unsigned before=se.writes;
    assert(sony_geni_firmware_init(&io,&wrapper,bytes,size,&loaded)==SonyGeniInitBusy && se.writes==before);
    se.regs[0x40/4]=0;se.regs[0x68/4]=1u<<8;
    assert(sony_geni_firmware_init(&io,&wrapper,bytes,size,&loaded)==SonyGeniInitProtocol && se.writes==before);
    se.regs[0x68/4]=0;
    assert(sony_geni_firmware_init(&io,&wrapper,bytes,size,&loaded)==SonyGeniInitProtocol && se.writes==before);
    se.regs[0x68/4]=0;wrap.regs[1]=0x30080000;
    assert(sony_geni_firmware_init(&io,&wrapper,bytes,size,&loaded)==SonyGeniInitHardware && se.writes==before);
    bytes[18]=0xff;bytes[19]=0xff;assert(sony_geni_firmware_parse(bytes,size,&fw)==SonyGeniInitHeader);
    assert(sony_geni_tcxo_config(0) && sony_geni_tcxo_config(1) && !sony_geni_tcxo_config(3));
    assert(!sony_geni_tcxo_config(0x100) && !sony_geni_tcxo_config(0x1001));
    uint32_t levels[]={0x106,0x600,1};assert(sony_geni_tcxo_level(levels,3)==2);
    assert(sony_geni_tcxo_level(levels,2)==-1 && sony_geni_tcxo_level(levels,9)==-1);
}
typedef struct {uint8_t tx[1024],rx[1024];unsigned clean,prepare,invalidate;} DmaMemory;
static void clean_dma(void *context,void *address,uint32_t length) {
    DmaMemory *d=context;assert(address==d->tx && length<=1024);++d->clean;
}
static void prepare_dma(void *context,void *address,uint32_t length) {
    DmaMemory *d=context;assert(address==d->rx && length<=1024);++d->prepare;
}
static void invalidate_dma(void *context,void *address,uint32_t length) {
    DmaMemory *d=context;assert(address==d->rx && length<=1024);++d->invalidate;
}
static void test_dma(void) {
    Engine e;SonyGeniI2c g;prepare(&e,&g);DmaMemory memory={0};
    e.regs[0x64/4]=1;SonyGeniIo io={read_reg,write_reg,&e};
    SonyGeniDma dma={&memory,memory.tx,memory.rx,0x980000000ull,0x980004000ull,1024,
                    clean_dma,prepare_dma,invalidate_dma};
    assert(!sony_geni_prepare_dma(&g,&io,0x28,0x300a0000,&dma));
    assert(e.regs[0xe1c/4]==15 && e.regs[0x258/4]==1 && e.regs[0x64/4]==1);
    assert(!(e.regs[0x614/4]&1));
    uint8_t command[]={0x26,0},bytes[132]={};
    assert(!sony_geni_read(&g,command,2,bytes,sizeof(bytes)) && memory.clean==1 && !memcmp(memory.tx,command,2));
    assert(e.regs[0xc34/4]==9 && e.regs[0xc3c/4]==2 && e.regs[0xc38/4]==1);
    // Vendor I2C and official GeniSpi use DMA_DONE with M_CMD_DONE disabled.
    // A stale opposite-direction completion cannot satisfy the current phase.
    e.regs[0xd40/4]=1;assert(sony_geni_poll(&g)==SonyGeniPending && g.phase==SonyGeniTx);
    e.regs[0xc40/4]=1;assert(sony_geni_poll(&g)==SonyGeniPending && g.phase==SonyGeniRx && memory.prepare==1);
    assert(e.regs[0xd34/4]==9 && e.regs[0xd3c/4]==132 && e.regs[0xd38/4]==0);
    for(unsigned i=0;i<sizeof(bytes);++i)memory.rx[i]=(uint8_t)i;
    e.regs[0x610/4]=1;assert(sony_geni_poll(&g)==SonyGeniPending && !memory.invalidate);
    e.regs[0xd40/4]=1;assert(sony_geni_poll(&g)==SonyGeniDone && memory.invalidate==1 && !e.tx_n);
    for(unsigned i=0;i<sizeof(bytes);++i)assert(bytes[i]==i);
    assert(!sony_geni_write(&g,command,2));
    e.regs[0xc40/4]=1;assert(sony_geni_poll(&g)==SonyGeniDone);
    assert(!sony_geni_read(&g,command,2,bytes,sizeof(bytes)));
    e.regs[0x610/4]=1;e.regs[0xc40/4]=1;assert(sony_geni_poll(&g)==SonyGeniPending && g.phase==SonyGeniRx);
    e.regs[0xd40/4]=1u<<6;assert(sony_geni_poll(&g)==SonyGeniPending && g.error==SonyGeniBusError && g.phase==SonyGeniCancel);
    e.regs[0x610/4]=1u<<4;assert(sony_geni_poll(&g)==SonyGeniFailed && g.dma_started);
}
typedef struct {uint32_t regs[0xd0000/4];unsigned writes;} Smmu;
static uint32_t smmu_read(void *ctx,unsigned offset){assert(offset<0xd0000);return ((Smmu *)ctx)->regs[offset/4];}
static void smmu_write(void *ctx,unsigned offset,uint32_t value){Smmu *s=ctx;assert(offset<0xd0000);s->regs[offset/4]=value;++s->writes;}
static void test_smmu(void) {
    Smmu *s=calloc(1,sizeof(*s));assert(s);
    s->regs[0x20/4]=(1u<<30)|8;s->regs[0x24/4]=(2u<<28)|16;s->regs[0x28/4]=0x1222;
    s->regs[0x800/4]=0x80000111;s->regs[0xc00/4]=15;
    s->regs[(0x1000+15*4)/4]=0x10000;s->regs[(0x1800+15*4)/4]=1;
    struct smmu_io io={s,smmu_read,smmu_write};
    struct smmu_plan plan=smmu_plan_bypass(&io,0xa3,0x980000000ull,32768);
    assert(!plan.error && plan.bank_ready && plan.bank==15 && plan.slot==1);
    assert(!smmu_configure_bypass(&io,&plan,0xa3) && s->regs[0x800/4]==0x80000111);
    unsigned before=s->writes;s->regs[(0xc00+4)/4]=1u<<16;
    plan=smmu_plan_bypass(&io,0xa3,0x980000000ull,32768);
    assert(plan.error && smmu_configure_bypass(&io,&plan,0xa3) && s->writes==before);
    free(s);
}
static void prepare(Engine *e,SonyGeniI2c *g) {
    memset(e,0,sizeof(*e));e->regs[0x68/4]=3u<<8;e->regs[0x48/4]=1;e->regs[0x278/4]=1;
    e->regs[0xe24/4]=(16u<<16)|(32u<<24);e->regs[0xe28/4]=(16u<<16)|(32u<<24);
    SonyGeniIo io={read_reg,write_reg,e};assert(!sony_geni_prepare(g,&io,0x28,0x30090000));
}
static void tx(Engine *e,SonyGeniI2c *g) {
    e->regs[0x610/4]=1u<<30;assert(sony_geni_poll(g)==0);
    e->regs[0x610/4]=1;assert(sony_geni_poll(g)==0);
    assert(g->phase==SonyGeniRx && e->regs[0x600/4]==((2u<<27)|(0x28u<<9)));
}
static void test_geni(void) {
    Engine e;SonyGeniI2c g;uint8_t command[]={0x26,0},bytes[132];prepare(&e,&g);
    e.regs[0xe24/4]=(64u<<16)|(32u<<24);e.regs[0xe28/4]=(64u<<16)|(32u<<24);
    SonyGeniIo versioned={read_reg,write_reg,&e};
    assert(!sony_geni_prepare(&g,&versioned,0x28,0x300a0000) && g.tx_depth==64 && g.rx_depth==64);
    assert(sony_geni_prepare(&g,&versioned,0x28,0x30090000)==-1);
    prepare(&e,&g);
    assert(!sony_geni_read(&g,command,2,bytes,sizeof(bytes)));tx(&e,&g);
    for(unsigned i=0;i<16;++i)e.rx[i]=0x03020100u+i*0x04040404u;
    e.rx_at=0;e.rx_n=16;e.regs[0x804/4]=16;e.regs[0x610/4]=1u<<26;
    assert(sony_geni_poll(&g)==0 && g.rx_done==64);
    for(unsigned i=0;i<16;++i)e.rx[16+i]=0x43424140u+i*0x04040404u;
    e.rx_n=32;e.regs[0x804/4]=16;e.regs[0x610/4]=1u<<26;
    assert(sony_geni_poll(&g)==0 && g.rx_done==128);
    e.rx[32]=0x83828180;e.rx_n=33;e.regs[0x804/4]=(1u<<31)|(4u<<28)|1;e.regs[0x610/4]=(1u<<27)|1;
    assert(sony_geni_poll(&g)==1 && g.done==1);
    for(unsigned i=0;i<sizeof(bytes);++i)assert(bytes[i]==i);
    prepare(&e,&g);assert(!sony_geni_read(&g,command,2,bytes,3));tx(&e,&g);
    e.rx[0]=0x00ccbbaa;e.rx_n=1;e.regs[0x804/4]=(1u<<31)|(3u<<28)|1;e.regs[0x610/4]=(1u<<27)|1;
    assert(sony_geni_poll(&g)==1 && !memcmp(bytes,(uint8_t[]){0xaa,0xbb,0xcc},3));
    prepare(&e,&g);assert(!sony_geni_read(&g,command,2,bytes,4));tx(&e,&g);
    e.regs[0x610/4]=1;assert(sony_geni_poll(&g)==0 && g.phase==SonyGeniCancel && g.error==SonyGeniShortRead);
    e.regs[0x610/4]=1u<<4;assert(sony_geni_poll(&g)==2);
    prepare(&e,&g);assert(!sony_geni_write(&g,command,2));assert(sony_geni_timeout(&g)==0 && g.phase==SonyGeniCancel);
    assert(sony_geni_timeout(&g)==0 && g.phase==SonyGeniAbort);assert(sony_geni_timeout(&g)==2 && g.phase==SonyGeniOffline);
    assert(sony_geni_write(&g,command,2)==-1);
    prepare(&e,&g);assert(!sony_geni_read(&g,command,2,bytes,4));tx(&e,&g);
    e.regs[0x804/4]=0x1ffffff;e.regs[0x610/4]=1u<<26;unsigned reads=e.reads;
    assert(sony_geni_poll(&g)==0 && g.error==SonyGeniInvalidFifo && e.reads-reads<5);
    prepare(&e,&g);assert(!sony_geni_write(&g,command,2));e.regs[0x610/4]=1|(1u<<10);
    assert(sony_geni_poll(&g)==0 && g.error==SonyGeniBusError && !g.done);
}
static void test_hid(void) {
    SonyHidTouchState prev={0};SonyHidTouchPlan plan;SonyHidContact now[10];
    for(unsigned i=0;i<10;++i)now[i]=(SonyHidContact){(uint8_t)i,(uint16_t)(i*3000),32767};
    assert(!sony_hid_touch_plan(&prev,now,10,&plan) && plan.count==1 && plan.reports[0][61]==10);
    prev=plan.after[0];for(unsigned i=0;i<10;++i)now[i].id=(uint8_t)(i+10);
    assert(!sony_hid_touch_plan(&prev,now,10,&plan) && plan.count==2);
    for(unsigned i=0;i<10;++i)assert(plan.reports[0][1+i*6]==2 && plan.reports[0][2+i*6]==i);
    assert(plan.after[0].count==0 && plan.after[1].count==10);
    prev=plan.after[1];assert(!sony_hid_touch_plan(&prev,0,0,&plan) && plan.count==1 && plan.after[0].count==0);
    now[0].id=now[1].id;assert(sony_hid_touch_plan(&prev,now,10,&plan)==-1);
}
int main(int argc,char **argv) {
    assert(argc==2);test_init(argv[1]);
    test_protocol();test_geni();test_dma();test_smmu();test_hid();
    puts("PASS no protected-alias access or firmware replacement; gated status visibility; FIFO/SE DMA repeated START/completion/cache/error recovery; Sony SID/bank conflict guards; SW82907 100k malformed/multi/up/palm; HID stable IDs/lifts");
    return 0;
}
