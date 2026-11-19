/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "SonyRpmh.h"
#include "SonyVotes.h"
#include "SonyIts.h"
#include "SonyCommandDb.h"
struct Registers {uint32_t values[16384];unsigned trigger,tcs,delay;int timeout,refused;uint32_t remote[16];};
static uint32_t read32(void *p,uint32_t reg){return ((struct Registers *)p)->values[reg/4];}
static void write32(void *p,uint32_t reg,uint32_t value){
    struct Registers *m=p;
    if(reg==0xd08){m->values[0xd04/4]&=~value;return;}
    m->values[reg/4]=value;
    for(unsigned i=0;i<3;i++){
        unsigned base=0xd00+i*672;
        if(reg==base+0x24 && value==((1u<<16)|(1u<<24))){
            m->trigger++;m->tcs=i;
            if(m->timeout)return;
            unsigned address=m->values[(base+0x38)/4];
            uint32_t message=m->values[(base+0x34)/4];
            if(message&(1u<<16))m->remote[(address-0x1000)/4]=m->values[(base+0x3c)/4];
            else m->values[(base+0x44)/4]=m->remote[(address-0x1000)/4];
            m->values[0xd04/4]|=1u<<i;m->values[(base+0x40)/4]=m->refused?0:((1u<<8)|(1u<<16));
        }
    }
}
static void pause_us(void *p,unsigned us){((struct Registers *)p)->delay+=us;}
static void init(struct Registers *m){memset(m,0,sizeof(*m));m->values[0]=3u<<16;m->values[3]=(3u<<12)|(16u<<27);
    for(unsigned i=0;i<3;i++)m->values[(0xd00+i*672+0x28)/4]=1;}
static void rpmh_test(void){
    struct Registers m;init(&m);struct sony_rpmh r;const struct sony_rpmh_io io={&m,read32,write32,pause_us,0};
    assert(!sony_rpmh_init(&r,&io,0xd00,2,7));
    m.values[(0xd00+2*672+0x2c)/4]=1; // retained command blocksTCS2
    m.values[0xd00/4]=0x40;m.remote[0]=975;uint32_t value=0;
    assert(!sony_rpmh_transfer(&r,0x1000,false,&value) && value==975 && m.tcs==1);
    assert(m.values[0xd00/4]==0x40 && m.values[(0xd00+2*672+0x2c)/4]==1);
    value=1000;assert(!sony_rpmh_transfer(&r,0x1000,true,&value) && m.remote[0]==1000);
    m.timeout=1;assert(sony_rpmh_transfer(&r,0x1000,true,&value)==ETIMEDOUT && (r.poisoned&2));
    m.timeout=0;assert(!sony_rpmh_transfer(&r,0x1000,false,&value) && m.tcs==0);
    m.values[(0xd00+0x2c)/4]=1;assert(sony_rpmh_transfer(&r,0x1000,false,&value)==EBUSY);
}
struct Remote {uint32_t words[8];unsigned writes;unsigned fail;};
static int transfer(void *p,uint32_t addr,bool write,uint32_t *v){struct Remote *r=p;unsigned i=(addr-0x1000)/4;assert(i<8);
    if(write){r->writes++;if(r->fail==r->writes)return ETIMEDOUT;r->words[i]=*v;}else *v=r->words[i];return 0;}
static void votes_test(void){
    struct Remote m={{850,1,4},0,0};const struct sony_vote_io io={&m,transfer};
    struct sony_vote_resource r={.address=0x1000,.min_uv=500000,.max_uv=1200000};
    assert(!sony_vote_update(&r,&io,0,7,1000000,true));assert(m.words[0]==1000 && m.words[1]==1 && m.words[2]==7);
    unsigned n=m.writes;assert(!sony_vote_update(&r,&io,0,7,1000000,true) && m.writes==n);
    assert(!sony_vote_update(&r,&io,1,7,1100000,true));assert(m.words[0]==1100);
    assert(!sony_vote_update(&r,&io,0,7,0,false) && m.words[0]==1100);
    assert(!sony_vote_update(&r,&io,1,7,0,false));assert(m.words[0]==850 && m.words[1]==1 && m.words[2]==4);
    assert(sony_vote_update(&r,&io,0,7,1300000,true)==ERANGE);
    m.fail=m.writes+1;assert(sony_vote_update(&r,&io,0,7,1000000,true)==ETIMEDOUT && r.poisoned);
    assert(sony_vote_update(&r,&io,0,7,1000000,true)==EIO);
    struct Remote b={{0x123},0,0};struct sony_bcm_resource bcm={.address=0x1000,.unit=1000,.width=16};
    const struct sony_vote_io bi={&b,transfer};assert(!sony_bcm_update(&bcm,&bi,0,100,200));
    assert(!sony_bcm_update(&bcm,&bi,1,100,300));assert(!sony_bcm_update(&bcm,&bi,0,0,0));
    assert(!sony_bcm_update(&bcm,&bi,1,0,0) && b.words[0]==0x123);
    struct Remote a={{2},0,0};const struct sony_vote_io ai={&a,transfer};
    struct sony_arc_resource arc={.address=0x1000};
    assert(!sony_arc_update(&arc,&ai,0,5,true)&&a.words[0]==5);
    assert(!sony_arc_update(&arc,&ai,1,6,true)&&a.words[0]==6);
    assert(!sony_arc_update(&arc,&ai,0,0,false)&&a.words[0]==6);
    assert(!sony_arc_update(&arc,&ai,1,0,false)&&a.words[0]==2);
    a.fail=a.writes+1;assert(sony_arc_update(&arc,&ai,0,5,true)==ETIMEDOUT&&arc.poisoned);
    assert(sony_arc_update(&arc,&ai,0,0,false)==EIO);
}
static void cmd_db_test(void){
    uint8_t data[512]={0};uint32_t v=0x0c0330db;memcpy(data+4,&v,4);
    data[8]=3;data[12]=64;data[14]=1;
    memcpy(data+144,"mx.lvl",6);v=0x30010;memcpy(data+160,&v,4);data[164]=12;
    uint16_t levels[]={0,48,64,128,256,384};memcpy(data+208,levels,sizeof(levels));
    struct sony_cmd_resource r={0};uint32_t index=99;
    assert(!sony_cmd_db_find(data,sizeof(data),"mx.lvl",3,&r));
    assert(!sony_cmd_arc_index(&r,384,&index)&&index==5);
    assert(!sony_cmd_arc_index(&r,129,&index)&&index==4);
    assert(sony_cmd_arc_index(&r,385,&index)==ERANGE);
    assert(sony_cmd_db_find(data,sizeof(data),"mx.lvl",5,&r)==EINVAL);
    assert(sony_cmd_db_find(data,sizeof(data),"absent",3,&r)==ENOENT);
    uint8_t aux[]={0xe8,3,0,0,16,0,2,0};uint32_t unit=0,width=0,vcd=0;
    r=(struct sony_cmd_resource){0x50004,aux,sizeof(aux),5};
    assert(!sony_cmd_bcm_aux(&r,&unit,&width,&vcd)&&unit==1000&&width==16&&vcd==2);
    aux[7]=1;assert(sony_cmd_bcm_aux(&r,&unit,&width,&vcd)==EINVAL);
}
static void its_test(void){struct sony_its_command c;sony_its_mapd(&c,0x1401,0x123400,5);
    assert(c.word[0]==(8ULL|(0x1401ULL<<32)) && c.word[1]==4 && c.word[2]==((1ULL<<63)|0x123400));
    sony_its_mapc(&c,0,0x17180000);assert(c.word[0]==9 && c.word[2]==((1ULL<<63)|0x17180000));
    for(unsigned i=0;i<32;i++){sony_its_mapti(&c,0x1401,i,8192+i,0);assert(c.word[1]==(i|((uint64_t)(8192+i)<<32)));}
    sony_its_sync(&c,0x17180000);assert(c.word[0]==5 && c.word[2]==0x17180000);
}
int main(void){rpmh_test();votes_test();cmd_db_test();its_test();puts("PASS069 RSC reservation/read/ACK/poison, boot-vote restore, rail/BCM/ARC ownership, raw cmd-db aux and exact32ITS encodings");}
