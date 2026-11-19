/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include "SonyIts.h"

static uint32_t armcpu_gic_ready=1,armcpu_boot_mpidr=0x80000300;
static int sony_shared_config_lock(){return 0;}
static void sony_shared_config_unlock(){}
static void IODelay(unsigned){}
#define SONY_WIFI_MSI_IOVA 0x1fff0000u
#define SONY_WIFI_MSI_OFFSET 0x40u

namespace {
struct Map {uint64_t physical,bytes;};
struct Memory {uint8_t *va;uint64_t pa;uint32_t bytes;};
Map its,redists;
Memory queue,itt,properties,boot_pending,tables[8];
uint32_t writer;uint64_t target;
volatile uint32_t ready,init_state,init_error;
void (*deliver)(void *,uint32_t);void *deliver_context;
uint64_t basers[8],controls[8],typers[8],prop[8],pend[8],cbaser,reader,its_ctl=1u<<31;
const unsigned boot=3;
unsigned page,allocations,live,writes,commands,fail_alloc;
bool refuse_restore,fail_commit,stall,refuse_pages;
enum {device=0,collection=1};

uint64_t read64(const Map &m,uint32_t r){
    if(&m==&its){
        if(r==8)return 1u|(7u<<4)|(4u<<8)|(31u<<13);
        if(r==0x80)return cbaser;
        if(r==0x90)return reader;
        assert(r>=0x100 && r<0x140);return basers[(r-0x100)/8];
    }
    unsigned i=r/SONY_ITS_REDIST_STRIDE;assert(i<8);
    switch(r%SONY_ITS_REDIST_STRIDE){case 8:return typers[i];case 0x70:return prop[i];case 0x78:return pend[i];}
    abort();
}
uint32_t read32(const Map &m,uint32_t r){
    if(&m==&its){assert(r==0 || r==0xffe8);return r==0?its_ctl:0x30;}
    assert(r%SONY_ITS_REDIST_STRIDE==0);return controls[r/SONY_ITS_REDIST_STRIDE];
}
void write64(const Map &m,uint32_t r,uint64_t v){
    ++writes;
    if(&m==&its){
        if(r==0x80){cbaser=v;return;}
        if(r==0x88){
            if(!v && !commands){reader=0;return;}
            assert(v==32*(commands+1u));
            sony_its_command c{};memcpy(&c,queue.va+32*commands,sizeof(c));
            if(!commands)assert(c.word[0]==9 && (c.word[2]&~(1ULL<<63))==(7u<<16));
            if(commands==2)assert(c.word[0]==(8ULL|(uint64_t(SONY_ITS_DEVICE_ID)<<32)) && c.word[1]==4);
            if(commands>=3 && commands<35)assert(c.word[1]==((uint64_t(8192+commands-3)<<32)|(commands-3)));
            ++commands;reader=stall?1:v;return;
        }
        assert(r>=0x100 && r<0x140 && its_ctl==(1ULL<<31));
        auto &reg=basers[(r-0x100)/8];
        if(v&SONY_ITS_GITS_BASER_VALID){reg=fail_commit?v^0x1000:v;return;}
        if(refuse_restore && writes==2){reg=v^1u;return;}
        reg=(v&~SONY_ITS_GITS_BASER_PAGE_SIZE_MASK)|
            (uint64_t(refuse_pages && (writes%2)?3:page)<<SONY_ITS_GITS_BASER_PAGE_SIZE_SHIFT);
        return;
    }
    assert(r/SONY_ITS_REDIST_STRIDE==boot);
    if(r%SONY_ITS_REDIST_STRIDE==0x70)prop[boot]=v;
    else {assert(r%SONY_ITS_REDIST_STRIDE==0x78);pend[boot]=v&~SONY_ITS_GICR_PENDBASER_PTZ;}
}
void write32(const Map &m,uint32_t r,uint32_t v){
    ++writes;
    if(&m==&its){assert(!r);its_ctl=v;}
    else {assert(r==boot*SONY_ITS_REDIST_STRIDE);controls[boot]=v;}
}
void clean(void *,size_t){}
bool mapping(Map &m,uint64_t base,uint64_t bytes){m={base,bytes};return true;}
bool allocate(Memory &m,uint32_t bytes,uint32_t align){
    if(++allocations==fail_alloc)return false;
    m={static_cast<uint8_t *>(calloc(1,bytes)),0x1000000u*allocations,bytes};
    assert(m.va && !(m.pa&(align-1)));++live;return true;
}
void release(Memory &m){if(m.va){free(m.va);assert(live);--live;}m={};}
}
#include "its_init_actual.inc"

static unsigned delivered;
static void callback(void *ctx,uint32_t bits){assert(ctx==&delivered);delivered|=bits;}
int main(int argc,char **argv){
    assert(argc==2);const char *name=argv[1];int expected=0;
    if(!strcmp(name,"16k"))page=1;
    else if(!strcmp(name,"64k"))page=2;
    else if(!strcmp(name,"foreign-baser")){basers[0]=1u<<12;expected=EBUSY;}
    else if(!strcmp(name,"foreign-peer")){controls[5]=1;expected=EBUSY;}
    else if(!strcmp(name,"foreign-properties")){prop[5]=0x100000;expected=EBUSY;}
    else if(!strcmp(name,"probe-restore")){refuse_restore=true;expected=EIO;}
    else if(!strcmp(name,"no-page")){refuse_pages=true;expected=ENOTSUP;}
    else if(!strcmp(name,"alloc")){fail_alloc=6;expected=ENOMEM;}
    else if(!strcmp(name,"commit-readback")){fail_commit=true;expected=EIO;}
    else if(!strcmp(name,"stalled")){stall=true;expected=EIO;}
    else assert(!strcmp(name,"4k"));
    for(unsigned i=0;i<8;i++)typers[i]=(uint64_t(i)<<40)|1u|((4u+i)<<8)|(i==7?16u:0);
    basers[device]|=(1ULL<<56)|(7ULL<<48)|(uint64_t(page)<<8);
    basers[collection]=(4ULL<<56)|(uint64_t(page)<<8);
    assert(sony069_its_attach(callback,&delivered)==expected);
    if(!expected){
        const unsigned bytes[]={4096,16384,65536};
        assert(live==6 && commands==36 && ready==1 && init_state==2);
        assert(controls[boot]==1 && prop[boot] && pend[boot] && !prop[0] && !pend[0]);
        assert(tables[collection].bytes==bytes[page] && tables[device].bytes>=8u*(SONY_ITS_DEVICE_ID+1));
        assert(((basers[device]>>8)&3)==page && ((basers[collection]>>8)&3)==page);
        assert(sony_radio_lpi_dispatch(8192) && sony_radio_lpi_dispatch(8223) && delivered==0x80000001u);
        assert(!sony_radio_lpi_dispatch(8224));
        assert(sony069_its_attach(callback,nullptr)==EBUSY);
    } else if(expected==EIO){
        assert(init_state==3 && !ready && !sony_radio_lpi_dispatch(8192));
        assert(live==(refuse_restore?0u:6u));
        const unsigned before=writes;
        assert(sony069_its_attach(callback,&delivered)==EIO && writes==before);
    } else {
        assert(!init_state && !ready && !live && !deliver);
        if(expected==EBUSY)assert(!writes && !allocations);
        if(expected==ENOMEM){fail_alloc=0;assert(!sony069_its_attach(callback,&delivered));}
    }
    assert(sony_its_redists_may_share_properties(0,UINT64_MAX));
    assert(sony_its_redists_may_share_properties(3ULL<<24,(3ULL<<24)|(1ULL<<32)));
    assert(!sony_its_redists_may_share_properties(3ULL<<24,(3ULL<<24)|(1ULL<<40)));
    // Fixture teardown only, after modeled hardware access has ended.
    release_preflight_allocations();assert(!live);
}
