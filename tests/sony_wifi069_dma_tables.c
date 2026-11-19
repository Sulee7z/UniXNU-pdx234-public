/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "SonyWifiDmaTables.h"
#include "ArmSmmu4KProgram.h"

static uint64_t tables[96*512],before[96*512];
static const uint64_t pool=UINT64_C(0x9a0000000),ram=UINT64_C(0x980000000);
static const uint64_t address_mask=UINT64_C(0x0000fffffffff000);
static unsigned seen[96],walk_tables,walk_leaves;

static void walk(size_t page,unsigned level,uint64_t prefix){
    assert(page<SONY_WIFI_DMA_TABLE_PAGES && !seen[page]++);
    ++walk_tables;
    for(unsigned slot=0;slot<512;slot++){
        const uint64_t entry=tables[page*512+slot];
        const unsigned shift=39-9*level;
        const uint64_t iova=prefix|((uint64_t)slot<<shift);
        if(!entry)continue;
        assert((entry&3)==3);
        if(level<3){
            const uint64_t next=entry&address_mask;
            assert(next>=pool && next-pool<SONY_WIFI_DMA_TABLE_PAGES*4096u);
            walk((size_t)((next-pool)/4096),level+1,iova);
        }else{
            ++walk_leaves;
            const uint64_t flags=(UINT64_C(3)<<53)|(1u<<11)|(1u<<10)|(1u<<6)|3u;
            if(iova>=SONY_WIFI_DMA_IOVA && iova-SONY_WIFI_DMA_IOVA<SONY_WIFI_DMA_BYTES)
                assert(entry==((ram+iova-SONY_WIFI_DMA_IOVA)|flags|(3u<<8)|(1u<<2)));
            else{
                assert(iova==SONY_WIFI_MSI_IOVA);
                assert(entry==(SONY_WIFI_MSI_PAGE|flags|(2u<<8)|(2u<<2)));
                assert((entry&address_mask)+SONY_WIFI_MSI_OFFSET==UINT64_C(0x17150040));
                assert((entry&(1u<<7))==0); // writable MSI, never the old read-only leaf
            }
        }
    }
}

static uint32_t regs[0x100000/4];
static unsigned writes,polls,stuck;
static int read32(void *context,size_t at,uint32_t *out){
    (void)context;assert(!(at&3)&&at<sizeof(regs));*out=regs[at/4];
    if((at&0xfff)==0x7f4){polls++;if(stuck)*out=1;}
    return 0;
}
static int read64(void *context,size_t at,uint64_t *out){
    (void)context;assert(!(at&7)&&at+8<=sizeof(regs));memcpy(out,(uint8_t *)regs+at,8);return 0;
}
static int write32(void *context,size_t at,uint32_t value){
    (void)context;assert(!(at&3)&&at<sizeof(regs));writes++;
    if((at&0xfff)==0x58)regs[at/4]&=~value;else regs[at/4]=value;return 0;
}
static int write64(void *context,size_t at,uint64_t value){
    (void)context;assert(!(at&7)&&at+8<=sizeof(regs));writes++;memcpy((uint8_t *)regs+at,&value,8);return 0;
}
static int barrier(void *context){(void)context;return 0;}
static void reset(void){
    memset(regs,0,sizeof(regs));writes=polls=stuck=0;
    regs[0x20/4]=(1u<<30)|(1u<<27)|(1u<<14)|128;
    regs[0x24/4]=0x60000050; //128 register pages,80 banks
    regs[0x28/4]=(1u<<12)|(5u<<8)|(5u<<4)|5u;
}

int main(void){
    ArmSmmu4KResult result={0};
    memset(tables,0xa5,sizeof(tables));memcpy(before,tables,sizeof(tables));
    assert(sony_wifi_dma_build(ram,pool,48,tables,66,&result)==ArmSmmu4KCapacity);
    assert(!memcmp(tables,before,sizeof(tables)) && result.table_pages==0);
    assert(sony_wifi_dma_build(ram+1,pool,48,tables,96,&result)==ArmSmmu4KBadRange);
    assert(!memcmp(tables,before,sizeof(tables)));
    assert(sony_wifi_dma_build(ram,pool,32,tables,96,&result)==ArmSmmu4KBadRange);
    assert(!memcmp(tables,before,sizeof(tables)));
    assert(sony_wifi_dma_build(ram,pool,48,tables,96,&result)==ArmSmmu4KSuccess);
    assert(result.table_pages==67 && result.leaf_pages==32769 && result.start_level==1 && result.mair==0xff44);
    walk(0,1,0);assert(walk_tables==67 && walk_leaves==32769);
    assert(!memcmp(tables+67*512,before+67*512,(96-67)*4096));
    // Exact previous failures: capacity != leaf budget; doorbell is offset40
    // inside the physical MSI page, not an unaligned page base.
    ArmSmmu4KConfig old={32,48,pool,96};
    ArmSmmu4KRange dma={SONY_WIFI_DMA_IOVA,ram,SONY_WIFI_DMA_BYTES,3,1,3};
    assert(ArmSmmu4KBuild(&old,&dma,1,tables,96,&result)==ArmSmmu4KBudget);
    old.leaf_budget=32769;
    ArmSmmu4KRange wrong={SONY_WIFI_MSI_IOVA,SONY_WIFI_MSI_PAGE+0x40,4096,1,0,0};
    assert(ArmSmmu4KBuild(&old,&wrong,1,tables,96,&result)==ArmSmmu4KBadRange);
    assert(sony_wifi_dma_build(ram,pool,48,tables,96,&result)==ArmSmmu4KSuccess);
    reset();const unsigned bank=2,cb=(128+bank)*4096;
    const ArmSmmu4KConfig config={32,48,pool,32769};
    ArmSmmu4KContextConfig context={.lower=&config,.lower_tables=&result,.asid=19,.coherent_walk=1};
    ArmSmmu4KIo io={NULL,sizeof(regs),read32,read64,write32,write64,barrier};
    ArmSmmu4KProgramResult programmed;
    assert(ArmSmmu4KProgramDisabledContext(&io,bank,&context,32,&programmed)==ArmSmmu4KSuccess);
    uint64_t ttbr=0;memcpy(&ttbr,(uint8_t *)regs+cb+0x20,8);
    assert(ttbr==(pool|(UINT64_C(19)<<48)) && programmed.context_offset==cb && programmed.enabled);
    assert(regs[(cb+0x10)/4]==((7u<<15)|(1u<<4)|5u));
    assert(regs[(cb+0x30)/4]==((2u<<30)|(1u<<23)|0x3500u|32u));
    assert((regs[cb/4]&0x61)==0x61 && regs[(cb+0x38)/4]==0xff44);
    unsigned previous_writes=writes;
    assert(ArmSmmu4KProgramDisabledContext(&io,bank,&context,32,&programmed)==ArmSmmu4KBusy);
    assert(writes==previous_writes);
    reset();io.register_bytes=0xd0000;
    assert(ArmSmmu4KProgramDisabledContext(&io,bank,&context,32,&programmed)==ArmSmmu4KUnsupported);
    assert(writes==0);io.register_bytes=sizeof(regs);
    reset();stuck=1;
    assert(ArmSmmu4KProgramDisabledContext(&io,bank,&context,8,&programmed)==ArmSmmu4KTimeout);
    assert(programmed.must_retain_tables && !programmed.enabled && polls<=16);
    puts("all32769 leaves /67 tables /MSI Device-RW-XN /old failures /official context registers and refusal paths PASS; hardware NOT tested");
    return 0;
}
