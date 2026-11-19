/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/* GICv3 ITS encodings and admission helpers, ARM IHI0069G / Linux GICv3 ITS. */
#include "SonyIts.h"
#include <string.h>

int sony_its_register_matches(uint64_t actual,uint64_t expected,uint64_t mask){
    return (actual&mask)==(expected&mask);
}

int sony_its_baser_has_owner(uint64_t value){
    return (value&SONY_ITS_BASER_OWNER_MASK)!=0;
}

int sony_its_baser_bytes_for_page(unsigned type,unsigned entry_bytes,unsigned page_bytes,uint32_t *bytes){
    uint64_t total;
    if(!bytes || (type!=SONY_ITS_GITS_BASER_TYPE_DEVICE && type!=SONY_ITS_GITS_BASER_TYPE_COLLECTION) ||
       !entry_bytes || (page_bytes!=SONY_ITS_PAGE_4K && page_bytes!=SONY_ITS_PAGE_16K && page_bytes!=SONY_ITS_PAGE_64K))return 0;
    total=(uint64_t)entry_bytes*(type==SONY_ITS_GITS_BASER_TYPE_DEVICE ? (UINT64_C(1)<<16) : (UINT64_C(1)<<SONY_ITS_COLLECTION_ID_BITS));
    total=(total+page_bytes-1)&~((uint64_t)page_bytes-1);
    if(!total || total>(uint64_t)SONY_ITS_TABLE_BYTES_MAX || total>UINT32_MAX)return 0;
    *bytes=(uint32_t)total;return 1;
}
int sony_its_baser_bytes(unsigned type,unsigned entry_bytes,uint32_t *bytes){
    return sony_its_baser_bytes_for_page(type,entry_bytes,SONY_ITS_PAGE_BYTES,bytes);
}
int sony_its_device_table_bytes(unsigned device_bits,unsigned entry_bytes,uint32_t *bytes){
    uint64_t total;
    if(!bytes || device_bits==0 || device_bits>32 || !entry_bytes)return 0;
    total=(uint64_t)entry_bytes*(UINT64_C(1)<<device_bits);
    total=(total+SONY_ITS_PAGE_BYTES-1)&~((uint64_t)SONY_ITS_PAGE_BYTES-1);
    if(!total || total>SONY_ITS_TABLE_BYTES_MAX || total>UINT32_MAX)return 0;
    *bytes=(uint32_t)total;return 1;
}
int sony_its_device_table_bytes_for_id(unsigned device_id,unsigned entry_bytes,unsigned page_bytes,uint32_t *bytes){
    uint64_t total;
    if(!bytes || !entry_bytes || (page_bytes!=SONY_ITS_PAGE_4K && page_bytes!=SONY_ITS_PAGE_16K && page_bytes!=SONY_ITS_PAGE_64K))return 0;
    total=(uint64_t)entry_bytes*((uint64_t)device_id+1u);
    total=(total+page_bytes-1)&~((uint64_t)page_bytes-1);
    if(!total || total>SONY_ITS_TABLE_BYTES_MAX || total>UINT32_MAX)return 0;
    *bytes=(uint32_t)total;return 1;
}
int sony_its_required_table_bytes(unsigned type,unsigned index,unsigned entry_bytes,unsigned page_bytes,uint32_t *bytes){
    uint64_t total;
    if(!bytes || !entry_bytes || (page_bytes!=SONY_ITS_PAGE_4K && page_bytes!=SONY_ITS_PAGE_16K && page_bytes!=SONY_ITS_PAGE_64K))return 0;
    if(type!=SONY_ITS_GITS_BASER_TYPE_DEVICE && type!=SONY_ITS_GITS_BASER_TYPE_COLLECTION)return 0;
    total=(uint64_t)entry_bytes*((uint64_t)index+1u);
    total=(total+page_bytes-1)&~((uint64_t)page_bytes-1);
    if(!total || total>SONY_ITS_TABLE_BYTES_MAX || total>UINT32_MAX)return 0;
    *bytes=(uint32_t)total;return 1;
}
int sony_its_root_table_bytes(unsigned id_bits,unsigned root_entry_bytes,unsigned page_bytes,uint32_t *bytes){
    uint64_t total;
    if(!bytes || id_bits==0 || id_bits>32 || root_entry_bytes!=8 ||
       (page_bytes!=SONY_ITS_PAGE_4K && page_bytes!=SONY_ITS_PAGE_16K && page_bytes!=SONY_ITS_PAGE_64K))return 0;
    total=(UINT64_C(1)<<id_bits)*root_entry_bytes;
    total=(total+page_bytes-1)&~((uint64_t)page_bytes-1);
    if(!total || total>SONY_ITS_TABLE_BYTES_MAX || total>UINT32_MAX)return 0;
    *bytes=(uint32_t)total;return 1;
}
int sony_its_baser_type_layout_valid(const uint64_t baser[8]){
    if(!baser)return 0;
    for(unsigned i=0;i<8;i++){
        unsigned type=(unsigned)((baser[i]>>56)&7);
        if(i<2){
            if(type!=(i==0?SONY_ITS_GITS_BASER_TYPE_DEVICE:SONY_ITS_GITS_BASER_TYPE_COLLECTION))return 0;
            if((baser[i]&SONY_ITS_GITS_BASER_VALID) || (baser[i]&SONY_ITS_BASER_PA_MASK_64K))return 0;
        }else if(type!=0 || (baser[i]&SONY_ITS_BASER_PA_MASK_64K))return 0;
    }
    return 1;
}
int sony_its_gicd_supports_lpis(uint32_t typer){return (typer&(1u<<17))!=0;}
unsigned sony_its_gicd_id_bits(uint32_t typer){return ((typer>>SONY_ITS_GICD_TYPER_IDBITS_SHIFT)&31u)+1u;}
uint64_t sony_its_gicd_lpi_count(uint32_t typer){
    const unsigned encoding=(typer&SONY_ITS_GICD_TYPER_NUM_LPIS_MASK)>>SONY_ITS_GICD_TYPER_NUM_LPIS_SHIFT;
    return encoding==0?(sony_its_gicd_id_bits(typer)>=14?((UINT64_C(1)<<sony_its_gicd_id_bits(typer))-SONY_ITS_LPI_BASE):0):(UINT64_C(1)<<(encoding+1u));
}
unsigned sony_its_gits_device_id_bits(uint64_t typer){return (unsigned)((typer>>SONY_ITS_GITS_TYPER_DEVBITS_SHIFT)&31u)+1u;}
unsigned sony_its_gits_event_id_bits(uint64_t typer){return (unsigned)((typer>>SONY_ITS_GITS_TYPER_IDBITS_SHIFT)&31u)+1u;}
unsigned sony_its_gits_itt_entry_bytes(uint64_t typer){return (unsigned)((typer>>SONY_ITS_GITS_TYPER_ITT_ENTRY_SHIFT)&15u)+1u;}
int sony_its_gits_typers_supported(uint64_t typer,uint32_t gicd_typer){
    /* GIC-600 requires ProcessorNumber targets (PTA=0), physical LPIs, and
     * memory-backed collections. GICD_TYPER.IDbits also caps PROPBASER.IDbits. */
    if(!(typer&1u) || (typer&SONY_ITS_GITS_TYPER_PTA) || (typer&(1ULL<<1)) ||
       ((typer>>SONY_ITS_GITS_TYPER_HCC_SHIFT)&0xffu)!=0)return 0;
    if(!sony_its_gicd_supports_lpis(gicd_typer) || sony_its_gicd_id_bits(gicd_typer)<14 ||
       sony_its_gicd_lpi_count(gicd_typer)<SONY_ITS_VECTOR_COUNT)return 0;
    return sony_its_gits_device_id_bits(typer)>=13 && sony_its_gits_event_id_bits(typer)>=SONY_ITS_EVENT_BITS &&
           sony_its_gits_itt_entry_bytes(typer)>=4;
}
uint64_t sony_its_baser_pagesize_value(uint64_t before,unsigned page_bytes){
    uint64_t encoding;
    switch(page_bytes){
    case SONY_ITS_PAGE_4K: encoding=0;break;
    case SONY_ITS_PAGE_16K: encoding=1;break;
    case SONY_ITS_PAGE_64K: encoding=2;break;
    default:return 0;
    }
    return (before&~SONY_ITS_GITS_BASER_PAGE_SIZE_MASK)|(encoding<<SONY_ITS_GITS_BASER_PAGE_SIZE_SHIFT);
}
uint64_t sony_its_baser_pa_bits(uint64_t physical,unsigned page_bytes){
    if(page_bytes==SONY_ITS_PAGE_64K)
        return (physical&0x0000ffffffff0000ULL)|(((physical>>48)&0xfULL)<<12);
    if(page_bytes==SONY_ITS_PAGE_4K || page_bytes==SONY_ITS_PAGE_16K)
        return physical&0x0000fffffffff000ULL;
    return 0;
}
uint64_t sony_its_baser_decode_pa(uint64_t value,unsigned page_bytes){
    if(page_bytes==SONY_ITS_PAGE_64K)
        return (value&0x0000ffffffff0000ULL)|(((value>>12)&0xfULL)<<48);
    if(page_bytes==SONY_ITS_PAGE_4K || page_bytes==SONY_ITS_PAGE_16K)
        return value&0x0000fffffffff000ULL;
    return 0;
}
int sony_its_queue_reader_valid(uint64_t reader,uint32_t writer,uint32_t queue_bytes){
    uint32_t offset=(uint32_t)(reader&SONY_ITS_READER_OFFSET_MASK);
    if((reader&1u) || (reader&~(uint64_t)(SONY_ITS_READER_OFFSET_MASK|1u)))return 0;
    if(queue_bytes<4096 || (queue_bytes&4095u) || queue_bytes>SONY_ITS_QUEUE_BYTES ||
       (writer&31u) || (offset&31u) || writer>=queue_bytes || offset>=queue_bytes)return 0;
    return 1;
}
int sony_its_queue_writer_valid(uint64_t value,uint32_t queue_bytes){
    const uint32_t offset=(uint32_t)(value&SONY_ITS_WRITER_OFFSET_MASK);
    if(value&~(uint64_t)SONY_ITS_WRITER_OFFSET_MASK)return 0;
    return queue_bytes>=4096 && (queue_bytes&4095u)==0 && queue_bytes<=SONY_ITS_QUEUE_BYTES && offset<queue_bytes;
}
unsigned sony_its_init_state_after_failure(unsigned current,int programmed,int error){
    (void)current;
    return programmed || error==0 ? 3u : 0u;
}
int sony_its_init_claim(volatile uint32_t *state,volatile uint32_t *error,uint32_t *saved_error){
    uint32_t current=__atomic_load_n(state,__ATOMIC_ACQUIRE),expected=0;
    if(saved_error)*saved_error=0;
    if(current==2)return 2;
    if(current==1)return 3;
    if(current==3){if(saved_error)*saved_error=__atomic_load_n(error,__ATOMIC_ACQUIRE);return 4;}
    if(current!=0)return 3;
    if(!__atomic_compare_exchange_n(state,&expected,1u,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return 3;
    return 1;
}
void sony_its_init_finish(volatile uint32_t *state,volatile uint32_t *error,int programmed,int failure){
    if(programmed){__atomic_store_n(error,(uint32_t)failure,__ATOMIC_RELAXED);__atomic_store_n(state,3u,__ATOMIC_RELEASE);}
    else __atomic_store_n(state,0u,__ATOMIC_RELEASE);
}
int sony_its_callback_can_publish(int callback_present,int same_owner){
    return !callback_present || same_owner;
}
uint64_t sony_its_baser_value_for_page(uint64_t before,uint64_t physical,uint32_t bytes,unsigned page_bytes){
    uint64_t value;
    if((page_bytes!=SONY_ITS_PAGE_4K && page_bytes!=SONY_ITS_PAGE_16K && page_bytes!=SONY_ITS_PAGE_64K) ||
        !bytes || (bytes%page_bytes)!=0 || physical>= (1ULL<<52) || bytes>(1ULL<<52)-physical ||
       (physical&(page_bytes-1)) || bytes/page_bytes==0 || bytes/page_bytes>256)return 0;
    value=(before&(SONY_ITS_GITS_BASER_TYPE_MASK|SONY_ITS_GITS_BASER_ENTRY_MASK))|
          SONY_ITS_GITS_BASER_VALID|SONY_ITS_GITS_BASER_INNER_NC|SONY_ITS_GITS_BASER_SHARE_IS|
          sony_its_baser_pagesize_value(0,page_bytes)|
           sony_its_baser_pa_bits(physical,page_bytes)|(((uint64_t)bytes/page_bytes)-1u);
    return value;
}
uint64_t sony_its_baser_value(uint64_t before,uint64_t physical,uint32_t bytes){
    return sony_its_baser_value_for_page(before,physical,bytes,SONY_ITS_PAGE_BYTES);
}
uint64_t sony_its_cbaser_value(uint64_t physical,uint32_t bytes){
    if(bytes<4096 || bytes>SONY_ITS_QUEUE_BYTES || (bytes&4095u) || physical>=(1ULL<<48) ||
       bytes>(1ULL<<48)-physical || (physical&4095u))return 0;
    return SONY_ITS_GITS_CBASER_VALID|SONY_ITS_GITS_BASER_INNER_NC|SONY_ITS_GITS_CBASER_SHARE_IS|
           (physical&SONY_ITS_CBASER_PA_MASK)|(bytes/4096u-1u);
}
uint64_t sony_its_propertybaser_value(uint64_t physical,unsigned id_bits){
    if(id_bits<14 || id_bits>32 || physical>=(1ULL<<52) || (physical&4095u))return 0;
    return (physical&0x000ffffffffff000ULL)|SONY_ITS_GICR_BASER_INNER_NC|SONY_ITS_GICR_BASER_SHARE_IS|((id_bits-1u)&31u);
}
uint64_t sony_its_pendingbaser_value(uint64_t physical){
    if(physical>=(1ULL<<52) || (physical&65535u))return 0;
    return (physical&0x000fffffffff0000ULL)|SONY_ITS_GICR_BASER_INNER_NC|SONY_ITS_GICR_BASER_SHARE_IS|SONY_ITS_GICR_PENDBASER_PTZ;
}
uint32_t sony_its_redist_stride(uint64_t typer){
    /* Sony's hash-bound live FDT supplies 0x40000 for this 0x20000 GICR. */
    (void)typer;
    return SONY_ITS_REDIST_STRIDE;
}
uint32_t sony_its_mpidr_affinity(uint32_t boot_mpidr_low){
    /* Sony has Aff3 == 0; the low MPIDR half also contains non-affinity flags. */
    return boot_mpidr_low&0x00ffffffu;
}
int sony_its_redists_may_share_properties(uint64_t first,uint64_t second){
    const unsigned a=(unsigned)((first>>24)&3u),b=(unsigned)((second>>24)&3u);
    const unsigned levels=a<b?a:b;
    if(!levels)return 1;
    const unsigned shift=32u+(4u-levels)*8u;
    return (first>>shift)==(second>>shift);
}
void sony_its_mapd(struct sony_its_command *c,uint32_t d,uint64_t itt,unsigned bits){
    if(!c)return;
    memset(c,0,sizeof(*c));c->word[0]=SONY_ITS_GITS_CMD_MAPD|(uint64_t)d<<32;
    c->word[1]=(bits-1u)&31u;c->word[2]=(itt&0x000fffffffffff00ULL)|(1ULL<<63);
}
void sony_its_mapc(struct sony_its_command *c,uint16_t collection,uint64_t target){
    if(!c)return;
    memset(c,0,sizeof(*c));c->word[0]=SONY_ITS_GITS_CMD_MAPC;c->word[2]=(target&0x000fffffffff0000ULL)|collection|(1ULL<<63);
}
void sony_its_mapti(struct sony_its_command *c,uint32_t d,uint32_t event,uint32_t lpi,uint16_t collection){
    if(!c)return;
    memset(c,0,sizeof(*c));c->word[0]=SONY_ITS_GITS_CMD_MAPTI|(uint64_t)d<<32;
    c->word[1]=event|(uint64_t)lpi<<32;c->word[2]=collection;
}
void sony_its_inv(struct sony_its_command *c,uint32_t device,uint32_t event){
    if(!c)return;
    memset(c,0,sizeof(*c));c->word[0]=SONY_ITS_GITS_CMD_INV|(uint64_t)device<<32;c->word[1]=event;
}
void sony_its_sync(struct sony_its_command *c,uint64_t target){
    if(!c)return;
    memset(c,0,sizeof(*c));c->word[0]=SONY_ITS_GITS_CMD_SYNC;c->word[2]=target&0x000fffffffff0000ULL;
}
