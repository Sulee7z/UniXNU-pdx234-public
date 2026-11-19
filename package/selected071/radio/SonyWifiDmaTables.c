/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include "SonyWifiDmaTables.h"
ArmSmmu4KStatus sony_wifi_dma_build(uint64_t physical,uint64_t table_physical,
    unsigned output_bits,uint64_t *tables,size_t capacity,ArmSmmu4KResult *result){
    const ArmSmmu4KConfig config={32,output_bits,table_physical,SONY_WIFI_DMA_LEAVES};
    const ArmSmmu4KRange ranges[]={
        {SONY_WIFI_DMA_IOVA,physical,SONY_WIFI_DMA_BYTES,ArmSmmu4KRead|ArmSmmu4KWrite,1,3},
        {SONY_WIFI_MSI_IOVA,SONY_WIFI_MSI_PAGE,4096,ArmSmmu4KRead|ArmSmmu4KWrite,0,2}
    };
    ArmSmmu4KStatus status=ArmSmmu4KBuild(&config,ranges,2,tables,capacity,result);
    if(status!=ArmSmmu4KSuccess)return status;
    if(result->start_level!=1 || result->table_pages!=SONY_WIFI_DMA_TABLE_PAGES ||
        result->leaf_pages!=SONY_WIFI_DMA_LEAVES)return ArmSmmu4KStateMismatch;
    size_t table=0;
    const uint64_t mask=UINT64_C(0x0000fffffffff000);
    for(unsigned level=1;level<3;level++){
        uint64_t entry=tables[table*512+((SONY_WIFI_MSI_IOVA>>(39-9*level))&511)];
        uint64_t page=entry&mask;
        if((entry&3)!=3 || page<table_physical || (page-table_physical)/4096>=result->table_pages)
            return ArmSmmu4KStateMismatch;
        table=(size_t)((page-table_physical)/4096);
    }
    uint64_t *leaf=&tables[table*512+((SONY_WIFI_MSI_IOVA>>12)&511)];
    const uint64_t expected=SONY_WIFI_MSI_PAGE|(UINT64_C(3)<<53)|(2u<<8)|(1u<<11)|(1u<<10)|(1u<<6)|3u;
    if(*leaf!=expected || result->mair!=UINT64_C(0xff44))return ArmSmmu4KStateMismatch;
    *leaf=expected|(2u<<2); /* Index2, MAIR[23:16]=0: Device-nGnRnE. */
    return ArmSmmu4KSuccess;
}
