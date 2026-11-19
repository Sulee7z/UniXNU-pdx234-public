/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <IOKit/IOLib.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <kern/task.h>
#include <sys/errno.h>
#include "SonySharedResources.h"
#include "SmmuBypass.h"
namespace {
IOMemoryMap *mapping;
volatile uint32_t *registers;
bool prepared;uint64_t prepared_pa;uint32_t prepared_bytes;
unsigned prepared_slot,prepared_bank;
uint32_t rd(void *,unsigned reg){return registers[reg/4];}
void wr(void *,unsigned reg,uint32_t value){registers[reg/4]=value;__asm__ volatile("dsb sy":::"memory");}
}
extern "C" int sony_radio_bluetooth_dma(uint64_t physical,uint32_t bytes,unsigned *slot,unsigned *bank){
    if(!physical || !bytes || !slot || !bank)return EINVAL;
    int e=sony_shared_config_lock();if(e)return e;
    if(prepared){
        e=(physical==prepared_pa && bytes==prepared_bytes)?0:EBUSY;
        if(!e){*slot=prepared_slot;*bank=prepared_bank;}sony_shared_config_unlock();return e;
    }
    if(!registers){
        IODeviceMemory *memory=IODeviceMemory::withRange(0x15000000,0xd0000);
        if(memory){mapping=memory->map(kIOMapAnywhere|kIOMapInhibitCache);memory->release();}
        if(mapping)registers=reinterpret_cast<volatile uint32_t *>(mapping->getVirtualAddress());
    }
    if(!registers){sony_shared_config_unlock();return ENOMEM;}
    const smmu_io io={nullptr,rd,wr};
    const smmu_plan plan=smmu_plan_bypass(&io,0x423,physical,bytes);
    const char *failure=plan.error?plan.error:smmu_configure_bypass(&io,&plan,0x423);
    if(failure){IOLog("[sony069-bt-dma] slot=%u bank=%u error=%s\n",plan.slot,plan.bank,failure);e=EBUSY;}
    else{prepared=true;prepared_pa=physical;prepared_bytes=bytes;prepared_slot=plan.slot;prepared_bank=plan.bank;
        *slot=plan.slot;*bank=plan.bank;}
    sony_shared_config_unlock();return e;
}
