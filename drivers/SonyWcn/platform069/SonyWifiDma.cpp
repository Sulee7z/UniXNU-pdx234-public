/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <IOKit/IOLib.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <kern/task.h>
#include <sys/errno.h>
#include "SonySharedResources.h"
#include "Sm8550AppsSmmu.h"
#include "SonyWifiDmaTables.h"
#include "ArmSmmu4KMmio.h"
#include "SonyResources.generated.h"

extern "C" int armcpu_spi_attach(uint32_t,bool,void (*)(void *),void *,uint32_t *,uint64_t *);
extern "C" {
uint8_t *sony069_wifi_dma_va;
volatile uint32_t sony069_wifi_dma_stream,sony069_wifi_dma_uncached,sony069_wifi_dma_iova,sony069_wifi_dma_bytes;
volatile uint32_t sony069_wifi_dma_atos[8];
}
namespace {
IOMemoryMap *map;volatile uint32_t *regs;
IOBufferMemoryDescriptor *buffer,*table_memory;
sm8550_apps_smmu_domain domain;
uint64_t physical,tables_pa;uint64_t *tables;
bool active,poisoned;
constexpr uint64_t iova=SONY_WIFI_DMA_IOVA;
constexpr uint32_t bytes=SONY_WIFI_DMA_BYTES,table_pages=SONY_WIFI_DMA_TABLE_PAGES;
ArmSmmu4KMmio mmio;ArmSmmu4KIo context_io;
ArmSmmu4KProgramResult programmed;
uint32_t fault_context;
uint32_t fault_snapshot[4],fault_count;
uint32_t rd(void *,uint32_t offset){return regs[offset/4];}
void wr(void *,uint32_t offset,uint32_t value){regs[offset/4]=value;__asm__ volatile("dsb sy":::"memory");}
void fault_irq(void *){
    const uint32_t cb=__atomic_load_n(&fault_context,__ATOMIC_ACQUIRE);
    if(!cb)return;
    const uint32_t status=rd(nullptr,cb+0x58);
    if(!(status&0xc00001feu))return;
    __atomic_store_n(&fault_snapshot[0],status,__ATOMIC_RELAXED);
    __atomic_store_n(&fault_snapshot[1],rd(nullptr,cb+0x60),__ATOMIC_RELAXED);
    __atomic_store_n(&fault_snapshot[2],rd(nullptr,cb+0x64),__ATOMIC_RELAXED);
    __atomic_store_n(&fault_snapshot[3],rd(nullptr,cb+0x68),__ATOMIC_RELAXED);
    __atomic_fetch_add(&fault_count,1u,__ATOMIC_RELEASE);
    // Linux arm_smmu_context_fault: clear this bank only, terminate a stalled access.
    wr(nullptr,cb+0x58,status);
    if(status&(1u<<30))wr(nullptr,cb+0x8,1);
}
void publish(void *ptr,size_t size){
    uint64_t ctr;__asm__ volatile("mrs %0,ctr_el0":"=r"(ctr));uintptr_t line=4u<<((ctr>>16)&15);
    for(uintptr_t at=(uintptr_t)ptr&~(line-1),end=(uintptr_t)ptr+size;at<end;at+=line) {
        __asm__ volatile("dc cvac,%0"::"r"(at):"memory");
    }
    __asm__ volatile("dsb sy":::"memory");
}
}
extern "C" int sony069_wifi_dma_prepare(){
    int e=sony_shared_config_lock();if(e)return e;
    if(__atomic_load_n(&active,__ATOMIC_ACQUIRE)){sony_shared_config_unlock();return 0;}
    if(poisoned){sony_shared_config_unlock();return EIO;}
    if(!regs){IODeviceMemory *memory=IODeviceMemory::withRange(SONY_APPS_SMMU_REG_BASE,SONY_APPS_SMMU_REG_BYTES);
        if(memory){map=memory->map(kIOMapAnywhere|kIOMapInhibitCache);memory->release();}
        if(map)regs=reinterpret_cast<volatile uint32_t *>(map->getVirtualAddress());}
    if(!regs){sony_shared_config_unlock();return ENOMEM;}
    const sm8550_apps_smmu_io io={nullptr,rd,wr};const uint16_t sid=0x1401;
    e=sm8550_apps_smmu_pick(&io,&sid,1,&domain);
    if(e){sony_shared_config_unlock();return -e;}
    const uint32_t cb=(domain.pages+domain.bank)*4096u;
    // The picker requires 4KiB register pages. Keep the firmware's final
    // bypass bank and stage-2-only slots outside our context ownership.
    if(domain.bank>=sizeof(kSonyAppsSmmuContextIrqs)/sizeof(kSonyAppsSmmuContextIrqs[0]) ||
       domain.bank<((domain.id1>>16)&255u) || domain.bank+1>=(domain.id1&255u) ||
       cb>SONY_APPS_SMMU_REG_BYTES-0x7f8 || rd(nullptr,cb+4)){
        sony_shared_config_unlock();return ENOTSUP;
    }
    const IOOptionBits flags=(IOOptionBits)kIODirectionInOut|(IOOptionBits)kIOMemoryPhysicallyContiguous|(IOOptionBits)kIOMemoryMapperNone;
    if(!buffer)buffer=IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task,flags,bytes,2u*1024*1024);
    if(!table_memory)table_memory=IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task,flags,table_pages*4096,4096);
    if(!buffer || !table_memory){sony_shared_config_unlock();return ENOMEM;}
    IOByteCount span=0;physical=buffer->getPhysicalSegment(0,&span,kIOMemoryMapperNone);
    if(!physical || span<bytes || physical>((UINT64_C(1)<<48)-bytes)){sony_shared_config_unlock();return EIO;}
    tables_pa=table_memory->getPhysicalSegment(0,&span,kIOMemoryMapperNone);
    if(!tables_pa || (tables_pa&4095) || span<table_pages*4096 || tables_pa>((UINT64_C(1)<<48)-table_pages*4096)){sony_shared_config_unlock();return EIO;}
    tables=static_cast<uint64_t *>(table_memory->getBytesNoCopy());
    uint8_t *cpu=static_cast<uint8_t *>(buffer->getBytesNoCopy());
    if(!tables || !cpu){sony_shared_config_unlock();return EIO;}
    unsigned widths[]={32,36,40,42,44,48};unsigned code=(domain.id2>>4)&15;
    if(code>=6){sony_shared_config_unlock();return ENOTSUP;}
    // Capacity counts table pages; leaf_budget counts all32769 mapped pages.
    // 32-bit IOVA needs one L1, one L2 and65 L3 pages, including MSI.
    ArmSmmu4KConfig config={32,widths[code],tables_pa,SONY_WIFI_DMA_LEAVES};
    ArmSmmu4KResult result={};
    if(sony_wifi_dma_build(physical,tables_pa,widths[code],tables,table_pages,&result)!=ArmSmmu4KSuccess){sony_shared_config_unlock();return EINVAL;}
    publish(tables,result.table_pages*4096);
    mmio={reinterpret_cast<volatile unsigned char *>(regs),SONY_APPS_SMMU_REG_BYTES};
    if(ArmSmmu4KBindMmio(&mmio,&context_io)!=ArmSmmu4KSuccess){sony_shared_config_unlock();return EINVAL;}
    ArmSmmu4KContextConfig context={};context.lower=&config;context.lower_tables=&result;
    context.id0=domain.id0;context.id2=domain.id2;context.asid=domain.asid;
    context.coherent_walk=(domain.id0>>14)&1u; // Sony DT dma-coherent, SMMU ID0.CTTW
    ArmSmmu4KContextImage image={};
    if(ArmSmmu4KEncodeContext(&context,&image)!=ArmSmmu4KSuccess){sony_shared_config_unlock();return ENOTSUP;}
    // Linux arm-smmu v2 uses the context bank index into the ordered DT IRQ
    // list after the global IRQ. No CBAR.IRPTNDX write on SMMUv2.
    uint32_t irq_state=0;
    __atomic_store_n(&fault_context,cb,__ATOMIC_RELEASE);
    const int irq=armcpu_spi_attach(kSonyAppsSmmuContextIrqs[domain.bank],false,fault_irq,nullptr,&irq_state,nullptr);
    if(irq || (irq_state&7u)!=3u){
        __atomic_store_n(&fault_context,0u,__ATOMIC_RELEASE);
        poisoned=!irq;sony_shared_config_unlock();return EIO;
    }
    poisoned=true;
    ArmSmmu4KStatus status=ArmSmmu4KProgramDisabledContext(&context_io,domain.bank,&context,10000,&programmed);
    if(status!=ArmSmmu4KSuccess || programmed.context_offset!=cb || __atomic_load_n(&fault_count,__ATOMIC_ACQUIRE)){
        sony_shared_config_unlock();return status==ArmSmmu4KTimeout?ETIMEDOUT:EIO;
    }
    e=sm8550_apps_smmu_route(&io,&domain);
    if(e){(void)ArmSmmu4KDisableOwnedContext(&context_io,domain.bank,&context,10000,&programmed);
        sony_shared_config_unlock();return -e;}
    sony069_wifi_dma_va=cpu;sony069_wifi_dma_iova=iova;sony069_wifi_dma_bytes=bytes;sony069_wifi_dma_uncached=0;
    sony069_wifi_dma_stream=sid;__atomic_store_n(&active,true,__ATOMIC_RELEASE);poisoned=false;
    IOLog("[sony069-wifi-dma] SID1401 slot%u bank%u ASID%u faultIRQ%u pa%llx bytes%u MSI%llx->%llx\n",
        domain.slots[0],domain.bank,domain.asid,kSonyAppsSmmuContextIrqs[domain.bank],physical,bytes,
        SONY_WIFI_MSI_IOVA+SONY_WIFI_MSI_OFFSET,SONY_WIFI_MSI_PAGE+SONY_WIFI_MSI_OFFSET);
    sony_shared_config_unlock();return 0;
}
extern "C" bool sony069_wifi_dma_faulted(void){return __atomic_load_n(&fault_count,__ATOMIC_ACQUIRE)!=0;}
extern "C" int sony069_wifi_dma_fault(uint32_t *out){
    if(!out || !__atomic_load_n(&active,__ATOMIC_ACQUIRE))return ENXIO;
    const unsigned cb=(unsigned)programmed.context_offset;
    out[0]=rd(nullptr,0x48);out[1]=domain.bank;out[2]=rd(nullptr,cb+0x58);
    out[3]=rd(nullptr,cb+0x60);out[4]=rd(nullptr,cb+0x64);out[5]=rd(nullptr,cb+0x68);out[6]=rd(nullptr,cb);
    if(sony069_wifi_dma_faulted())for(unsigned i=0;i<4;i++)out[i+2]=__atomic_load_n(&fault_snapshot[i],__ATOMIC_RELAXED);
    return 0;
}
