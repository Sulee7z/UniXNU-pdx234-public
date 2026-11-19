/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <IOKit/IOLib.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <kern/task.h>
#include <sys/errno.h>
#include "SonySharedResources.h"
#include "SonyIts.h"
#include "SonyWifiDmaTables.h"
extern "C" volatile uint32_t armcpu_gic_ready;
extern "C" volatile uint32_t armcpu_boot_mpidr;
namespace {
struct Map {IOMemoryMap *map;volatile uint8_t *va;uint64_t physical,bytes;};
Map its,redists;
struct Memory {IOBufferMemoryDescriptor *md;uint8_t *va;uint64_t pa;uint32_t bytes;};
// Only the boot redistributor has its LPIs enabled by this path.
Memory queue,itt,properties,boot_pending,tables[8];
uint32_t writer;uint64_t target;
volatile uint32_t ready,init_state,init_error;
void (*deliver)(void *,uint32_t);void *deliver_context;
uint64_t read64(const Map &m,uint32_t r){return *reinterpret_cast<volatile uint64_t *>(m.va+r);}
uint32_t read32(const Map &m,uint32_t r){return *reinterpret_cast<volatile uint32_t *>(m.va+r);}
void barrier(){__asm__ volatile("dsb sy":::"memory");}
void write64(const Map &m,uint32_t r,uint64_t v){*reinterpret_cast<volatile uint64_t *>(m.va+r)=v;barrier();}
void write32(const Map &m,uint32_t r,uint32_t v){*reinterpret_cast<volatile uint32_t *>(m.va+r)=v;barrier();}
void clean(void *base,size_t size){
    uint64_t ctr;__asm__ volatile("mrs %0,ctr_el0":"=r"(ctr));uintptr_t line=4u<<((ctr>>16)&15);
    uintptr_t at=(uintptr_t)base&~(line-1),end=(uintptr_t)base+size;
    for(;at<end;at+=line)__asm__ volatile("dc cvac,%0"::"r"(at):"memory");barrier();
}
bool mapping(Map &m,uint64_t base,uint64_t bytes){
    if(m.va)return m.physical==base && m.bytes>=bytes;IODeviceMemory *memory=IODeviceMemory::withRange(base,bytes);
    if(memory){m.map=memory->map(kIOMapAnywhere|kIOMapInhibitCache);memory->release();}
    if(m.map)m.va=reinterpret_cast<volatile uint8_t *>(m.map->getVirtualAddress());
    if(m.va){m.physical=base;m.bytes=bytes;}
    return m.va;
}
bool allocate(Memory &m,uint32_t bytes,uint32_t alignment){
    if(m.md)return m.bytes>=bytes;
    const IOOptionBits flags=(IOOptionBits)kIODirectionInOut|(IOOptionBits)kIOMemoryPhysicallyContiguous|(IOOptionBits)kIOMemoryMapperNone;
    m.md=IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task,flags,bytes,alignment);if(!m.md)return false;
    IOByteCount contiguous=0;m.pa=m.md->getPhysicalSegment(0,&contiguous,kIOMemoryMapperNone);
    m.va=static_cast<uint8_t *>(m.md->getBytesNoCopy());m.bytes=bytes;
    if(!m.va || !m.pa || (m.pa&(alignment-1)) || contiguous<bytes || m.pa>=(1ULL<<48) || bytes>(1ULL<<48)-m.pa){
        m.md->release();memset(&m,0,sizeof(m));return false;
    }
    memset(m.va,0,bytes);clean(m.va,bytes);return true;
}
void release(Memory &m){if(m.md)m.md->release();memset(&m,0,sizeof(m));}
void release_preflight_allocations(){
    release(queue);release(itt);release(properties);release(boot_pending);
    for(unsigned i=0;i<8;i++)release(tables[i]);
}
int preflight_failure(int error){release_preflight_allocations();__atomic_store_n(&init_state,0u,__ATOMIC_RELEASE);return error;}
int programmed_failure(int error){init_error=(uint32_t)error;__atomic_store_n(&init_state,3u,__ATOMIC_RELEASE);return error;}
int choose_baser_page(unsigned index,uint64_t before,unsigned *page_bytes){
    // Probe while disabled and quiescent, never publish a table during a probe.
    // Try 4 KiB first: this is the mode observed in this board's Android log.
    static const unsigned candidates[]={SONY_ITS_PAGE_4K,SONY_ITS_PAGE_16K,SONY_ITS_PAGE_64K};
    const uint32_t reg=0x100+8*index;
    for(unsigned candidate:candidates){
        const uint64_t request=sony_its_baser_pagesize_value(before,candidate);
        write64(its,reg,request);
        const uint64_t actual=read64(its,reg);
        if(sony_its_baser_has_owner(actual))return EIO;
        write64(its,reg,before);
        if(!sony_its_register_matches(read64(its,reg),before,SONY_ITS_BASER_READBACK_MASK))return EIO;
        if(sony_its_register_matches(actual,request,SONY_ITS_BASER_READBACK_MASK)){
            *page_bytes=candidate;return 0;
        }
    }
    return ENOTSUP;
}
int send(const sony_its_command &command){
    const uint32_t next=(writer+32)&(SONY_ITS_QUEUE_BYTES-1u);
    const uint64_t reader=read64(its,0x90);
    if(!sony_its_queue_reader_valid(reader,writer,queue.bytes))return EIO;
    if((reader&SONY_ITS_READER_OFFSET_MASK)==next)return EBUSY;
    memcpy(queue.va+writer,&command,32);clean(queue.va+writer,32);
    write64(its,0x88,next);
    for(unsigned n=0;n<100000;n++){
        uint64_t actual=read64(its,0x90);
        if(!sony_its_queue_reader_valid(actual,writer,queue.bytes))return EIO;
        if((actual&SONY_ITS_READER_OFFSET_MASK)==next){writer=next;return 0;}IODelay(1);
    }
    return ETIMEDOUT;
}
int initialize(){
    const uint32_t state=__atomic_load_n(&init_state,__ATOMIC_ACQUIRE);
    if(state==2)return 0;
    if(state==1)return EBUSY;
    if(state==3)return (int)__atomic_load_n(&init_error,__ATOMIC_ACQUIRE);
    uint32_t expected=0;
    if(!__atomic_compare_exchange_n(&init_state,&expected,1u,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return EBUSY;
    if(!__atomic_load_n(&armcpu_gic_ready,__ATOMIC_ACQUIRE))return preflight_failure(EAGAIN);
    if(!mapping(its,0x17140000,0x20000) || !mapping(redists,0x17180000,0x200000))return preflight_failure(ENOMEM);
    if((read32(its,0xffe8)&0xf0)!=0x30)return preflight_failure(ENOTSUP);
    uint64_t typer=read64(its,8);
    const unsigned device_bits=(unsigned)((typer>>13)&31)+1;
    const unsigned event_bits=(unsigned)((typer>>8)&31)+1;
    if(!(typer&1) || device_bits<13 || event_bits<5)return preflight_failure(ENOTSUP);
    // Do not replace an enabled foreign ITS/redistributor table owner. Normal
    // cold initialization is allowed when firmware left the controller idle.
    if(read32(its,0)&1)return preflight_failure(EBUSY);
    unsigned waits=0;while(!(read32(its,0)&(1u<<31)) && waits++<1000)IODelay(1);
    if(!(read32(its,0)&(1u<<31)))return preflight_failure(ETIMEDOUT);
    const uint32_t affinity=sony_its_mpidr_affinity(armcpu_boot_mpidr);
    uint32_t rd=UINT32_MAX;
    uint32_t frames[8];unsigned count=0;bool last=false;
    for(uint64_t off=0;off+0x20000<=redists.bytes;){
        if(count==sizeof(frames)/sizeof(frames[0]))return preflight_failure(ENOTSUP);
        const uint64_t t=read64(redists,(uint32_t)(off+8));
        frames[count++]=(uint32_t)off;
        if((uint32_t)(t>>32)==affinity){if(rd!=UINT32_MAX)return preflight_failure(ENOTSUP);rd=(uint32_t)off;}
        if(t&SONY_ITS_GICR_TYPER_LAST){last=true;break;}
        const uint32_t stride=sony_its_redist_stride(t);
        if(off+stride>redists.bytes)break;
        off+=stride;
    }
    if(!last || rd==UINT32_MAX)return preflight_failure(ENODEV);
    const uint64_t rd_typer=read64(redists,rd+8);
    if(!(rd_typer&SONY_ITS_GICR_TYPER_PLPIS))return preflight_failure(ENOTSUP);
    if(read32(redists,rd)&1)return preflight_failure(EBUSY);
    /* Disabled controllers can still contain firmware-installed table owners. */
    if((read64(redists,rd+0x70)&0x000ffffffffff000ULL) ||
       (read64(redists,rd+0x78)&0x000fffffffff0000ULL))return preflight_failure(EBUSY);
    for(unsigned i=0;i<count;i++){
        const uint32_t peer=frames[i];if(peer==rd)continue;
        const uint64_t peer_typer=read64(redists,peer+8);
        if(!sony_its_redists_may_share_properties(rd_typer,peer_typer))continue;
        if((read32(redists,peer)&(SONY_ITS_GICR_CTLR_ENABLE_LPIS|SONY_ITS_GICR_CTLR_RWP)) ||
           (read64(redists,peer+0x70)&0x000ffffffffff000ULL))return preflight_failure(EBUSY);
    }
    if(read64(its,0x80)&((1ULL<<63)|0x000ffffffffff000ULL))return preflight_failure(EBUSY);
    uint64_t baser_before[8];bool have_device=false,have_collection=false;
    for(unsigned i=0;i<8;i++){
        baser_before[i]=read64(its,0x100+8*i);
        const unsigned type=(unsigned)((baser_before[i]>>56)&7);
        if(sony_its_baser_has_owner(baser_before[i]))return preflight_failure(EBUSY);
        if(type==1){if(have_device)return preflight_failure(ENOTSUP);have_device=true;}
        else if(type==4){if(have_collection)return preflight_failure(ENOTSUP);have_collection=true;}
        else if(type!=0)return preflight_failure(ENOTSUP);
    }
    if(!have_device || !have_collection)return preflight_failure(ENOTSUP);
    const uint64_t redistributor=redists.physical+rd;
    target=(typer&SONY_ITS_GITS_TYPER_PTA)?redistributor:((rd_typer>>8)&0xffff)<<16;
    unsigned page_bytes[8]={};
    for(unsigned i=0;i<8;i++){
        if(!(baser_before[i]&SONY_ITS_GITS_BASER_TYPE_MASK))continue;
        const int e=choose_baser_page(i,baser_before[i],&page_bytes[i]);
        if(e==EIO)return programmed_failure(e);
        if(e)return preflight_failure(e);
    }
    if(!allocate(queue,65536,65536) || !allocate(itt,4096,256) ||
       !allocate(properties,65536,65536) || !allocate(boot_pending,65536,65536))return preflight_failure(ENOMEM);
    const unsigned itt_size=((typer>>4)&15)+1;
    if(itt_size*SONY_ITS_VECTOR_COUNT>itt.bytes)return preflight_failure(ENOTSUP);
    /* Reserve all backing memory before publishing any valid descriptors. */
    for(unsigned i=0;i<8;i++){
        const uint64_t before=baser_before[i];const unsigned type=(unsigned)((before>>56)&7);
        if(type!=1 && type!=4)continue;
        const unsigned entry=(unsigned)(((before>>48)&31)+1);
        // Flat tables cover the configured device/collection only, not every
        // value of the hardware's potentially 32-bit device-ID field.
        uint32_t bytes=0;
        if(!sony_its_required_table_bytes(type,type==1?SONY_ITS_DEVICE_ID:SONY_ITS_COLLECTION_ID,
                entry,page_bytes[i],&bytes) || bytes/page_bytes[i]>256)return preflight_failure(ENOTSUP);
        if(!allocate(tables[i],bytes,page_bytes[i]))return preflight_failure(ENOMEM);
    }
    /* Writes below can leave controller ownership partially programmed. Do not retry. */
    for(unsigned i=0;i<8;i++){
        const uint64_t before=baser_before[i];const unsigned type=(unsigned)((before>>56)&7);
        if(type!=1 && type!=4)continue;
        const uint64_t value=sony_its_baser_value_for_page(before,tables[i].pa,tables[i].bytes,page_bytes[i]);
        if(!value)return programmed_failure(EIO);
        write64(its,0x100+8*i,value);uint64_t actual=read64(its,0x100+8*i);
        if(!sony_its_register_matches(actual,value,SONY_ITS_BASER_READBACK_MASK))return programmed_failure(EIO);
    }
    const uint64_t cbaser=sony_its_cbaser_value(queue.pa,queue.bytes);
    write64(its,0x80,cbaser);
    if(!sony_its_register_matches(read64(its,0x80),cbaser,SONY_ITS_CBASER_READBACK_MASK))return programmed_failure(EIO);
    writer=0;write64(its,0x88,0);
    for(unsigned i=0;i<SONY_ITS_VECTOR_COUNT;i++)properties.va[i]=0xa3; // prioritya0, Group1, enabled
    clean(properties.va,properties.bytes);
    const uint64_t propbaser=properties.pa|(1ULL<<7)|(1ULL<<10)|13u; //14 ID bits cover LPIs 8192..8223
    const uint64_t pendbaser=boot_pending.pa|(1ULL<<7)|(1ULL<<10)|(1ULL<<62); // PTZ is write-only
    write64(redists,rd+0x70,propbaser);
    if(!sony_its_register_matches(read64(redists,rd+0x70),propbaser,SONY_ITS_PROPBASER_READBACK_MASK))return programmed_failure(EIO);
    write64(redists,rd+0x78,pendbaser);
    if(!sony_its_register_matches(read64(redists,rd+0x78),pendbaser,SONY_ITS_PENDBASER_READBACK_MASK))return programmed_failure(EIO);
    write32(redists,rd,read32(redists,rd)|1u);
    for(unsigned n=0;n<10000 && (read32(redists,rd)&(1u<<3));n++)IODelay(1);
    if(!(read32(redists,rd)&1) || (read32(redists,rd)&(1u<<3)))return programmed_failure(EIO);
    write32(its,0,read32(its,0)|1u);
    if(!(read32(its,0)&1))return programmed_failure(EIO);
    sony_its_command c;sony_its_mapc(&c,0,target);int e=send(c);if(e)return programmed_failure(e);
    sony_its_sync(&c,target);if((e=send(c)))return programmed_failure(e);
    sony_its_mapd(&c,0x1401,itt.pa,5);if((e=send(c)))return programmed_failure(e);
    for(unsigned i=0;i<SONY_ITS_VECTOR_COUNT;i++){
        sony_its_mapti(&c,0x1401,i,SONY_ITS_LPI_BASE+i,0);if((e=send(c)))return programmed_failure(e);
    }
    sony_its_sync(&c,target);if((e=send(c)))return programmed_failure(e);
    __atomic_store_n(&ready,1u,__ATOMIC_RELEASE);
    __atomic_store_n(&init_state,2u,__ATOMIC_RELEASE);return 0;
}
}
extern "C" bool sony_radio_lpi_dispatch(uint32_t intid){
    if(intid<SONY_ITS_LPI_BASE || intid>=SONY_ITS_LPI_BASE+SONY_ITS_VECTOR_COUNT)return false;
    if(!__atomic_load_n(&ready,__ATOMIC_ACQUIRE) || !deliver)return false;
    deliver(deliver_context,1u<<(intid-SONY_ITS_LPI_BASE));return true;
}
extern "C" int sony069_its_attach(void (*callback)(void *,uint32_t),void *context){
    if(!callback)return EINVAL;
    int e=sony_shared_config_lock();if(e)return e;
    if(deliver && (deliver!=callback || deliver_context!=context))e=EBUSY;
    else{
        deliver=callback;deliver_context=context;e=initialize();
        if(e && __atomic_load_n(&init_state,__ATOMIC_ACQUIRE)==0){deliver=nullptr;deliver_context=nullptr;}
    }
    sony_shared_config_unlock();return e;
}
extern "C" int sony069_its_target(uint32_t *lo,uint32_t *hi,uint32_t *data){
    if(!lo || !hi || !data)return EINVAL;
    if(!__atomic_load_n(&ready,__ATOMIC_ACQUIRE))return ENXIO;
    /* Endpoint address must traverse its private SMMU domain. MSI IOVA page is
     * mapped to actual GITS_TRANSLATER17150040, not ordinary DMA arena RAM. */
    *lo=(uint32_t)SONY_WIFI_MSI_IOVA+SONY_WIFI_MSI_OFFSET;*hi=0;*data=0;return 0;
}
