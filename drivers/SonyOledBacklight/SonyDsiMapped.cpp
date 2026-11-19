// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <IOKit/IOLib.h>
#include "SonyDsiMapped.h"
namespace {
SonyDsiMappedOwner gOwner;
volatile uint32_t gInstalled;
uint32_t read(void *,unsigned host,uint32_t reg) {
    return gOwner.host[host][reg/4];
}
void write(void *,unsigned host,uint32_t reg,uint32_t value) {
    gOwner.host[host][reg/4]=value;
    __asm__ volatile("dsb sy" ::: "memory");
}
void delay(void *,uint32_t us) { IODelay(us); }
int acquire(void *,uint64_t *epoch) {return gOwner.acquire(gOwner.owner,epoch);}
bool owned(void *,uint64_t epoch) {return gOwner.owned(gOwner.owner,epoch);}
void release(void *,uint64_t epoch) {gOwner.release(gOwner.owner,epoch);}
}
extern "C" int native_sony_oled_bind_mapped(const SonyDsiMappedOwner *owner,const SonyDsiQualification *q) {
    if(!owner || !q || !owner->host[0] || !owner->host[1] || owner->host[0]==owner->host[1] ||
       owner->physical[0]!=SONY_DSI0_BASE || owner->physical[1]!=SONY_DSI1_BASE ||
       owner->bytes[0]!=SonyDsiHostBytes || owner->bytes[1]!=SonyDsiHostBytes ||
       ((uintptr_t)owner->host[0]&3) || ((uintptr_t)owner->host[1]&3) ||
       !owner->acquire || !owner->owned || !owner->release)return SonyDsiArgument;
    uint32_t expected=0;
    if(!__atomic_compare_exchange_n(&gInstalled,&expected,1u,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return SonyDsiBusy;
    gOwner=*owner;
    const SonyDsiIo io={nullptr,read,write,delay,acquire,owned,release};
    const int result=native_sony_oled_bind_transport(&io,q);
    __atomic_store_n(&gInstalled,result?0u:2u,__ATOMIC_RELEASE);
    return result;
}
