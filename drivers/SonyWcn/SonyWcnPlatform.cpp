/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <IOKit/IOLocks.h>
#include <sys/errno.h>
#include "SonyWcnPlatform.h"
#include "SonyWcnPower.h"

namespace {
IOLock *power_lock;
sony_wcn_power state;
const sony_wcn_platform *provider;
IOLock *lock() {
    IOLock *current=__atomic_load_n(&power_lock,__ATOMIC_ACQUIRE);
    if(current)return current;
    IOLock *candidate=IOLockAlloc();if(!candidate)return nullptr;
    if(!__atomic_compare_exchange_n(&power_lock,&current,candidate,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) {
        IOLockFree(candidate);return current;
    }
    return candidate;
}
int rail(void *,unsigned index,bool on) {
    const auto &r=sony_wcn_rails[index];
    return provider->rail_vote(r.resource,r.microvolts,on);
}
int pcie(void *,bool on){return provider->pcie_vote(on);}
int clock_on(void *){return provider->sleep_clock();}
const sony_wcn_power_ops operations={nullptr,rail,pcie,clock_on};
}
extern "C" int sony_wcn_platform_install(const sony_wcn_platform *ops) {
    if(!ops || ops->version!=1 || !ops->rail_vote || !ops->pcie_vote || !ops->sleep_clock || !ops->gcc_update || !ops->uart14_clock_vote)return EINVAL;
    IOLock *mutex=lock();if(!mutex)return ENOMEM;
    IOLockLock(mutex);
    const int error=provider && provider!=ops?EBUSY:0;
    /* The provider's structure and code must have boot lifetime. */
    if(!error)__atomic_store_n(&provider,ops,__ATOMIC_RELEASE);
    IOLockUnlock(mutex);return error;
}
extern "C" int sony_wcn_platform_ready(void) {
    return __atomic_load_n(&provider,__ATOMIC_ACQUIRE)?0:ENXIO;
}
extern "C" int sony_wcn_platform_wifi_ready(void) {
    const auto *p=__atomic_load_n(&provider,__ATOMIC_ACQUIRE);
    return p && p->wifi_msi_attach && p->wifi_msi_target?0:ENXIO;
}
extern "C" int sony_wcn_gcc_update(uint32_t offset,uint32_t clear,uint32_t set) {
    if(offset%4 || offset>=0x80000)return EINVAL;
    const int ready=sony_wcn_platform_ready();
    return ready?ready:provider->gcc_update(offset,clear,set);
}
extern "C" int sony_wcn_uart14_clock_vote(bool on) {
    const int ready=sony_wcn_platform_ready();
    return ready?ready:provider->uart14_clock_vote(on);
}
extern "C" int sony_wcn_platform_bluetooth_ready(void) {
    const auto *p=__atomic_load_n(&provider,__ATOMIC_ACQUIRE);
    return p && p->bluetooth_dma_prepare?0:ENXIO;
}
extern "C" int sony_wcn_bluetooth_dma_prepare(uint64_t physical,uint32_t bytes,unsigned *slot,unsigned *bank) {
    if(!physical || !bytes || !slot || !bank)return EINVAL;
    const int ready=sony_wcn_platform_bluetooth_ready();
    return ready?ready:provider->bluetooth_dma_prepare(physical,bytes,slot,bank);
}
extern "C" int sony_wcn_wifi_msi_attach(void (*deliver)(void *,uint32_t),void *context) {
    if(!deliver)return EINVAL;
    const int ready=sony_wcn_platform_wifi_ready();
    return ready?ready:provider->wifi_msi_attach(deliver,context);
}
extern "C" int sony_wcn_wifi_msi_target(uint32_t *lo,uint32_t *hi,uint32_t *data) {
    if(!lo || !hi || !data)return EINVAL;
    const int ready=sony_wcn_platform_wifi_ready();
    return ready?ready:provider->wifi_msi_target(lo,hi,data);
}
extern "C" int sony_wcn_power_get(unsigned radio) {
    if(radio>SONY_WCN_BLUETOOTH)return EINVAL;
    if(sony_wcn_platform_ready())return ENXIO;
    IOLock *mutex=lock();if(!mutex)return ENOMEM;
    IOLockLock(mutex);const int e=sony_wcn_power_acquire(&state,&operations,radio);IOLockUnlock(mutex);return e;
}
extern "C" int sony_wcn_power_put(unsigned radio) {
    if(radio>SONY_WCN_BLUETOOTH)return EINVAL;
    if(sony_wcn_platform_ready())return ENXIO;
    IOLock *mutex=lock();if(!mutex)return ENOMEM;
    IOLockLock(mutex);const int e=sony_wcn_power_release(&state,&operations,radio);IOLockUnlock(mutex);return e;
}
extern "C" unsigned sony_wcn_power_owners(void) {
    IOLock *mutex=lock();if(!mutex)return 0;
    IOLockLock(mutex);const unsigned owners=state.owners;IOLockUnlock(mutex);return owners;
}
