/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <IOKit/IOLib.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOLocks.h>
#include <kern/clock.h>
#include <sys/errno.h>
#include "SonySharedResources.h"
#include "SonyRpmh.h"
#include "SonyVotes.h"
#include "SonyCommandDb.h"
#include "SonyResources.generated.h"
#include "QcomRpmh.h"
#include "QcomQmp.h"
#include "BootResetCore.h"
#include "SonyWcnPlatform.h"

extern "C" int armcpu_spi_share(uint32_t,void (*)(void *),void *);
namespace {
struct Window {
    IOMemoryMap *mapping=nullptr;volatile uint32_t *words=nullptr;
    bool open(uint64_t base,uint64_t size){
        if(words)return true;
        IODeviceMemory *memory=IODeviceMemory::withRange(base,size);
        if(memory){mapping=memory->map(kIOMapAnywhere|kIOMapInhibitCache);memory->release();}
        if(mapping)words=reinterpret_cast<volatile uint32_t *>(mapping->getVirtualAddress());
        return words;
    }
    uint32_t read(uint32_t reg) const{return words[reg/4];}
    void write(uint32_t reg,uint32_t value){words[reg/4]=value;__asm__ volatile("dsb sy":::"memory");}
};
IOLock *configuration;
Window gcc,rsc,db,aoss,ipcc,spmi_core,spmi_cfg,spmi_obs,spmi_channels;
sony_rpmh rpmh;
uint8_t *database;
bool initialized,uart_claimed,pdc_ready;
uint32_t uart_initial;
volatile uint32_t completions;
QcomQmp qmp;
struct Resource {const SonyResourceSpec *spec;sony_vote_resource rail;};
Resource *resources;unsigned resource_count;
struct Bcm {char name[9];sony_bcm_resource vote;};
Bcm bcms[16];unsigned bcm_count;
struct Arc {char name[9];sony_cmd_resource spec;sony_arc_resource vote;};
Arc arcs[8];unsigned arc_count;
IOLock *get_lock(){
    IOLock *current=__atomic_load_n(&configuration,__ATOMIC_ACQUIRE);if(current)return current;
    IOLock *candidate=IOLockAlloc();if(!candidate)return nullptr;
    if(!__atomic_compare_exchange_n(&configuration,&current,candidate,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)){
        IOLockFree(candidate);return current;
    }
    return candidate;
}
uint32_t rread(void *,uint32_t reg){return rsc.read(reg);}
void rwrite(void *,uint32_t reg,uint32_t value){rsc.write(reg,value);}
void delay(void *,unsigned us){IODelay(us);}
uint32_t complete(void *){return __atomic_exchange_n(&completions,0,__ATOMIC_ACQ_REL);}
void rsc_irq(void *){
    const uint32_t ours=__atomic_load_n(&rpmh.claimed,__ATOMIC_ACQUIRE);
    const uint32_t bits=rsc.read(rpmh.tcs_base+4)&ours;
    if(bits){__atomic_fetch_or(&completions,bits,__ATOMIC_RELEASE);rsc.write(rpmh.tcs_base+8,bits);}
}
int transfer(void *,uint32_t address,bool write,uint32_t *value){return sony_rpmh_transfer(&rpmh,address,write,value);}
const sony_vote_io vote_io={nullptr,transfer};
void kick(void *){ipcc.write(0x0c,0u<<16|0u);} // generated/verified AOP client0, GLINK_QMP signal0
int qmp_open(){
    if(qmp.state==QcomQmpOpen)return 0;
    qcom_qmp_init(&qmp,aoss.words,kSonyQmpReg[1],kick,nullptr);
    for(unsigned n=0;n<1000;n++){
        int state=qcom_qmp_step(&qmp);if(state==QcomQmpOpen)return 0;if(state<0)return EIO;IOSleep(1);
    }
    return ETIMEDOUT;
}
int pdc_prepare(){
    if(pdc_ready)return 0;
    int e=qmp_open();if(e)return e;
    for(const char *message:kSonyPdcMessages){
        if(qcom_qmp_send(&qmp,message)!=QcomQmpSending)return EBUSY;
        unsigned n=0;for(;n<1000;n++){if(qcom_qmp_step(&qmp)==QcomQmpOpen)break;IOSleep(1);}
        /* No abandon on uncertainty. The remote may still process the queued
         * message; pin this channel rather than overwrite a pending request. */
        if(n==1000)return ETIMEDOUT;
    }
    pdc_ready=true;return 0;
}
int sleep_clock(){
    if(!spmi_core.open(0xc400000,0x3000) || !spmi_cfg.open(0xc42d000,0x4000) ||
       !spmi_obs.open(0xc440000,0x80000))return ENOMEM;
    br_arbiter arb={spmi_core.words,spmi_cfg.words,0};
    uint32_t version=spmi_core.read(0),count=spmi_core.read(4)&0x7ff;
    if(version<BR_VERSION_V7_MIN || version>=BR_VERSION_V8_MIN || !count || count>1024)return ENOTSUP;
    // PPID0:ba is directly derived from actual PMK8550 SID0 baseb800 gpio3.
    int apid=-1;unsigned owner=8;
    for(unsigned i=0;i<count;i++){
        uint32_t m=spmi_core.read(0x2000+4*i);
        if(m && ((m>>8)&0xfff)==0xba){unsigned o=spmi_cfg.read(4*i)&7;
            if(apid<0 || o==0){apid=(int)i;owner=o;}}
    }
    if(apid<0)return ENOENT;
    uint8_t type=0,sub=0,mode=0,source=0,enabled=0;
    if(br_read8(spmi_obs.words,&arb,apid,4,&type) || br_read8(spmi_obs.words,&arb,apid,5,&sub) ||
       br_read8(spmi_obs.words,&arb,apid,0x40,&mode) || br_read8(spmi_obs.words,&arb,apid,0x44,&source) ||
       br_read8(spmi_obs.words,&arb,apid,0x46,&enabled))return EIO;
    if(type!=0x10 || sub<0x10 || sub>0x13)return ENOTSUP;
    if((mode&3)==1 && (source&15)==2 && (enabled&0x80))return 0;
    if(owner!=0)return EACCES;
    if(!spmi_channels.open(0xc500000,(uint64_t)count*4096))return ENOMEM;
    const uint8_t offsets[]={0x42,0x41,0x44,0x40,0x46},values[]={5,0,2,1,0x80};
    for(unsigned i=0;i<sizeof(offsets);i++){
        if(br_write8(spmi_channels.words,apid,offsets[i],values[i]))return EIO;
        uint8_t actual=0;if(br_read8(spmi_obs.words,&arb,apid,offsets[i],&actual) || actual!=values[i])return EIO;
    }
    return 0;
}
int rail(const char *name,uint32_t uv,bool on){return sony_shared_vote(SONY_SHARED_WCN,name,7,uv,on);}
int pcie(bool on){return sony_shared_bcm_vote(SONY_SHARED_WCN,"SN7",on?2000000:0,on?2000000:0);}
int sleep_vote(){int e=sony_shared_config_lock();if(e)return e;e=pdc_prepare();if(!e)e=sleep_clock();sony_shared_config_unlock();return e;}
int uart_vote(bool on){
    int e=sony_shared_config_lock();if(e)return e;
    uint32_t value=gcc.read(0x52010);
    if(on){if(!uart_claimed){uart_initial=value&0x40f;uart_claimed=true;}value|=0x40f;}
    else if(uart_claimed){value=(value&~0x400u)|(uart_initial&0x400u);
        if(!(value&0x203f0u))value=(value&~0xfu)|(uart_initial&0xfu);}
    gcc.write(0x52010,value);if((gcc.read(0x52010)&0x40f)!=(value&0x40f))e=EIO;
    if(!e && !on)uart_claimed=false;sony_shared_config_unlock();return e;
}
}
extern "C" int sony_shared_config_lock(){IOLock *lock=get_lock();if(!lock)return ENOMEM;IOLockLock(lock);return 0;}
extern "C" void sony_shared_config_unlock(){IOLockUnlock(configuration);}
extern "C" int native_sony_shared_resources_init(){
    int e=sony_shared_config_lock();if(e)return e;
    if(initialized){sony_shared_config_unlock();return 0;}
    if(!gcc.open(0x100000,0x80000) || !rsc.open(0x17a20000,0x10000) || !db.open(0x81c60000,0x20000) ||
       !aoss.open(kSonyQmpReg[0],kSonyQmpReg[1]) || !ipcc.open(0x408000,0x1000)){sony_shared_config_unlock();return ENOMEM;}
    if(!database)database=static_cast<uint8_t *>(IOMallocData(0x20000));
    resource_count=sizeof(kSonyResources)/sizeof(kSonyResources[0]);
    if(!resources)resources=static_cast<Resource *>(IOMallocZeroData(resource_count*sizeof(Resource)));
    if(!database || !resources){sony_shared_config_unlock();return ENOMEM;}
    for(unsigned i=0;i<0x20000;i+=4){uint32_t v=db.read(i);memcpy(database+i,&v,4);}
    sony_rpmh_io io={nullptr,rread,rwrite,delay,complete};
    e=sony_rpmh_init(&rpmh,&io,0xd00,2,SONY_RSC_ACTIVE_MASK);
    if(!e){int irq=armcpu_spi_share(SONY_RSC_INTID,rsc_irq,nullptr);if(irq)e=EIO;}
    if(!e)initialized=true;
    sony_shared_config_unlock();return e;
}
extern "C" int sony_shared_vote(unsigned client,const char *name,unsigned mode,unsigned uv,bool enabled){
    if(!name || client>=SONY_SHARED_CLIENTS)return EINVAL;
    int e=native_sony_shared_resources_init();if(e)return e;
    e=sony_shared_config_lock();if(e)return e;Resource *found=nullptr;
    for(unsigned i=0;i<resource_count;i++)if(!strcmp(name,kSonyResources[i].name)){found=&resources[i];found->spec=&kSonyResources[i];break;}
    if(!found)e=ENOENT;
    else{
        if(!found->rail.address){QcomRpmhResource entry={};
            if(qcom_cmd_db_find(database,0x20000,name,&entry))e=ENOENT;
            else{found->rail.address=entry.address;found->rail.min_uv=found->spec->min_uv;found->rail.max_uv=found->spec->max_uv;}}
        if(!e)e=sony_vote_update(&found->rail,&vote_io,client,mode,uv,enabled);
    }
    sony_shared_config_unlock();return e;
}
extern "C" int sony_shared_bcm_vote(unsigned client,const char *name,uint64_t avg,uint64_t peak){
    if(!name || strlen(name)>8 || client>=SONY_SHARED_CLIENTS)return EINVAL;
    int e=native_sony_shared_resources_init();if(e)return e;e=sony_shared_config_lock();if(e)return e;
    Bcm *resource=nullptr;
    for(unsigned i=0;i<bcm_count;i++)if(!strcmp(name,bcms[i].name))resource=&bcms[i];
    if(!resource){
        if(bcm_count>=16)e=ENOSPC;
        else{sony_cmd_resource entry={};uint32_t unit=0,width=0,vcd=0;
            e=sony_cmd_db_find(database,0x20000,name,5,&entry);
            if(!e)e=sony_cmd_bcm_aux(&entry,&unit,&width,&vcd);
            if(!e){resource=&bcms[bcm_count++];strlcpy(resource->name,name,sizeof(resource->name));
                resource->vote.address=entry.address;resource->vote.unit=unit;
                resource->vote.width=width;resource->vote.vcd=vcd;}}
    }
    if(!e)e=sony_bcm_update(&resource->vote,&vote_io,client,avg,peak);
    sony_shared_config_unlock();return e;
}
extern "C" int sony_shared_arc_vote(unsigned client,const char *name,unsigned corner,bool enabled){
    if(!name||!name[0]||strlen(name)>8||client>=SONY_SHARED_CLIENTS)return EINVAL;
    int e=native_sony_shared_resources_init();if(e)return e;
    e=sony_shared_config_lock();if(e)return e;Arc *resource=nullptr;
    for(unsigned i=0;i<arc_count;i++)if(!strcmp(name,arcs[i].name))resource=&arcs[i];
    if(!resource){
        if(arc_count>=8)e=ENOSPC;
        else{sony_cmd_resource entry={};e=sony_cmd_db_find(database,0x20000,name,3,&entry);
            uint32_t off=0;if(!e)e=sony_cmd_arc_index(&entry,0,&off);
            if(!e){resource=&arcs[arc_count++];strlcpy(resource->name,name,sizeof(resource->name));
                resource->spec=entry;resource->vote.address=entry.address;}}
    }
    uint32_t index=0;
    if(!e)e=sony_cmd_arc_index(&resource->spec,enabled?corner:0,&index);
    if(!e)e=sony_arc_update(&resource->vote,&vote_io,client,index,enabled);
    sony_shared_config_unlock();return e;
}
extern "C" int sony_shared_gcc_update(uint32_t offset,uint32_t clear,uint32_t set){
    if(offset%4 || offset>=0x80000)return EINVAL;
    int e=native_sony_shared_resources_init();if(e)return e;e=sony_shared_config_lock();if(e)return e;
    uint32_t value=(gcc.read(offset)&~clear)|set;gcc.write(offset,value);
    if((gcc.read(offset)&(clear|set))!=(value&(clear|set)))e=EIO;
    sony_shared_config_unlock();return e;
}
extern "C" int sony069_its_attach(void (*)(void *,uint32_t),void *);
extern "C" int sony069_its_target(uint32_t *,uint32_t *,uint32_t *);
extern "C" int native_sony_radio_platform069_init(){
    int e=native_sony_shared_resources_init();if(e)return e;
    static const sony_wcn_platform provider={1,rail,pcie,sleep_vote,sony069_its_attach,sony069_its_target,
                                            sony_radio_bluetooth_dma,sony_shared_gcc_update,uart_vote};
    e=sony_wcn_platform_install(&provider);if(e)return e;
    e=native_sony_bluetooth_publish();
    if(e)IOLog("[sony069-radio] ADT/address publish error=%d\n",e);
    return e;
}
