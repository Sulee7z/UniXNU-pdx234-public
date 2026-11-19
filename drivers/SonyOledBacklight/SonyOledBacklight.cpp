// SPDX-License-Identifier: BSD-2-Clause-Patent
// OS contract adapted from UniXNU-sheng6c42e105 AppleARMBacklight.cpp; transport
// is Sony dual DSI, never GENI/KTZ. Physical completion requires matching 0x52
// responses from both hosts. No backlight-control is published on a failed read.
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOTimerEventSource.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSSymbol.h>
#include <pexpert/pexpert.h>
#include "SonyOledBacklight.h"
#include "SonyOledPolicy.h"

#if !__has_feature(ptrauth_calls) || !__has_feature(ptrauth_signed_block_descriptors)
#error Sony OLED native wrapper requires D27 native PAC and signed Block descriptors
#endif

namespace {
SonyDsi gDsi;
volatile uint32_t gBinding;
volatile uint64_t gRequest;
const OSMetaClass *gAppleClass;
volatile bool gAppleIdentity;
uint64_t nowUs() {
    uint64_t ns=0; absolutetime_to_nanoseconds(mach_absolute_time(),&ns); return ns/1000;
}
void bump(unsigned i) { __atomic_fetch_add(&native_sony_oled_stats[i],1,__ATOMIC_RELAXED); }
uint32_t levelForDbv(uint16_t dbv) {
    uint32_t low=0,high=SONY_OLED_MAX_LEVEL;
    while(low<high) {
        const uint32_t mid=low+(high-low)/2;
        if(sony_oled_sdr_dbv(mid)<dbv)low=mid+1;else high=mid;
    }
    return low;
}
void snapshot() {
    native_sony_oled_stats[3]=gDsi.observed[0]; native_sony_oled_stats[4]=gDsi.observed[1];
    native_sony_oled_stats[5]=(int32_t)gDsi.failures;
    native_sony_oled_stats[6]=(int32_t)gDsi.interrupt[0]; native_sony_oled_stats[7]=(int32_t)gDsi.interrupt[1];
    native_sony_oled_stats[8]=gDsi.last_error; native_sony_oled_stats[9]=(int32_t)gDsi.timeouts;
    native_sony_oled_stats[10]=(int32_t)gDsi.completed; native_sony_oled_stats[11]=gDsi.poisoned;
    native_sony_oled_stats[12]=(int32_t)gDsi.errors[0]; native_sony_oled_stats[13]=(int32_t)gDsi.errors[1];
}
}

extern "C" { volatile int32_t native_sony_oled_request[6]; }

extern "C" int native_sony_oled_bind_transport(const SonyDsiIo *io,const SonyDsiQualification *qualification) {
    uint32_t expected=0;
    if(!__atomic_compare_exchange_n(&gBinding,&expected,1u,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return SonyDsiBusy;
    const int result=sony_dsi_init(&gDsi,io,qualification);
    __atomic_store_n(&gBinding,result?0u:2u,__ATOMIC_RELEASE);
    return result;
}

class SonyOledBacklight : public IOService {
    OSDeclareDefaultStructors(SonyOledBacklight)
    IOWorkLoop *loop=nullptr;
    IOTimerEventSource *request=nullptr,*fade=nullptr,*tick=nullptr;
    uint32_t level=0,target=0,from=0,to=0,period=0,sending=0;
    uint64_t fadeAt=0,acquireUntil=0;
    uint32_t addedTimers=0;
    bool published=false,pending=false,initial=true;
    uint32_t failed=0;

    void fault(int result) {
        __atomic_store_n(&failed,1u,__ATOMIC_RELEASE); snapshot(); native_sony_oled_stats[8]=result; native_sony_oled_stats[0]=-4;
        tick->cancelTimeout(); fade->cancelTimeout(); request->cancelTimeout();
        setProperty("SonyTransportReady",false);
        removeProperty("backlight-control");
        setProperty("SonyTransportError",(uint64_t)(uint32_t)result,32);
        IOLog("sony-oled: service stopped error=%d poisoned=%u completed=%u; no further physical updates\n",
              result,gDsi.poisoned,gDsi.completed);
    }
    bool publishParameters(uint32_t currentLevel) {
        OSDictionary *brightness=OSDictionary::withCapacity(3),*milli=OSDictionary::withCapacity(3);
        OSDictionary *parameters=OSDictionary::withCapacity(2);
        const struct {const char *key; uint32_t level; uint32_t milli;} values[]={
            {"min",0,SONY_OLED_NOMINAL_MIN*1000},{"max",SONY_OLED_MAX_LEVEL,SONY_OLED_NOMINAL_MAX*1000},
            {"value",currentLevel,(uint32_t)((uint64_t)currentLevel*SONY_OLED_NOMINAL_MAX*1000/SONY_OLED_MAX_LEVEL)}};
        bool ok=brightness&&milli&&parameters;
        for(const auto &value:values) {
            OSNumber *a=OSNumber::withNumber(value.level,32),*b=OSNumber::withNumber(value.milli,32);
            if(!a || !b)ok=false;
            if(ok)ok=brightness->setObject(value.key,a)&&milli->setObject(value.key,b);
            OSSafeReleaseNULL(a); OSSafeReleaseNULL(b);
        }
        if(ok)ok=parameters->setObject("brightness",brightness)&&parameters->setObject("BrightnessMilliNits",milli);
        if(ok)ok=setProperty("IODisplayParameters",parameters);
        OSSafeReleaseNULL(brightness); OSSafeReleaseNULL(milli); OSSafeReleaseNULL(parameters);
        return ok;
    }
    bool calibration() {
        // These compatibility coordinates are explicit nominal values. They do
        // not assert measured nits, EDR/HBM capability or an OLED current curve.
        const int32_t table[]={SONY_OLED_NOMINAL_MIN<<16,SONY_OLED_NOMINAL_MID<<16,SONY_OLED_NOMINAL_MAX<<16};
        OSData *marketing=OSData::withBytes(table,sizeof table);
        OSData *max=OSData::withBytes(&table[2],sizeof table[2]);
        OSNumber *min=OSNumber::withNumber(SONY_OLED_NOMINAL_MIN,32),*mid=OSNumber::withNumber(SONY_OLED_NOMINAL_MID,32);
        OSDictionary *parameters=OSDictionary::withCapacity(6);
        bool ok=marketing&&max&&min&&mid&&parameters;
        if(ok)ok=setProperty("backlight-marketing-table",marketing)&&setProperty("LmaxProduct",max)&&
                 setProperty("LminProduct",min)&&setProperty("LmidProduct",mid);
        const char *keys[]={"lMinProduct","lMidProduct","lMaxProduct","lMinPanel","lMidPanel","lMaxPanel"};
        for(unsigned i=0;i<6;++i) {
            OSNumber *number=OSNumber::withNumber((uint32_t)table[i%3],32);
            if(!number)ok=false;
            if(ok)ok=parameters->setObject(keys[i],number);
            OSSafeReleaseNULL(number);
        }
        if(ok)ok=setProperty("backlight-calibration-parameters",parameters);
        OSSafeReleaseNULL(marketing); OSSafeReleaseNULL(max); OSSafeReleaseNULL(min); OSSafeReleaseNULL(mid); OSSafeReleaseNULL(parameters);
        setProperty("SonyLuminanceMeasured",false); setProperty("SonyHBMEnabled",false);
        setProperty("SonyBrightnessScale","nominal CoreBrightness coordinates; not measured nits");
        return ok;
    }
    bool publishFirst() {
        if(gDsi.observed[0]>SONY_OLED_SDR_MAX_DBV)return false;
        level=target=from=to=levelForDbv(gDsi.observed[0]);
        if(!calibration() || !publishParameters(level))return false;
        uint32_t control=1; PE_parse_boot_argn("backlight-control",&control,sizeof control);
        if(control==1) {
            const OSSymbol *name=OSSymbol::withCString("AppleARMBacklight");
            gAppleClass=name?OSMetaClass::getMetaClassWithName(name):nullptr;
            OSSafeReleaseNULL(name);
            if(!gAppleClass)return false;
            __atomic_store_n(&gAppleIdentity,true,__ATOMIC_RELEASE);
            // Same scoped grant property as the official service. No sandbox
            // executable, vtable or original Apple object is patched here.
            if(!setProperty("NativeSandboxGrantProcess","backboardd") || !setProperty("backlight-control",true))return false;
        }
        setProperty("SonyTransportReady",true); setProperty("SonyTransport","DCS0x51/write + DCS0x52/dual-host verification");
        __atomic_store_n(&published,true,__ATOMIC_RELEASE); registerService(); native_sony_oled_stats[0]=control==1?4:3;
        return true;
    }
    void kick() {
        if(__atomic_load_n(&failed,__ATOMIC_ACQUIRE) || sony_dsi_busy(&gDsi))return;
        int result;
        if(initial)result=sony_dsi_start_read(&gDsi,nowUs());
        else if(pending) {
            sending=target;
            result=sony_dsi_start_write(&gDsi,sony_oled_sdr_dbv(sending),nowUs());
        } else return;
        if(result==SonyDsiBusy) {
            if(nowUs()>=acquireUntil){fault(SonyDsiTimeout);return;}
            bump(14); tick->setTimeoutMS(1); return;
        }
        if(result!=SonyDsiPending){fault(result);return;}
        tick->setTimeoutMS(1);
    }
    void service() {
        if(__atomic_load_n(&failed,__ATOMIC_ACQUIRE))return;
        if(!sony_dsi_busy(&gDsi)){kick();return;}
        const int result=sony_dsi_step(&gDsi,nowUs()); snapshot();
        if(result==SonyDsiPending){tick->setTimeoutMS(1);return;}
        if(result!=SonyDsiOK){fault(result);return;}
        if(initial) {
            initial=false;
            if(!publishFirst()){fault(SonyDsiUnqualified);return;}
        } else {
            // The OS-visible current value changes ONLY after the complete
            // write AND matching physical readback, not after enqueue/DMA done.
            level=sending; native_sony_oled_stats[2]=(int32_t)level;
            native_sony_oled_stats[15]=(int32_t)gDsi.requested;
            if(!publishParameters(level)){fault(kIOReturnNoMemory);return;}
            pending=target!=sending;
        }
        acquireUntil=nowUs()+100000; kick();
    }
    void applyTarget(uint32_t value) {
        target=value; pending=true; acquireUntil=nowUs()+100000; kick();
    }
    static void tickFired(OSObject *owner,IOTimerEventSource *) { static_cast<SonyOledBacklight *>(owner)->service(); }
    static void fadeFired(OSObject *owner,IOTimerEventSource *sender) {
        auto self=static_cast<SonyOledBacklight *>(owner); if(__atomic_load_n(&self->failed,__ATOMIC_ACQUIRE))return;
        const uint64_t elapsed=(nowUs()-self->fadeAt)/1000;
        const uint32_t value=sony_oled_fade_level(self->from,self->to,elapsed,self->period);
        if(value!=self->target)self->applyTarget(value);
        if(elapsed<self->period)sender->setTimeoutMS(16);
    }
    static void requestFired(OSObject *owner,IOTimerEventSource *) {
        auto self=static_cast<SonyOledBacklight *>(owner); if(__atomic_load_n(&self->failed,__ATOMIC_ACQUIRE))return;
        const uint64_t request=__atomic_exchange_n(&gRequest,0ull,__ATOMIC_ACQUIRE);
        if(!(request>>63))return;
        self->fade->cancelTimeout(); self->from=self->level;
        self->to=(uint32_t)(request>>16)&0xffff; self->period=(uint32_t)request&0xffff;
        self->fadeAt=nowUs(); __atomic_fetch_add(&native_sony_oled_request[2],1,__ATOMIC_RELAXED);
        if(!self->period || self->to==self->from)self->applyTarget(self->to);else fadeFired(self,self->fade);
    }
    static IOReturn begin(OSObject *owner,void *,void *,void *,void *) {
        auto self=static_cast<SonyOledBacklight *>(owner);
        self->acquireUntil=nowUs()+100000; self->kick(); return kIOReturnSuccess;
    }
public:
    bool start(IOService *provider) override {
        if(!IOService::start(provider))return false;
        loop=IOWorkLoop::workLoop();
        request=IOTimerEventSource::timerEventSource(this,&SonyOledBacklight::requestFired);
        fade=IOTimerEventSource::timerEventSource(this,&SonyOledBacklight::fadeFired);
        tick=IOTimerEventSource::timerEventSource(this,&SonyOledBacklight::tickFired);
        if(!loop || !request || !fade || !tick)return false;
        IOTimerEventSource *timers[]={request,fade,tick};
        for(unsigned i=0;i<3;++i) {
            if(loop->addEventSource(timers[i]))return false;
            addedTimers|=1u<<i;
        }
        native_sony_oled_stats[0]=2; loop->runAction(&SonyOledBacklight::begin,this); return true;
    }
    void free() override {
        IOTimerEventSource *timers[]={request,fade,tick};
        for(unsigned i=0;i<3;++i)if(auto timer=timers[i]) {
            timer->cancelTimeout();if(loop && (addedTimers&(1u<<i)))loop->removeEventSource(timer);timer->release();
        }
        OSSafeReleaseNULL(loop); IOService::free();
    }
    IOReturn setProperties(OSObject *properties) override {
        auto dictionary=OSDynamicCast(OSDictionary,properties); if(!dictionary)return kIOReturnBadArgument;
        if(__atomic_load_n(&failed,__ATOMIC_ACQUIRE) || !__atomic_load_n(&published,__ATOMIC_ACQUIRE))return kIOReturnNotReady;
        uint32_t goal,ms=0;
        if(auto nits=OSDynamicCast(OSNumber,dictionary->getObject("brightness-nits")))goal=sony_oled_level_for_nits((int32_t)nits->unsigned32BitValue());
        else if(auto brightness=OSDynamicCast(OSNumber,dictionary->getObject("brightness"))) {
            const int32_t value=(int32_t)brightness->unsigned32BitValue();
            goal=value<0?0:(uint32_t)value>SONY_OLED_MAX_LEVEL?SONY_OLED_MAX_LEVEL:(uint32_t)value;
            if(auto period=OSDynamicCast(OSNumber,dictionary->getObject("FadePeriod")))ms=sony_oled_fade_ms(period->unsigned32BitValue());
        } else return kIOReturnSuccess;
        bump(1); native_sony_oled_request[0]=(int32_t)goal; native_sony_oled_request[1]=(int32_t)ms;
        __atomic_store_n(&gRequest,UINT64_C(1)<<63 | (uint64_t)goal<<16 | ms,__ATOMIC_RELEASE);
        request->setTimeoutUS(1); // asynchronous acceptance, NOT physical success
        return kIOReturnSuccess;
    }
};

SonyOledBacklight::MetaClass SonyOledBacklight::gMetaClass;
const OSMetaClass *const SonyOledBacklight::metaClass=&SonyOledBacklight::gMetaClass;
const OSMetaClass *const SonyOledBacklight::superClass=&IOService::gMetaClass;
SonyOledBacklight::SonyOledBacklight(const OSMetaClass *meta):IOService(meta) {}
SonyOledBacklight::~SonyOledBacklight() {}
const OSMetaClass *SonyOledBacklight::getMetaClass() const {
    return __atomic_load_n(&gAppleIdentity,__ATOMIC_ACQUIRE)&&gAppleClass?gAppleClass:&gMetaClass;
}
OSMetaClassConstructorInit(SonyOledBacklight,IOService,)
OSDefineDefaultStructors(SonyOledBacklight,IOService)

extern "C" void native_sony_oled_backlight_start(void) {
    if(__atomic_load_n(&gBinding,__ATOMIC_ACQUIRE)!=2) {
        native_sony_oled_stats[0]=-2; native_sony_oled_stats[8]=SonyDsiUnqualified;
        IOLog("sony-oled: no qualified display-owner DSI handoff; no MMIO or backlight-control publication\n");return;
    }
    auto service=OSTypeAlloc(SonyOledBacklight);
    IOService *provider=IOService::getPlatform();
    bool attached=false;
    if(!service || !service->init() || !(attached=service->attach(provider)) || !service->start(provider)) {
        if(service){if(attached)service->detach(provider);service->release();}
        native_sony_oled_stats[0]=-3; native_sony_oled_stats[8]=kIOReturnNoMemory;return;
    }
    // Permanent native service, as the display-owner callback context is boot-long.
    // Keep its creation reference; failure after start does not drop a live lease.
}
