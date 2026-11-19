// SPDX-License-Identifier: BSD-2-Clause-Patent
// D27CoreBrightness service, nominal coordinates. Physical status is explicitly
// write-only: requested != transmitted != verified. No fabricated0x52 readback.
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOTimerEventSource.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSSymbol.h>
#include <libkern/OSKextLib.h>
#include <pexpert/pexpert.h>
#include <mach/kmod.h>
#include "Native069.h"
#include "../SonyOledBacklight.h"
extern "C" {volatile int32_t native_sony_oled_request[6];}
#if !__has_feature(ptrauth_calls)||!__has_feature(ptrauth_signed_block_descriptors)
#error D27nativePACandBlocksrequired
#endif
namespace {
const OSMetaClass *appleClass;
volatile bool appleIdentity;
volatile uint64_t pending;
uint64_t nowMs(){uint64_t ns=0;absolutetime_to_nanoseconds(mach_absolute_time(),&ns);return ns/1000000;}
uint32_t nitsLevel(int32_t nits){if(nits<=0)return 0;const uint64_t value=((uint64_t)nits*4095+(500u<<15))/(500u<<16);return value<1?1:value>4095?4095:(uint32_t)value;}
}
class SonyOledBacklight:public IOService {
    OSDeclareDefaultStructors(SonyOledBacklight)
    IOWorkLoop *loop=nullptr;IOTimerEventSource *timer=nullptr;bool timerAdded=false;
    uint32_t requested=2047,transmitted=UINT32_MAX,from=0,to=0,duration=0;
    uint64_t fadeStart=0;bool fading=false;
    void cleanup(){
        if(timer){timer->cancelTimeout();if(timerAdded&&loop)loop->removeEventSource(timer);timerAdded=false;OSSafeReleaseNULL(timer);}
        OSSafeReleaseNULL(loop);
        if(__atomic_load_n(&appleIdentity,__ATOMIC_ACQUIRE)){__atomic_store_n(&appleIdentity,false,__ATOMIC_RELEASE);appleClass=nullptr;}
        removeProperty("backlight-control");removeProperty("SonyTransportReady");
    }
    bool publishParameters(uint32_t value){
        auto brightness=OSDictionary::withCapacity(3),milli=OSDictionary::withCapacity(3),parameters=OSDictionary::withCapacity(2);
        bool ok=brightness&&milli&&parameters;
        const struct {const char *name;uint32_t level,nits;} rows[]={{"min",0,2000},{"max",4095,500000},{"value",value,(uint32_t)((uint64_t)value*500000/4095)}};
        for(const auto &r:rows){auto a=OSNumber::withNumber(r.level,32),b=OSNumber::withNumber(r.nits,32);
            if(!a||!b)ok=false;if(ok)ok=brightness->setObject(r.name,a)&&milli->setObject(r.name,b);OSSafeReleaseNULL(a);OSSafeReleaseNULL(b);}
        if(ok)ok=parameters->setObject("brightness",brightness)&&parameters->setObject("BrightnessMilliNits",milli)&&setProperty("IODisplayParameters",parameters);
        OSSafeReleaseNULL(brightness);OSSafeReleaseNULL(milli);OSSafeReleaseNULL(parameters);return ok;
    }
    bool calibration(){
        const int32_t values[]={2<<16,140<<16,500<<16};auto data=OSData::withBytes(values,sizeof(values));auto max=OSData::withBytes(values+2,4);
        auto min=OSNumber::withNumber(2,32),mid=OSNumber::withNumber(140,32);auto table=OSDictionary::withCapacity(6);
        bool ok=data&&max&&min&&mid&&table;
        if(ok)ok=setProperty("backlight-marketing-table",data)&&setProperty("LmaxProduct",max)&&setProperty("LminProduct",min)&&setProperty("LmidProduct",mid);
        const char *keys[]={"lMinProduct","lMidProduct","lMaxProduct","lMinPanel","lMidPanel","lMaxPanel"};
        for(unsigned i=0;i<6;++i){auto v=OSNumber::withNumber((uint32_t)values[i%3],32);if(!v)ok=false;if(ok)ok=table->setObject(keys[i],v);OSSafeReleaseNULL(v);}
        if(ok)ok=setProperty("backlight-calibration-parameters",table);
        OSSafeReleaseNULL(data);OSSafeReleaseNULL(max);OSSafeReleaseNULL(min);OSSafeReleaseNULL(mid);OSSafeReleaseNULL(table);
        setProperty("SonyLuminanceMeasured",false);setProperty("SonyCurrentVerified",false);setProperty("SonyHBMEnabled",false);
        setProperty("SonyBrightnessScale","nominal2/140/500,notmeasurednits");
        setProperty("SonyReadbackPolicy","OEMwrite51;targetDBVnotreadback");return ok;
    }
    static void tick(OSObject *owner,IOTimerEventSource *sender){
        auto self=static_cast<SonyOledBacklight *>(owner);auto display=native_sony_display069_instance();
        if(display->poisoned){self->setProperty("SonyTransportReady",false);self->removeProperty("backlight-control");return;}
        const uint64_t request=__atomic_exchange_n(&pending,0ull,__ATOMIC_ACQUIRE);
        if(request>>63){self->from=self->requested;self->to=(uint32_t)(request>>16)&65535;self->duration=(uint32_t)request&65535;self->fadeStart=nowMs();self->fading=true;}
        if(self->fading){
            const uint64_t elapsed=nowMs()-self->fadeStart;
            const uint32_t goal=!self->duration||elapsed>=self->duration?self->to:
                (uint32_t)((int64_t)self->from+((int64_t)self->to-self->from)*(int64_t)elapsed/self->duration);
            if(goal!=self->requested||elapsed==0){if(!native_sony_display069_request(goal))self->requested=goal;}
            if(goal==self->to)self->fading=false;
        }
        if(self->transmitted!=display->transmitted&&display->packets_sent){
            self->transmitted=display->transmitted;
            self->publishParameters(self->transmitted);
            self->setProperty("SonyTransmittedLevel",(uint64_t)self->transmitted,32);
            IOLog("[sony069-brightness] requested=%u transmitted=%u DBV=%u current=unverified errors=%u\n",self->requested,self->transmitted,d69_sdr_dbv(self->transmitted),display->failures);
        }
        self->setProperty("SonyRequestedLevel",(uint64_t)self->requested,32);
        sender->setTimeoutMS(self->fading?16:100);
    }
public:
    bool start(IOService *provider) override {
        if(!IOService::start(provider)||!native_sony_display069_instance()->ready||!calibration()||!publishParameters(requested)){cleanup();return false;}
        loop=IOWorkLoop::workLoop();timer=IOTimerEventSource::timerEventSource(this,tick);
        if(!loop||!timer){cleanup();return false;}
        if(loop->addEventSource(timer)){cleanup();return false;}timerAdded=true;
        uint32_t control=1;PE_parse_boot_argn("backlight-control",&control,sizeof(control));
        if(control==1){auto name=OSSymbol::withCString("AppleARMBacklight");appleClass=name?OSMetaClass::getMetaClassWithName(name):nullptr;OSSafeReleaseNULL(name);
            if(!appleClass){cleanup();return false;}
            if(!setProperty("NativeSandboxGrantProcess","backboardd")||!setProperty("backlight-control",true)){cleanup();return false;}
            __atomic_store_n(&appleIdentity,true,__ATOMIC_RELEASE);}
        if(!setProperty("SonyTransportReady",true)||!setProperty("SonyTransmittedLevel",UINT64_C(0xffffffff),32)){cleanup();return false;}
        native_sony_oled_stats[0]=4;
        registerService();timer->setTimeoutMS(1);IOLog("[sony069-brightness] servicepublished write-only,inheritedcurrentunknown\n");return true;
    }
    void stop(IOService *provider) override {cleanup();IOService::stop(provider);}
    IOReturn setProperties(OSObject *properties) override {
        auto dictionary=OSDynamicCast(OSDictionary,properties);if(!dictionary)return kIOReturnBadArgument;
        if(!native_sony_display069_instance()->ready||native_sony_display069_instance()->poisoned)return kIOReturnNotReady;
        uint32_t goal,ms=0;
        if(auto n=OSDynamicCast(OSNumber,dictionary->getObject("brightness-nits")))goal=nitsLevel((int32_t)n->unsigned32BitValue());
        else if(auto n=OSDynamicCast(OSNumber,dictionary->getObject("brightness"))){const int32_t v=(int32_t)n->unsigned32BitValue();goal=v<0?0:v>4095?4095:(uint32_t)v;
            if(auto period=OSDynamicCast(OSNumber,dictionary->getObject("FadePeriod"))){const uint64_t requested=((uint64_t)period->unsigned32BitValue()*1000)>>16;ms=requested>5000?5000:(uint32_t)requested;}}
        else return kIOReturnSuccess;
        __atomic_store_n(&pending,UINT64_C(1)<<63|(uint64_t)goal<<16|ms,__ATOMIC_RELEASE);timer->setTimeoutUS(1);return kIOReturnSuccess;
    }
};
SonyOledBacklight::MetaClass SonyOledBacklight::gMetaClass;
const OSMetaClass *const SonyOledBacklight::metaClass=&SonyOledBacklight::gMetaClass;
const OSMetaClass *const SonyOledBacklight::superClass=&IOService::gMetaClass;
SonyOledBacklight::SonyOledBacklight(const OSMetaClass *meta):IOService(meta){}
SonyOledBacklight::~SonyOledBacklight(){cleanup();}
const OSMetaClass *SonyOledBacklight::getMetaClass()const{return __atomic_load_n(&appleIdentity,__ATOMIC_ACQUIRE)&&appleClass?appleClass:&gMetaClass;}
OSMetaClassConstructorInit(SonyOledBacklight,IOService,)
OSDefineDefaultStructors(SonyOledBacklight,IOService)
// The retained mapped-binding wrapper uses the old read52 owner ABI. Refuse
// that contract explicitly. Native069 is the sole owner of the command FIFO.
extern "C" int native_sony_oled_bind_transport(const SonyDsiIo *,const SonyDsiQualification *){
    return SonyDsiUnqualified;
}
extern "C" void native_sony_oled_backlight_start(void){
    if(!native_sony_display069_instance()->ready){native_sony_oled_stats[0]=-2;return;}
    auto service=OSTypeAlloc(SonyOledBacklight);auto provider=IOService::getPlatform();
    const bool attached=service&&provider&&service->init()&&service->attach(provider);
    if(!attached||!service->start(provider)){
        native_sony_oled_stats[0]=-5;
        if(attached){service->stop(provider);service->detach(provider);}
        OSSafeReleaseNULL(service);
        IOLog("[sony069-brightness] service init failed\n");
    }
}
