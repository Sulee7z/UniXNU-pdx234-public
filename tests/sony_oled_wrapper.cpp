// SPDX-License-Identifier: BSD-2-Clause-Patent
// Execute the production wrapper with explicit IOKit mocks. This qualifies
// async/property/fade/error logic, not IOKit matching or device transport.
#include <algorithm>
#include <cassert>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>
#include "SonyOledBacklight.h"
#include "SonyOledPolicy.h"
#include "actual-model.inc"

using IOReturn=int;
using OSReturn=int;
constexpr int kIOReturnSuccess=0,kIOReturnNoMemory=-10,kIOReturnBadArgument=-11,kIOReturnNotReady=-12;
struct OSObject {
    unsigned refs=1;
    virtual ~OSObject()=default;
    virtual void free() {}
    void retain(){refs++;}
    void release(){assert(refs);if(!--refs){free();delete this;}}
};
struct OSNumber:OSObject {
    uint64_t value;
    static OSNumber *withNumber(uint64_t value,unsigned){auto n=new OSNumber;n->value=value;return n;}
    uint32_t unsigned32BitValue(){return (uint32_t)value;}
};
struct OSData:OSObject {
    std::vector<uint8_t> bytes;
    static OSData *withBytes(const void *data,unsigned n) {
        auto d=new OSData;d->bytes.assign((const uint8_t *)data,(const uint8_t *)data+n);return d;
    }
};
struct OSString:OSObject {std::string value;explicit OSString(const char *s):value(s) {}};
struct OSBool:OSObject {bool value;explicit OSBool(bool b):value(b) {}};
struct OSSymbol:OSObject {
    std::string value;static const OSSymbol *withCString(const char *s){auto a=new OSSymbol;a->value=s;return a;}
    void release() const{const_cast<OSSymbol *>(this)->OSObject::release();}
};
struct OSDictionary:OSObject {
    std::map<std::string,OSObject *> items;
    static OSDictionary *withCapacity(unsigned){return new OSDictionary;}
    bool setObject(const char *key,OSObject *value) {
        assert(value);value->retain();auto &old=items[key];if(old)old->release();old=value;return true;
    }
    OSObject *getObject(const char *key){auto i=items.find(key);return i==items.end()?nullptr:i->second;}
    void remove(const char *key){auto i=items.find(key);if(i!=items.end()){i->second->release();items.erase(i);}}
    ~OSDictionary(){for(auto &[k,v]:items)v->release();}
};
static bool appleAvailable=true;
struct OSMetaClass {
    static const OSMetaClass *getMetaClassWithName(const OSSymbol *s);
};
static OSMetaClass apple;
const OSMetaClass *OSMetaClass::getMetaClassWithName(const OSSymbol *s){assert(s->value=="AppleARMBacklight");return appleAvailable?&apple:nullptr;}
static uint64_t clockUs;
static uint64_t mach_absolute_time(){return clockUs*1000;}
static void absolutetime_to_nanoseconds(uint64_t value,uint64_t *out){*out=value;}
static void IOLog(const char *,...){}
static unsigned control=1;
static int PE_parse_boot_argn(const char *key,void *out,unsigned n){assert(!std::strcmp(key,"backlight-control")&&n==4);*(unsigned *)out=control;return 1;}
struct IOService;
static IOService *publishedService;
struct IOService:OSObject {
    static OSMetaClass gMetaClass;
    OSDictionary *properties=OSDictionary::withCapacity(16);
    explicit IOService(const OSMetaClass * = nullptr){}
    virtual const OSMetaClass *getMetaClass()const{return &gMetaClass;}
    virtual bool start(IOService *){return true;}
    virtual IOReturn setProperties(OSObject *){return 0;}
    bool init(){return true;}
    bool attach(IOService *){return true;}
    void detach(IOService *){}
    static IOService *getPlatform(){static IOService platform;return &platform;}
    bool setProperty(const char *key,OSObject *o){return properties->setObject(key,o);}
    bool setProperty(const char *key,bool b){auto o=new OSBool(b);const bool ok=setProperty(key,o);o->release();return ok;}
    bool setProperty(const char *key,const char *s){auto o=new OSString(s);const bool ok=setProperty(key,o);o->release();return ok;}
    bool setProperty(const char *key,uint64_t value,unsigned){auto o=OSNumber::withNumber(value,32);const bool ok=setProperty(key,o);o->release();return ok;}
    void removeProperty(const char *key){properties->remove(key);}
    void registerService(){publishedService=this;}
    ~IOService(){properties->release();}
};
OSMetaClass IOService::gMetaClass;
static unsigned timerCount,failTimer;
struct IOTimerEventSource:OSObject {
    using Action=void (*)(OSObject *,IOTimerEventSource *);
    OSObject *owner;Action action;uint64_t due=0;
    static std::vector<IOTimerEventSource *> timers;
    static IOTimerEventSource *timerEventSource(OSObject *owner,Action action) {
        if(++timerCount==failTimer)return nullptr;
        auto t=new IOTimerEventSource;t->owner=owner;t->action=action;timers.push_back(t);return t;
    }
    void setTimeoutMS(unsigned ms){due=clockUs+(uint64_t)ms*1000;}
    void setTimeoutUS(unsigned us){due=clockUs+us;}
    void cancelTimeout(){due=0;}
    ~IOTimerEventSource(){timers.erase(std::remove(timers.begin(),timers.end(),this),timers.end());}
};
std::vector<IOTimerEventSource *> IOTimerEventSource::timers;
struct IOWorkLoop:OSObject {
    using Action=IOReturn (*)(OSObject *,void *,void *,void *,void *);
    static IOWorkLoop *workLoop(){return new IOWorkLoop;}
    int addEventSource(OSObject *){return 0;}void removeEventSource(OSObject *){}
    int runAction(Action action,OSObject *owner){return action(owner,nullptr,nullptr,nullptr,nullptr);}
};
#define OSDynamicCast(type,object) dynamic_cast<type *>(object)
#define OSSafeReleaseNULL(object) do{if(object){(object)->release();(object)=nullptr;}}while(0)
#define OSDeclareDefaultStructors(name) public: struct MetaClass:OSMetaClass {}; static MetaClass gMetaClass; static const OSMetaClass *const metaClass; static const OSMetaClass *const superClass; name(const OSMetaClass *); ~name() override; const OSMetaClass *getMetaClass()const override; private:
#define OSMetaClassConstructorInit(name,parent,unused)
#define OSDefineDefaultStructors(name,parent)
#define OSTypeAlloc(name) new name(name::metaClass)
extern "C" {volatile int32_t native_sony_oled_stats[24];}
#include "actual-wrapper.inc"

static void advance(uint64_t until) {
    unsigned limit=0;
    for(;;) {
        IOTimerEventSource *next=nullptr;
        for(auto timer:IOTimerEventSource::timers)if(timer->due && (!next || timer->due<next->due))next=timer;
        if(!next || next->due>until)break;
        assert(++limit<100000);clockUs=next->due;next->due=0;next->action(next->owner,next);
    }
    clockUs=until;
}
static OSDictionary *requestValue(const char *key,uint32_t n) {
    auto request=OSDictionary::withCapacity(2);auto value=OSNumber::withNumber(n,32);request->setObject(key,value);value->release();return request;
}
static uint32_t shown(IOService *service) {
    auto params=dynamic_cast<OSDictionary *>(service->properties->getObject("IODisplayParameters"));assert(params);
    auto bright=dynamic_cast<OSDictionary *>(params->getObject("brightness"));assert(bright);
    auto value=dynamic_cast<OSNumber *>(bright->getObject("value"));assert(value);return value->unsigned32BitValue();
}
int main(int argc,char **argv) {
    native_sony_oled_backlight_start();assert(native_sony_oled_stats[0]==-2 && !publishedService);
    Model m;SonyDsi unused;setup(&m,&unused);const auto q=qualification();
    assert(!native_sony_oled_bind_transport(&unused.io,&q));
    assert(native_sony_oled_bind_transport(&unused.io,&q)==SonyDsiBusy);
    if(argc>1 && !std::strcmp(argv[1],"missing-meta"))appleAvailable=false;
    if(argc>1 && !std::strcmp(argv[1],"no-control"))control=0;
    if(argc>1 && !std::strcmp(argv[1],"allocation-fail"))failTimer=2;
    if(argc>1 && !std::strcmp(argv[1],"timeout"))m.never_done=true;
    native_sony_oled_backlight_start();advance(10000);
    if(failTimer) {
        assert(native_sony_oled_stats[0]==-3 && !publishedService && IOTimerEventSource::timers.empty()&&!m.lease);
        puts("PASS actual wrapper: partial event-source allocation cleans up without publication or transport");return 0;
    }
    if(m.never_done) {
        advance(30000);assert(native_sony_oled_stats[0]==-4 && !publishedService && gDsi.poisoned && m.lease);
        const auto writes=m.writes;advance(1000000);assert(writes==m.writes);
        auto service=static_cast<SonyOledBacklight *>(IOTimerEventSource::timers[0]->owner);service->release();
        puts("PASS actual wrapper: initial read timeout never publishes, never rewrites poisoned active host");return 0;
    }
    if(!appleAvailable) {
        assert(!publishedService && native_sony_oled_stats[0]==-4);
        // Failed-after-start services intentionally remain boot-long in kernel;
        // release the host fixture instance to run leak sanitizers.
        auto service=static_cast<SonyOledBacklight *>(IOTimerEventSource::timers[0]->owner);service->release();
        puts("PASS actual wrapper: absent AppleARMBacklight metaclass never publishes backlight-control");return 0;
    }
    auto service=publishedService;
    if(!control) {
        assert(service && native_sony_oled_stats[0]==3 && service->getMetaClass()!=&apple && !service->properties->getObject("backlight-control"));
        service->release();puts("PASS actual wrapper: backlight-control=0 omits both Apple identity and control property");return 0;
    }
    assert(service && native_sony_oled_stats[0]==4 && service->getMetaClass()==&apple);
    assert(service->properties->getObject("backlight-control") && shown(service)>0);
    auto max=dynamic_cast<OSData *>(service->properties->getObject("LmaxProduct"));assert(max&&max->bytes.size()==4);
    auto table=dynamic_cast<OSData *>(service->properties->getObject("backlight-marketing-table"));assert(table&&table->bytes.size()==12);
    assert(!dynamic_cast<OSBool *>(service->properties->getObject("SonyLuminanceMeasured"))->value);
    const auto before=shown(service);auto req=requestValue("brightness",4095);
    auto duration=OSNumber::withNumber(1<<16,32);req->setObject("FadePeriod",duration);duration->release();
    assert(service->setProperties(req)==0 && shown(service)==before);req->release();
    advance(510000);assert(shown(service)>before && shown(service)<4095);
    // Latest request replaces a queued request and cancels the existing fade.
    req=requestValue("brightness",0);assert(!service->setProperties(req));req->release();
    req=requestValue("brightness-nits",250<<16);assert(!service->setProperties(req));req->release();
    advance(530000);assert(shown(service)==sony_oled_level_for_nits(250<<16) && m.dbv[0]<=2047);
    const uint32_t requests=(uint32_t)native_sony_oled_stats[1];
    auto unknown=OSDictionary::withCapacity(0);assert(!service->setProperties(unknown));unknown->release();
    assert((uint32_t)native_sony_oled_stats[1]==requests && service->setProperties(nullptr)==kIOReturnBadArgument);
    req=requestValue("brightness-nits",0);assert(!service->setProperties(req));req->release();advance(550000);
    assert(!shown(service) && !m.dbv[0] && !m.dbv[1]);
    m.mismatch=true;req=requestValue("brightness",1000);assert(!service->setProperties(req));req->release();advance(570000);
    assert(!shown(service) && native_sony_oled_stats[0]==-4 && !service->properties->getObject("backlight-control"));
    req=requestValue("brightness",3000);assert(service->setProperties(req)==kIOReturnNotReady);req->release();
    service->release();assert(IOTimerEventSource::timers.empty()&&!m.lease);
    puts("PASS actual wrapper: gated publication/nominal calibration/async/latest request/fade/off/confirmed-only value/failure withdrawal");
}
