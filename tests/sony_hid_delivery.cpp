// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <cassert>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <vector>
#include "HidTouchReport.h"
#define NATIVE_HID_SOURCE_API 1
#define OSDeclareDefaultStructors(name)
#define OSDefineMetaClassAndStructors(name,parent)
#define OSDynamicCast(type,obj) dynamic_cast<type *>(obj)
#define OSSafeReleaseNULL(obj) do{if(obj){(obj)->release();(obj)=nullptr;}}while(0)
using IOReturn=int;
using IOOptionBits=unsigned;
constexpr int kIOReturnSuccess=0,kIOReturnNoMemory=-1,kIOReturnBadArgument=-2,kIODirectionNone=0,kIOHIDReportTypeInput=0;
static void *gIOServicePlane=nullptr;
struct OSObject {virtual ~OSObject()=default;virtual void release(){delete this;}};
struct OSIterator:OSObject {virtual OSObject *getNextObject(){return nullptr;}};
static bool eventPresent;
struct IORegistryEntry:OSObject {
    OSIterator *getChildIterator(void *);
    virtual void *metaCast(const char *){return nullptr;}
};
struct EventDriver:IORegistryEntry {void *metaCast(const char *s) override{return !std::strcmp(s,"IOHIDEventDriver")?this:nullptr;}};
static EventDriver driver;
struct Children:OSIterator {unsigned next=0;OSObject *getNextObject() override{return eventPresent && !next++?&driver:nullptr;}};
OSIterator *IORegistryEntry::getChildIterator(void *){return new Children;}
struct IOMemoryDescriptor:OSObject {std::vector<unsigned char> bytes;};
static bool failAllocation,failSubmission;
static std::vector<std::vector<unsigned char>> reports;
struct IOBufferMemoryDescriptor:IOMemoryDescriptor {
    static IOBufferMemoryDescriptor *withBytes(const void *p,size_t n,int){
        if(failAllocation)return nullptr;auto *b=new IOBufferMemoryDescriptor;b->bytes.assign((const unsigned char *)p,(const unsigned char *)p+n);return b;
    }
};
struct OSString:OSObject {static OSString *withCString(const char *){return new OSString;}};
struct IOWorkLoop;
struct IOService:IORegistryEntry {
    virtual bool start(IOService *){return true;}virtual void stop(IOService *){}virtual void free(){}
    bool setProperty(const char *,bool){return true;}
    virtual IOWorkLoop *getWorkLoop() const{return nullptr;}
};
struct IOHIDDevice:IOService {
    virtual OSString *newTransportString()const{return nullptr;}
    virtual OSString *newProductString()const{return nullptr;}
    virtual IOReturn newReportDescriptor(IOMemoryDescriptor **)const{return -1;}
    IOReturn handleReport(IOMemoryDescriptor *b,int type,unsigned options){
        assert(type==0 && !options);if(failSubmission)return -8;reports.push_back(b->bytes);return 0;
    }
};
struct IOTimerEventSource:OSObject {
    using Action=void (*)(OSObject *,IOTimerEventSource *);
    static IOTimerEventSource *current;
    Action action;OSObject *owner;unsigned due=0;
    static IOTimerEventSource *timerEventSource(OSObject *o,Action a){auto *t=new IOTimerEventSource;t->owner=o;t->action=a;return current=t;}
    void setTimeoutMS(unsigned ms){due=ms;}
    void cancelTimeout(){due=0;}
    void fire(){due=0;action(owner,this);}
};
IOTimerEventSource *IOTimerEventSource::current;
struct IOWorkLoop:OSObject {
    using Action=IOReturn (*)(OSObject *,void *,void *,void *,void *);
    static IOWorkLoop *workLoop(){return new IOWorkLoop;}
    int addEventSource(OSObject *){return 0;}void removeEventSource(OSObject *){}
    int runAction(Action a,OSObject *o,void *p=nullptr){return a(o,p,nullptr,nullptr,nullptr);}
};
extern "C" {
volatile uint32_t native_touch_seq,native_touch_count,native_touch_hid_reports;
volatile int native_touch_xs[12],native_touch_ys[12],native_touch_ids[12];
}
static void (*sink)(void *);static void *sinkContext;
extern "C" __attribute__((weak)) void native_touch_set_sink(void (*s)(void *),void *c){sink=s;sinkContext=c;}
extern "C" void native_hid_input_observed(unsigned,int){}
extern "C" void native_hid_live_checkpoint(IOService *){}
extern "C" bool native_hid_input_requested(){return false;}
static int PE_parse_boot_argn(const char *name,void *out,unsigned n){assert(!std::strcmp(name,"touch-hid") && n==4);*(unsigned *)out=1;return 1;}
#include "actual-hid.inc"
static void publish(unsigned count,unsigned y){
    ++native_touch_seq;native_touch_count=count;native_touch_ids[0]=2;native_touch_xs[0]=822;native_touch_ys[0]=(int)y;++native_touch_seq;
    assert(sink);sink(sinkContext);
}
int main(int argc,char **){
    IOService provider;auto *s=static_cast<NativeHidInput *>(native_hid_input_allocate());assert(s->start(&provider));
    assert(sink && sinkContext==s);auto *timer=IOTimerEventSource::current;
    publish(1,3840);assert(reports.empty());eventPresent=true;timer->fire();
    if(argc>1){assert(reports.empty());puts("PASS old064 late event-driver matching loses already-published contact until a later sensor frame");}
    else {
        assert(reports.size()==1 && reports[0].size()==62 && reports[0][1]==3 && reports[0][2]==2 && reports[0][5]==255 && reports[0][6]==127);
        failSubmission=true;publish(0,0);assert(reports.size()==1 && timer->due==8);failSubmission=false;timer->fire();
        assert(reports.size()==2 && reports[1][1]==2);
        failAllocation=true;publish(1,2000);assert(reports.size()==2 && timer->due==8);failAllocation=false;timer->fire();assert(reports.size()==3);
        timer->fire();assert(reports.size()==3);
        puts("PASS actualHID start->sink->workloop->report, delayed event match replay, failed release/allocation retry and no duplicate report");
    }
    s->stop(&provider);assert(!sink);s->free();delete s;
}
