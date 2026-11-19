"""ComposableGOP/late-start hookoverlay. Frozen sources remain untouched."""
import hashlib
def once(text,old,new):
    if text.count(old)!=1:raise ValueError('Sony069display lifecycle anchor differs:'+old[:100])
    return text.replace(old,new)

GOP_SHA='08f3339ff43702eb417f29bef7410a6bcb01a20bc9afde6867ba5c355cf96d8f'
def gop(text):
    if hashlib.sha256(text.encode()).hexdigest()!=GOP_SHA:raise ValueError('Require exact qualifiedphysicaldisplay009source')
    text='''extern "C" int native_sony_display069_producer_enter(void);
extern "C" void native_sony_display069_producer_leave(void);
extern "C" void native_sony_display069_power(unsigned);
extern "C" unsigned native_sony_display069_observed_hz(void);
extern "C" void native_sony_display069_set_refresh_sink(void (*)(void *),void *);
struct Sony069DisplayProducer {
    bool acquired;
    Sony069DisplayProducer():acquired(native_sony_display069_producer_enter()==0){}
    ~Sony069DisplayProducer(){if(acquired)native_sony_display069_producer_leave();}
};
'''+text
    text=once(text,'    void kickOnce() {','''    void kickOnce() {
        Sony069DisplayProducer reservation;
        if(!reservation.acquired){if(ownerRetryTimer)ownerRetryTimer->setTimeoutMS(1);return;}''')
    text=once(text,'    IOTimerEventSource *vsyncTimer=nullptr;', '''    IOTimerEventSource *ownerRetryTimer=nullptr;
    static void ownerRetry(OSObject *owner,IOTimerEventSource *) {
        static_cast<NativeLegacyDisplay *>(owner)->kickSwapQueue();
    }
    static void ownerRefresh(void *context) {
        auto self=static_cast<NativeLegacyDisplay *>(context);
        IOWorkLoop *loop=self->getWorkLoop();
        if(!loop)return;
        auto action=[](OSObject *o,void *,void *,void *,void *)->IOReturn {
            auto display=static_cast<NativeLegacyDisplay *>(o);
            display->stopVsync();display->startVsync();
            native_legacy_set_refresh_properties(display);
            return kIOReturnSuccess;
        };
        loop->runAction(action,self);
    }
    IOTimerEventSource *vsyncTimer=nullptr;''')
    text=once(text,'        startVsync();startDirect();return true;', '''        startVsync();startDirect();
        if(IOWorkLoop *loop=getWorkLoop()) {
            ownerRetryTimer=IOTimerEventSource::timerEventSource(this,&NativeLegacyDisplay::ownerRetry);
            if(ownerRetryTimer && loop->addEventSource(ownerRetryTimer))OSSafeReleaseNULL(ownerRetryTimer);
        }
        native_sony_display069_set_refresh_sink(&NativeLegacyDisplay::ownerRefresh,this);
        return true;''')
    text=once(text,'    void stop(IOService *provider) override {','''    void stop(IOService *provider) override {
        native_sony_display069_power(0);
        native_sony_display069_set_refresh_sink(nullptr,nullptr);
        if(ownerRetryTimer){ownerRetryTimer->cancelTimeout();if(IOWorkLoop *loop=getWorkLoop())loop->removeEventSource(ownerRetryTimer);OSSafeReleaseNULL(ownerRetryTimer);}''')
    text=once(text,'    IOReturn setPowerState(unsigned long ordinal,IOService *device) override {','''    IOReturn setPowerState(unsigned long ordinal,IOService *device) override {
        native_sony_display069_power((unsigned)ordinal);''')
    # Existing software-vsync policy may request120 before actualswitch; keep
    # notifications60 until owner has measured externalTE120, then refresh sink
    # restarts the cached timer and originalfamilypropertypublisher.
    anchor='        unsigned hz=native_legacy_refresh_hz();'
    if text.count(anchor)!=3:raise ValueError('Exact three retained refresh policy consumers required')
    text=text.replace(anchor,'        unsigned hz=native_sony_display069_observed_hz()==120?120:60;')
    return text

def startup(text):
    text='extern "C" void native_sony_display069_probe(void);\n'+text
    return once(text,'    native_sony_oled_backlight_probe();','    native_sony_display069_probe();')
