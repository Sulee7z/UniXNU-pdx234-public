// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOLocks.h>
#include <IOKit/IOPlatformExpert.h>
#include <pexpert/pexpert.h>
#include <kern/clock.h>
#include <machine/machine_routines.h>
#include "Native069.h"
#include "Resources069.h"
#include "SonyDisplay069.generated.h"
#include "SonySharedResources.h"
// ARC uses encoded corner units and CommandDB aux conversion. This is the
// common RPMh provider ABI, not a second private TCS implementation.
extern "C" int sony_shared_arc_vote(unsigned,const char *,unsigned,bool);
extern "C" void native_sony_oled_backlight_probe(void);
extern "C" int PE_current_console(PE_Video *);
extern "C" int sony_shared_config_lock(void);
extern "C" void sony_shared_config_unlock(void);

namespace {
struct Window {
    IOMemoryMap *map=nullptr;volatile uint32_t *words=nullptr;
    bool open(unsigned region){
        if(words)return true;
        auto memory=IODeviceMemory::withRange(kD69Base[region],kD69Bytes[region]);
        if(memory){map=memory->map(kIOMapAnywhere|kIOMapInhibitCache);memory->release();}
        words=map?reinterpret_cast<volatile uint32_t *>(map->getVirtualAddress()):nullptr;return words;
    }
} windows[D69Regions];
D69Resources resources;
D69Display display;
D69SharedPower installed;
uint32_t installedState,probeState,powerBits;
bool resourcesOn=false,transactionHeld=false;
uint32_t sharedGccError;
volatile uint64_t brightnessRequest;
uint64_t powerToken;
IOWorkLoop *workloop;
IOTimerEventSource *timer;
bool fpsRequested,stopped;
bool suspended;
uint32_t desiredPower=1;
IOLock *sinkLock;
void (*refreshSink)(void *);
OSObject *refreshContext;
uint64_t retryUntil;
uint64_t nowUs(){uint64_t ns=0;absolutetime_to_nanoseconds(mach_absolute_time(),&ns);return ns/1000;}
uint32_t ioRead(void *,unsigned region,uint32_t offset){
    if(region>=D69Regions || offset%4 || offset>=kD69Bytes[region] || !windows[region].words)return UINT32_MAX;
    return windows[region].words[offset/4];
}
void ioWrite(void *,unsigned region,uint32_t offset,uint32_t value){
    if(region>=D69Regions || offset%4 || offset>=kD69Bytes[region] || !windows[region].words)return;
    if(region==D69Gcc){
        // Only DISP branch enablebit is owned here. Preserve all shared GCC
        // fields under commonprovider lock, never overwrite a stale fullword.
        if(sony_shared_gcc_update(offset,0,value&1))sharedGccError=1;
        return;
    }
    windows[region].words[offset/4]=value;__asm__ volatile("dsb sy":::"memory");
}
uint64_t ioNow(void *){return nowUs();}
void ioDelay(void *,uint32_t us){IODelay(us);}
bool criticalIrqs;
void ioCritical(void *,bool enter){
    // No sleeping/allocation in this short single-buffer programming section.
    // The XNU IRQ API preserves/restores its standard DAIF state; it does not
    // change GIC/DSI interrupt routing or mask validation.
    if(enter)criticalIrqs=ml_set_interrupts_enabled(FALSE);
    else ml_set_interrupts_enabled(criticalIrqs);
}
int ioConfigLock(void *){return sony_shared_config_lock();}
void ioConfigUnlock(void *){sony_shared_config_unlock();}
int sharedVote(void *,const char *,const D69VoteSpec *specs,unsigned count,uint64_t *token){
    if(count!=D69Rails||!token)return D69Argument;
    int error=native_sony_shared_resources_init();if(error)return error;
    for(unsigned i=0;i<count;++i){const auto &vote=specs[i];
        if(vote.kind==D69Vrm)error=sony_shared_vote(SONY_SHARED_DISPLAY,vote.resource,vote.mode,vote.voltage_mv*1000,vote.enable);
        else if(vote.kind==D69Arc)error=sony_shared_arc_vote(SONY_SHARED_DISPLAY,vote.resource,vote.corner,vote.enable);
        else return D69Argument;
        if(error){
            // A remote write may still commit after timeout. Retain partial
            // lifetime votes and stop; do not claim an all-or-error rollback.
            native_sony_display069_stats[10]=(int32_t)powerBits;
            return error;
        }
        powerBits|=1u<<i;
    }
    *token=++powerToken;return 0;
}
int sharedRelease(void *,uint64_t token){
    if(token!=powerToken||powerBits!=((1u<<D69Rails)-1))return D69Epoch;
    // Display lifetime votes intentionally remain while inherited scanout runs.
    // Per-command release has no authority to shut down the panel or PLL.
    return 0;
}
bool sharedHeld(void *,uint64_t token){return token==powerToken&&powerBits==((1u<<D69Rails)-1);}
int physicalHold(void *){
    if(!resourcesOn)return D69Resource;
    const int error=d69_resources_hold(&resources);if(error)return resources.pinned?D69Poisoned:error;
    if(sharedGccError){resources.pinned=true;resources.last_error=D69Resource;return D69Poisoned;}
    transactionHeld=true;return 0;
}
bool physicalHeld(void *){return transactionHeld&&!sharedGccError&&d69_resources_held(&resources);}
int physicalRelease(void *){
    int error=d69_resources_release(&resources);
    if(error)return resources.pinned?D69Poisoned:error;
    transactionHeld=false;
    return 0;
}
void stats(){
    native_sony_display069_stats[0]=display.ready?4:2;
    native_sony_display069_stats[1]=display.last_error;
    native_sony_display069_stats[2]=display.requested;
    native_sony_display069_stats[3]=display.transmitted;
    native_sony_display069_stats[4]=(int32_t)display.current_verified;
    native_sony_display069_stats[5]=display.observed_hz;
    native_sony_display069_stats[6]=display.tx.state;
    native_sony_display069_stats[7]=display.packets_sent;
    native_sony_display069_stats[8]=display.failures;
    native_sony_display069_stats[9]=display.poisoned;
    native_sony_display069_stats[11]=display.tx.mdp_over_budget;
    native_sony_display069_stats[12]=display.tx.te_events[0];
    native_sony_display069_stats[13]=display.tx.te_events[1];
}
void tick(OSObject *,IOTimerEventSource *sender){
    if(stopped)return;
    int result=0;
    if(d69_busy(&display))result=d69_step(&display);
    else if(!__atomic_load_n(&desiredPower,__ATOMIC_ACQUIRE)) {
        if(!suspended){result=d69_stop(&display);suspended=result==D69OK;}
        stats();if(result==D69Busy)sender->setTimeoutMS(1);return;
    }
    else if(suspended){result=d69_resume(&display);if(!result)suspended=false;}
    else if(!display.ready){result=d69_probe(&display);if(!result)native_sony_oled_backlight_probe();}
    else if(fpsRequested){result=d69_switch120(&display);if(result!=D69Busy)fpsRequested=false;}
    else if(const uint64_t request=__atomic_exchange_n(&brightnessRequest,0ull,__ATOMIC_ACQUIRE)) {
        result=d69_brightness(&display,(uint32_t)request&0xffff);
        if(result==D69Busy){uint64_t empty=0;__atomic_compare_exchange_n(&brightnessRequest,&empty,request,false,__ATOMIC_RELEASE,__ATOMIC_RELAXED);}
    }
    stats();
    if(result<0){IOLog("[sony069-display] error=%d state=%u poisoned=%u packet=%u/%u tx=%u current-unverified=%u observed-hz=%u\n",
        result,display.tx.state,display.poisoned,display.tx.index,display.tx.count,display.transmitted,display.current_verified,display.observed_hz);
        if(display.poisoned){stopped=true;return;}
    }
    if(display.observed_hz==120)native_sony_display069_notify_refresh();
    if(!display.ready&&nowUs()>retryUntil){stopped=true;IOLog("[sony069-display] retained path not ready after boundedretry error=%d\n",result);return;}
    if(d69_busy(&display)||fpsRequested||__atomic_load_n(&brightnessRequest,__ATOMIC_ACQUIRE))sender->setTimeoutMS(1);
    else if(!display.ready)sender->setTimeoutMS(20);
    // Ready/idle has no periodic4ms wakeup. Real requests and lifecycle edges
    // re-arm this event source; a running panel does not imply CPU polling.
}
}
extern "C" {volatile int32_t native_sony_display069_stats[32];}
extern "C" int native_sony_display069_install_power(const D69SharedPower *provider){
    if(!provider||provider->abi_version!=1||provider->bytes!=sizeof(*provider)||!provider->vote||!provider->release||!provider->held)return D69Argument;
    uint32_t expected=0;if(!__atomic_compare_exchange_n(&installedState,&expected,1u,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return D69Busy;
    installed=*provider;__atomic_store_n(&installedState,2u,__ATOMIC_RELEASE);return 0;
}
extern "C" D69Display *native_sony_display069_instance(void){return &display;}
extern "C" void native_sony_display069_start_backlight(void){native_sony_oled_backlight_probe();}
extern "C" int native_sony_display069_producer_enter(void){return !display.initialized?0:d69_producer_enter(&display);}
extern "C" void native_sony_display069_producer_leave(void){if(display.initialized)d69_producer_leave(&display);}
extern "C" int native_sony_display069_stop(void){return d69_stop(&display);}
extern "C" unsigned native_sony_display069_observed_hz(void){return display.observed_hz;}
extern "C" int native_sony_display069_request(uint32_t level){
    if(!display.ready||display.poisoned)return D69Resource;if(level>4095)level=4095;
    __atomic_store_n(&brightnessRequest,UINT64_C(1)<<63|level,__ATOMIC_RELEASE);
    if(timer)timer->setTimeoutUS(1);return 0;
}
extern "C" void native_sony_display069_power(unsigned ordinal){
    __atomic_store_n(&desiredPower,ordinal?1u:0u,__ATOMIC_RELEASE);
    if(timer)timer->setTimeoutUS(1);
}
extern "C" void native_sony_display069_set_refresh_sink(void (*callback)(void *),void *context){
    IOLock *lock=__atomic_load_n(&sinkLock,__ATOMIC_ACQUIRE);
    if(!lock){IOLock *candidate=IOLockAlloc();if(!candidate)return;
        if(!__atomic_compare_exchange_n(&sinkLock,&lock,candidate,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))IOLockFree(candidate);
        else lock=candidate;}
    OSObject *next=callback&&context?static_cast<OSObject *>(context):nullptr;if(next)next->retain();
    IOLockLock(lock);OSObject *old=refreshContext;refreshContext=next;refreshSink=next?callback:nullptr;IOLockUnlock(lock);
    if(old)old->release();
}
extern "C" void native_sony_display069_notify_refresh(void){
    static bool delivered=false;if(delivered||!sinkLock)return;
    IOLockLock(sinkLock);auto callback=refreshSink;OSObject *context=refreshContext;if(context)context->retain();IOLockUnlock(sinkLock);
    if(callback&&context){delivered=true;callback(context);}if(context)context->release();
}
extern "C" void native_sony_display069_probe(void){
    uint32_t enable=0;if(!PE_parse_boot_argn("backlight",&enable,sizeof(enable))||enable!=1)return;
    uint32_t expected=0;if(!__atomic_compare_exchange_n(&probeState,&expected,1u,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return;
    PE_Video video={};if(PE_current_console(&video)||!video.v_display||!video.v_baseAddr||!video.v_width||!video.v_height){native_sony_display069_stats[0]=-1;return;}
    // Actual inherited GOP remains live. Resource votes establish normal access
    // before first display register access; no prior brightness/120 certificate.
    if(__atomic_load_n(&installedState,__ATOMIC_ACQUIRE)!=2){
        const D69SharedPower common={1,sizeof(D69SharedPower),nullptr,sharedVote,sharedRelease,sharedHeld};installed=common;installedState=2;
    }
    D69Io io={nullptr,ioRead,ioWrite,ioNow,ioDelay,physicalHold,physicalRelease,physicalHeld,ioCritical,ioConfigLock,ioConfigUnlock};
    int error=d69_resources_init(&resources,&io,&installed,kD69Votes);
    if(error){native_sony_display069_stats[0]=-2;native_sony_display069_stats[1]=error;return;}
    // GCC registers and dispcc resource ranges are exactDT. No protectedaliases.
    for(unsigned region=0;region<D69Regions;++region)if(!windows[region].open(region)){
        native_sony_display069_stats[0]=-3;native_sony_display069_stats[1]=kIOReturnNoMemory;return;}
    // Acquire shared RPMh/ARC votes once, then activate inherited GCC/DISPCC
    // branches through the normal owner before any controller register read.
    error=d69_resources_hold(&resources);
    if(error){native_sony_display069_stats[0]=-4;native_sony_display069_stats[1]=error;
        native_sony_display069_stats[10]=resources.last_error;return;}
    resourcesOn=true;
    D69Board board={};memcpy(board.ctl,kD69_ctl,sizeof(board.ctl));memcpy(board.dsc,kD69_dsc,sizeof(board.dsc));
    memcpy(board.dsc_enc,kD69_dsc_enc,sizeof(board.dsc_enc));memcpy(board.pp,kD69_pp,sizeof(board.pp));memcpy(board.intf,kD69_intf,sizeof(board.intf));
    board.width=(uint32_t)video.v_width;board.height=(uint32_t)video.v_height;memcpy(board.phy,kD69Phy,sizeof(board.phy));
    // DISPCC bi_tcxo is clock-controller /4 of Sony76.8MHz xo_board; exactPLL
    // Sony4nm ref is19.2MHz. VSYNC rate is reverse-derived from inheritedRCG.
    board.pll_ref_hz=kD69XoBoard/4;board.bit_clock_hz=1191321360;board.vsync_hz=d69_vsync_rate(&resources,kD69XoBoard/4);
    for(const auto &mode:kD69TimingBudgets)if(mode.width==board.width&&mode.height==board.height){
        if(mode.hz==60)board.mdp_budget_60_us=mode.transfer_us;
        else if(mode.hz==120)board.mdp_budget_120_us=mode.transfer_us;
    }
    // Sony's matching DSI command-mode driver polls STATUS.MDP_BUSY every2ms
    // for200ms in dsi_ctrl_hw_cmn_wait_for_cmd_mode_mdp_idle().
    board.mdp_idle_timeout_us=200000;
    if(!board.mdp_budget_60_us||!board.mdp_budget_120_us){native_sony_display069_stats[0]=-5;native_sony_display069_stats[1]=D69Mode;return;}
    board.timestamp_hz=0; // timestamp event is correlated with mach time; no guessed QTimer frequency
    error=d69_init(&display,&io,&board);
    if(error){native_sony_display069_stats[0]=-5;native_sony_display069_stats[1]=error;return;}
    uint32_t fps=0;PE_parse_boot_argn("panel120",&fps,sizeof(fps));fpsRequested=fps==1;
    workloop=IOWorkLoop::workLoop();timer=IOTimerEventSource::timerEventSource(IOService::getPlatform(),tick);
    if(!workloop||!timer||workloop->addEventSource(timer)){native_sony_display069_stats[0]=-6;return;}
    retryUntil=nowUs()+5000000;timer->setTimeoutMS(1);
    IOLog("[sony069-display] ownerstarted GOP=%ux%u vsync-source=%u resourcesvoted firstprobe pending\n",board.width,board.height,board.vsync_hz);
}
