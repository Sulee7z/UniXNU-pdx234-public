// SPDX-License-Identifier: BSD-2-Clause-Patent
// Sony-owned SW82907 transport. Initial implementation uses FIFO + IRQ-level
// polling, FIFO or SE DMA; no protected-register writes, Novatek download or sensor flashing.
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSSymbol.h>
#include <libkern/c++/OSIterator.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/OSKextLib.h>
#include <kern/thread.h>
#include <mach/kmod.h>
#include <pexpert/pexpert.h>
#include "Sw82907.h"
#include "Sw82907Boot.h"
#include "GeniI2c.h"
#include "GeniInit.h"
#include "SonyTouchIrq.h"
#include "SmmuBypass.h"

extern kmod_info_t g_kernel_kmod_info;
extern "C" {
void native_sony_hid_static_init(void) __asm__("__GLOBAL__sub_I_NativeHidInput.cpp");
IOService *native_hid_input_allocate(void);
extern const uint8_t native_sony_geni_firmware[];
extern const uint32_t native_sony_geni_firmware_size;
void native_touch_set_sink(void (*)(void *), void *);
void native_touch_published(void);
volatile uint32_t native_touch_seq, native_touch_count, native_touch_hid_reports;
volatile int native_touch_xs[12], native_touch_ys[12], native_touch_ids[12];
volatile uint32_t native_sony_touch_stage, native_sony_touch_frames, native_sony_touch_valid;
volatile uint32_t native_sony_touch_bad, native_sony_touch_irq_low, native_sony_touch_fw_revision;
volatile int native_sony_touch_error, native_sony_touch_hid_result;
volatile uint32_t native_sony_touch_fw_loaded, native_sony_touch_qup_version, native_sony_touch_clock_level;
volatile uint32_t native_sony_touch_last_irq, native_sony_touch_last_x, native_sony_touch_last_y;
volatile uint32_t native_hid_input_events[8];
volatile int native_hid_input_results[8];
IOReturn armcpu_spi_mask(uint32_t,bool) __attribute__((weak_import));
IOReturn armcpu_spi_attach(uint32_t,bool,void (*)(void *),void *,uint32_t *,uint64_t *) __attribute__((weak_import));
volatile uint32_t native_sony_touch_irq_attached,native_sony_touch_engine_interrupts;
volatile int native_sony_touch_irq_attach_result=-1,native_sony_touch_irq_mask_result=-1;
volatile uint32_t native_sony_touch_substep,native_sony_touch_last_reg,native_sony_touch_last_length;
volatile uint32_t native_sony_touch_last_ic,native_sony_touch_last_status,native_sony_touch_last_info;
volatile uint32_t native_sony_touch_engine_state,native_sony_touch_engine_ios,native_sony_touch_tx_in,native_sony_touch_rx_in;
volatile uint32_t native_sony_touch_chip_id,native_sony_touch_boot_status,native_sony_touch_drive_status;
volatile uint32_t native_sony_touch_sensor_version,native_sony_touch_boot_skipped,native_sony_touch_code_status;
volatile uint32_t native_sony_touch_smmu_slot,native_sony_touch_smmu_bank,native_sony_touch_event_driver;
extern volatile uint32_t native_touch_edge_install[3],native_touch_edge_stats[4];
char native_sony_touch_product[9];
volatile uint32_t native_sony_touch_dma_mode,native_sony_touch_irq_masked;
volatile uint32_t native_sony_touch_transfer_irq,native_sony_touch_dma_tx,native_sony_touch_dma_rx;
volatile uint32_t native_sony_touch_gpio_config[2],native_sony_touch_clock_halt[5];
volatile uint32_t native_sony_touch_pll_mode;
volatile int native_sony_touch_transfer_error,native_sony_touch_hid_load,native_sony_touch_hid_meta;
volatile uint32_t native_sony_touch_hid_size,native_sony_touch_hid_resource,native_sony_touch_hid_started;
IOBufferMemoryDescriptor *native_sony_touch_pinned_dma;
}

namespace {
// Live DT base f000000 PLUS kalama GPIO REG_BASE=100000. Not base+gpio*1000.
constexpr uint64_t kGpioBase=0x0f100000, kGccBase=0x00100000;
constexpr uint64_t kEngineBase=0x00a90000;
constexpr uint32_t kVote=(1u<<18)|(1u<<19)|(1u<<20)|(1u<<21)|(1u<<26);
struct Region {
    IOMemoryMap *map=nullptr;
    uintptr_t base=0;
    bool open(uint64_t address,uint64_t length) {
        IODeviceMemory *memory=IODeviceMemory::withRange(address,length);
        if(!memory)return false;
        map=memory->map(kIOMapAnywhere|kIOMapInhibitCache);memory->release();
        base=map?(uintptr_t)map->getVirtualAddress():0;
        return base!=0;
    }
    ~Region(){OSSafeReleaseNULL(map);}
    uint32_t read(uint32_t reg) const{return *reinterpret_cast<volatile uint32_t *>(base+reg);}
    void write(uint32_t reg,uint32_t value) const{
        *reinterpret_cast<volatile uint32_t *>(base+reg)=value;
        __asm__ volatile("dsb sy":::"memory");
    }
};
void (*gSink)(void *);
void *gContext;
extern "C" int sony_shared_config_lock(void);
extern "C" void sony_shared_config_unlock(void);
class SonySmmuGuard {
    bool held;
public:
    SonySmmuGuard():held(sony_shared_config_lock()==0){}
    ~SonySmmuGuard(){if(held)sony_shared_config_unlock();}
    bool ready() const{return held;}
};
void publish(const Sw82907FrameData &frame) {
    native_touch_seq=native_touch_seq+1;
    __asm__ volatile("dmb ish":::"memory");
    native_touch_count=frame.count;
    for(unsigned i=0;i<frame.count;++i) {
        native_touch_ids[i]=frame.contacts[i].id;
        native_touch_xs[i]=frame.contacts[i].x;
        native_touch_ys[i]=frame.contacts[i].y;
    }
    __asm__ volatile("dmb ish":::"memory");
    native_touch_seq=native_touch_seq+1;
    native_touch_published();
}
uint32_t engineRead(void *ctx,uint32_t reg){return static_cast<Region *>(ctx)->read(reg);}
void engineWrite(void *ctx,uint32_t reg,uint32_t value){static_cast<Region *>(ctx)->write(reg,value);}
int engineAttach(uint32_t intid,int edge,void (*handler)(void *),void *context,uint32_t *readback,uint64_t *router) {
    return armcpu_spi_attach(intid,edge!=0,handler,context,readback,router);
}
int engineMask(uint32_t intid,int masked){return armcpu_spi_mask(intid,masked!=0);}
void engineInterrupt(void *) {
    (void)armcpu_spi_mask(SONY_TOUCH_ENGINE_INTID,true);
    __atomic_fetch_add(&native_sony_touch_engine_interrupts,1,__ATOMIC_RELAXED);
}
void dmaCache(void *address,uint32_t length,unsigned operation) {
    uint64_t ctr;__asm__ volatile("mrs %0,ctr_el0":"=r"(ctr));
    const uintptr_t line=4u<<((ctr>>16)&15u);
    uintptr_t at=(uintptr_t)address&~(line-1),end=(uintptr_t)address+length;
    for(;at<end;at+=line) {
        if(operation==0)__asm__ volatile("dc cvac,%0"::"r"(at):"memory");
        else if(operation==1)__asm__ volatile("dc civac,%0"::"r"(at):"memory");
        else __asm__ volatile("dc ivac,%0"::"r"(at):"memory");
    }
    __asm__ volatile("dsb sy":::"memory");
}
void dmaClean(void *,void *address,uint32_t length){dmaCache(address,length,0);}
void dmaPrepareRx(void *,void *address,uint32_t length){dmaCache(address,length,1);}
void dmaInvalidate(void *,void *address,uint32_t length){dmaCache(address,length,2);}
constexpr uint32_t kDmaPage=16384;
struct Session {
    Region vote,halt,clock,gpio,engine,wrapper,pll,smmu;
    IOBufferMemoryDescriptor *dmaMemory=nullptr;
    bool dmaPrepared=false;
    SonyGeniI2c bus={};
    uint8_t bytes[SW82907_FRAME_BYTES]={};
    ~Session() {
        // An uncertain abort must never release RAM which the device can still
        // reach. A failed DMA session stays permanently pinned for this boot.
        if(dmaMemory && bus.dma_started && (bus.error || bus.phase!=SonyGeniIdle)) {
            native_sony_touch_pinned_dma=dmaMemory;dmaMemory=nullptr;
        }
        if(dmaMemory){if(dmaPrepared)dmaMemory->complete();dmaMemory->release();}
    }
    bool clocks() {
        if(!vote.open(kGccBase+0x52000,0x1000) || !halt.open(kGccBase+0x23000,0x1000) ||
           !clock.open(kGccBase+0x18000,0x1000) || !gpio.open(kGpioBase+24*0x1000,22*0x1000) ||
           !pll.open(kGccBase,0x1000))return false;
        // Shared parent vote, as sheng does. Initial DFS levels can depend on
        // GPLL0 even though the final I2C level is TCXO; do not access an unclocked SE.
        {SonySmmuGuard guard;if(!guard.ready())return false;vote.write(0x18,vote.read(0x18)|1u);}
        unsigned pllWait=0;while(!(pll.read(0)&(1u<<31)) && pllWait++<100)IOSleep(1);
        native_sony_touch_pll_mode=pll.read(0);
        if(!(native_sony_touch_pll_mode&(1u<<31)))return false;
        {SonySmmuGuard guard;if(!guard.ready())return false;vote.write(8,vote.read(8)|kVote);}
        bool ready=false;
        for(unsigned i=0;i<20;++i) {
            const uint32_t master=halt.read(0x27c),slave=halt.read(0x280);
            ready=(!(master&(1u<<31)) || (master&2u)) && (!(slave&(1u<<31)) || (slave&2u)) &&
                  !(halt.read(0x284)&(1u<<31)) && !(halt.read(0x294)&(1u<<31)) &&
                  !(clock.read(0x4e4)&(1u<<31));
            if(ready)break;IOSleep(1);
        }
        native_sony_touch_clock_halt[0]=halt.read(0x27c);native_sony_touch_clock_halt[1]=halt.read(0x280);
        native_sony_touch_clock_halt[2]=halt.read(0x284);native_sony_touch_clock_halt[3]=halt.read(0x294);
        native_sony_touch_clock_halt[4]=clock.read(0x4e4);
        if(!ready)return false;
        for(unsigned pin=44;pin<=45;++pin) {
            const uint32_t at=(pin-24)*0x1000;
            gpio.write(at,(gpio.read(at)&~0x3ffu)|4u); // mux1, 2mA, no pull, no GPIO OE
            native_sony_touch_gpio_config[pin-44]=gpio.read(at);
        }
        // IRQ GPIO25, active-low. Only read its level; leave GIC/TLMM IRQ routing alone.
        gpio.write(0x1000,gpio.read(0x1000)&~0x23cu);
        return true;
    }
    bool prepareDma(const SonyGeniIo &io) {
        native_sony_touch_substep=25;
        dmaMemory=IOBufferMemoryDescriptor::inTaskWithPhysicalMask(kernel_task,
            (IOOptionBits)kIODirectionInOut|(IOOptionBits)kIOMemoryPhysicallyContiguous,2*kDmaPage,0xfffffff000ULL);
        if(!dmaMemory || dmaMemory->prepare()!=kIOReturnSuccess)return false;
        dmaPrepared=true;
        addr64_t length=0;const uint64_t physical=dmaMemory->getPhysicalSegment(0,&length);
        uint8_t *virtualAddress=static_cast<uint8_t *>(dmaMemory->getBytesNoCopy());
        if(!physical || !virtualAddress || length<2*kDmaPage)return false;
        memset(virtualAddress,0,2*kDmaPage);dmaCache(virtualAddress,2*kDmaPage,1);
        // New read-only live DT also confirms wrapper0xac0000 SID0xa3 and apps
        // SMMU0x15000000. Use the existing sheng planner, refusing conflicting banks/streams.
        if(!smmu.open(0x15000000,0xd0000))return false;
        SonySmmuGuard guard;if(!guard.ready())return false;
        smmu_io registers={&smmu,engineRead,engineWrite};
        smmu_plan plan=smmu_plan_bypass(&registers,0xa3,physical,2*kDmaPage);
        native_sony_touch_smmu_slot=plan.slot;native_sony_touch_smmu_bank=plan.bank;
        const char *smmuError=plan.error?plan.error:smmu_configure_bypass(&registers,&plan,0xa3);
        if(smmuError){IOLog("[sony-touch-smmu] slot=%u bank=%u error=%s\n",plan.slot,plan.bank,smmuError);return false;}
        native_sony_touch_substep=26;
        SonyGeniDma buffers={nullptr,virtualAddress,virtualAddress+kDmaPage,physical,physical+kDmaPage,
                            kDmaPage,dmaClean,dmaPrepareRx,dmaInvalidate};
        return sony_geni_prepare_dma(&bus,&io,SW82907_ADDRESS,native_sony_touch_qup_version,&buffers)==0;
    }
    bool prepare() {
        if(!engine.open(kEngineBase,0x4000) || !wrapper.open(0x00ac0000,0x2000))return false;
        native_sony_touch_qup_version=wrapper.read(4);
        SonyGeniIo io={engineRead,engineWrite,&engine},common={engineRead,engineWrite,&wrapper};
        native_sony_touch_substep=21;
        if(!armcpu_spi_mask || !armcpu_spi_attach){native_sony_touch_error=-109;return false;}
        SonyTouchIrqOps irqOps={engineAttach,engineMask};SonyTouchIrqState irqState={};
        const int irqResult=sony_touch_irq_prepare(&io,&irqOps,engineInterrupt,&irqState);
        native_sony_touch_irq_attach_result=irqState.attach_result;native_sony_touch_irq_mask_result=irqState.mask_result;
        native_sony_touch_irq_attached=irqState.registered;native_sony_touch_irq_masked=irqState.masked;
        if(irqResult){native_sony_touch_error=-109;return false;}
        native_sony_touch_substep=22;
        unsigned loaded=0;
        const int init=sony_geni_firmware_init(&io,&common,native_sony_geni_firmware,
                                              native_sony_geni_firmware_size,&loaded);
        native_sony_touch_fw_loaded=loaded;
        native_sony_touch_fw_revision=engine.read(0x68);
        if(init){native_sony_touch_error=init;return false;}
        const uint32_t dfs=clock.read(0x504);
        unsigned level=0;
        if(dfs&1u) {
            uint32_t configs[8];for(unsigned i=0;i<8;++i)configs[i]=clock.read(0x50c+4*i);
            const int chosen=sony_geni_tcxo_level(configs,8);if(chosen<0){native_sony_touch_error=-106;return false;}
            level=(unsigned)chosen;engine.write(0x7c,level);engine.write(0x80,engine.read(0x80)|1u);
        } else {
            // Dedicated SE4 RCG: parent-map0 selector0=19.2MHz TCXO, HID1=divide1.
            clock.write(0x4f4,(clock.read(0x4f4)&~0x371fu)|1u);
            clock.write(0x4f0,clock.read(0x4f0)|1u);
            unsigned waited=0;while((clock.read(0x4f0)&1u) && waited++<20)IOSleep(1);
            if(clock.read(0x4f0)&1u || !sony_geni_tcxo_config(clock.read(0x4f4))){native_sony_touch_error=-107;return false;}
            engine.write(0x7c,0);engine.write(0x80,engine.read(0x80)&~1u);
        }
        if((engine.read(0x7c)&7u)!=level){native_sony_touch_error=-108;return false;}
        native_sony_touch_clock_level=level;
        native_sony_touch_substep=24;
        engine.write(0x48,0x21);engine.write(0x278,(7u<<20)|(10u<<10)|24u);
        native_sony_touch_dma_mode=engine.read(0x64)&1u;
        IOLog("[sony-touch-engine] fw=%08x if=%08x ios=%08x clk=%08x scl=%08x hw=%08x/%08x mode=%s\n",
            native_sony_touch_fw_revision,engine.read(0x64),engine.read(0x50),engine.read(0x48),engine.read(0x278),
            engine.read(0xe24),engine.read(0xe28),native_sony_touch_dma_mode?"SE-DMA":"FIFO");
        if(native_sony_touch_dma_mode)return prepareDma(io);
        return sony_geni_prepare(&bus,&io,SW82907_ADDRESS,native_sony_touch_qup_version)==0;
    }
    bool wait() {
        for(unsigned ms=0;ms<25;++ms) {
            const int result=sony_geni_poll(&bus);
            native_sony_touch_transfer_irq=bus.last_irq;native_sony_touch_dma_tx=bus.last_dma_tx;
            native_sony_touch_dma_rx=bus.last_dma_rx;native_sony_touch_transfer_error=bus.error;
            if(result==SonyGeniDone)return true;
            if(result==SonyGeniFailed)return false;
            IOSleep(1);
        }
        for(unsigned recovery=0;recovery<3;++recovery) {
            if(sony_geni_timeout(&bus)==SonyGeniFailed)return false;
            for(unsigned ms=0;ms<5;++ms) {
                if(sony_geni_poll(&bus)!=SonyGeniPending)return false;
                IOSleep(1);
            }
        }
        return false;
    }
    void captureBus() {
        native_sony_touch_transfer_irq=bus.last_irq;native_sony_touch_dma_tx=bus.last_dma_tx;
        native_sony_touch_dma_rx=bus.last_dma_rx;native_sony_touch_transfer_error=bus.error;
        native_sony_touch_engine_state=engine.read(0x40);native_sony_touch_engine_ios=engine.read(0x50);
        if(bus.dma_mode){native_sony_touch_tx_in=engine.read(0xc54);native_sony_touch_rx_in=engine.read(0xd54);}
    }
    bool read(uint16_t reg,uint32_t length,uint8_t *destination) {
        native_sony_touch_last_reg=reg;native_sony_touch_last_length=length;
        uint8_t command[2];
        const bool success=!sw82907_read_command(reg,length,command) && !sony_geni_read(&bus,command,2,destination,length) && wait();
        captureBus();
        if(!success)IOLog("[sony-touch-xfer] read reg=%x len=%u phase=%u error=%u irq=%08x dma=%08x/%08x state=%08x ios=%08x\n",
            reg,length,bus.phase,bus.error,bus.last_irq,bus.last_dma_tx,bus.last_dma_rx,native_sony_touch_engine_state,native_sony_touch_engine_ios);
        return success;
    }
    bool word(uint16_t reg,uint32_t value) {
        native_sony_touch_last_reg=reg;native_sony_touch_last_length=4;
        uint8_t command[6];
        const bool success=!sw82907_write_word(reg,value,command) && !sony_geni_write(&bus,command,6) && wait();
        captureBus();
        if(!success)IOLog("[sony-touch-xfer] write reg=%x value=%08x phase=%u error=%u irq=%08x dma=%08x/%08x\n",
            reg,value,bus.phase,bus.error,bus.last_irq,bus.last_dma_tx,bus.last_dma_rx);
        return success;
    }
    bool readWord(uint16_t reg,uint32_t &value) {
        uint8_t data[4];if(!read(reg,sizeof(data),data))return false;
        value=(uint32_t)data[0]|(uint32_t)data[1]<<8|(uint32_t)data[2]<<16|(uint32_t)data[3]<<24;
        return true;
    }
    bool checkBoot() {
        // Same two attempts/10ms as Sony lxs_hal_chk_boot(). A zero boot
        // register was observed on PDX065 after valid chip/product DMA reads.
        // Preserve the vendor's SKIP meaning instead of requiring bit2=1.
        uint32_t value=0;int result=Sw82907BootCrcError;
        for(unsigned attempt=0;attempt<2;++attempt) {
            if(!readWord(0x011,value))return false;
            native_sony_touch_boot_status=value;result=sw82907_boot_result(value);
            IOLog("[sony-touch-boot] attempt=%u raw=%08x result=%d\n",attempt,value,result);
            if(result==Sw82907BootSkip){native_sony_touch_boot_skipped=1;return true;}
            if(result==Sw82907BootOk)break;
            IOSleep(10);
        }
        if(result!=Sw82907BootOk){native_sony_touch_error=-33;return false;}
        for(unsigned attempt=0;attempt<2;++attempt) {
            if(!readWord(SW82907_STATUS_REG,value))return false;
            native_sony_touch_code_status=value;result=sw82907_code_crc_result(value);
            if(result==Sw82907BootSkip){native_sony_touch_boot_skipped=2;return true;}
            if(result==Sw82907BootOk)return true;
            IOSleep(10);
        }
        native_sony_touch_error=-36;return false;
    }
    bool initController() {
        native_sony_touch_substep=31;
        // DT reset-gpio is GPIO24, active-low; vendor reset pulse=5ms, flash settle=110ms.
        gpio.write(4,gpio.read(4)&~2u);
        gpio.write(0,(gpio.read(0)&~0x3ffu)|0x200u);
        IOSleep(5);gpio.write(4,gpio.read(4)|2u);IOSleep(110);
        uint8_t identity[4],product[8];uint32_t version=0;
        native_sony_touch_substep=32;
        if(!read(0,4,identity))return false;
        native_sony_touch_chip_id=(uint32_t)identity[0]|(uint32_t)identity[1]<<8|(uint32_t)identity[2]<<16|(uint32_t)identity[3]<<24;
        if(memcmp(identity,"1067",4)){native_sony_touch_error=-31;return false;}
        if(!readWord(0x642,version))return false;
        native_sony_touch_sensor_version=version;
        if(!sw82907_version_supported(version)){native_sony_touch_error=-35;return false;}
        if(!read(0x644,8,product))return false;
        memcpy(native_sony_touch_product,product,8);native_sony_touch_product[8]=0;
        if(memcmp(product,"S2X65234",8)){native_sony_touch_error=-32;return false;}
        if(!checkBoot())return false;
        IOLog("[sony-touch-sensor] chip=%08x product=%.8s version=%08x boot=%08x skipped=%u\n",
            native_sony_touch_chip_id,native_sony_touch_product,native_sony_touch_sensor_version,
            native_sony_touch_boot_status,native_sony_touch_boot_skipped);
        native_sony_touch_substep=33;
        if(!word(SW82907_DEVICE_CTL,1) || !word(SW82907_DRIVE_CTL,4))return false;
        IOSleep(30);
        native_sony_touch_substep=34;
        if(!word(0xd06,2) || !word(0xd03,2) || !word(SW82907_DRIVE_CTL,0x301))return false;
        IOSleep(30);
        if(!read(SW82907_STATUS_REG,4,identity))return false;
        native_sony_touch_drive_status=(uint32_t)identity[0]|(uint32_t)identity[1]<<8|(uint32_t)identity[2]<<16|(uint32_t)identity[3]<<24;
        IOLog("[sony-touch-drive] status=%08x running=%u\n",native_sony_touch_drive_status,identity[0]&31u);
        if(sw82907_code_crc_result(native_sony_touch_drive_status)!=Sw82907BootOk ||
           (native_sony_touch_drive_status&(1u<<5))==0 ||
           (identity[0]&31u)==0u || (identity[0]&31u)==15u || (identity[0]&31u)==16u){native_sony_touch_error=-34;return false;}
        native_sony_touch_substep=35;
        return true;
    }
};
void fail(int error) {
    if(!native_sony_touch_error)native_sony_touch_error=error;
    IOLog("[sony-touch] stage=%u error=%d firmware=%08x frames=%u valid=%u bad=%u\n",
          native_sony_touch_stage,native_sony_touch_error,native_sony_touch_fw_revision,native_sony_touch_frames,
          native_sony_touch_valid,native_sony_touch_bad);
}
IORegistryEntry *findEventDriver(IORegistryEntry *parent,unsigned depth) {
    if(!depth)return nullptr;
    OSIterator *iterator=parent->getChildIterator(gIOServicePlane);
    if(!iterator)return nullptr;
    IORegistryEntry *found=nullptr;
    while(OSObject *object=iterator->getNextObject()) {
        IORegistryEntry *entry=OSDynamicCast(IORegistryEntry,object);if(!entry)continue;
        if(entry->metaCast("IOHIDEventDriver")){found=entry;found->retain();break;}
        if((found=findEventDriver(entry,depth-1)))break;
    }
    iterator->release();return found;
}
void publishUsage(IOService *device) {
    IORegistryEntry *driver=findEventDriver(device,4);if(!driver)return;
    if(!native_sony_touch_event_driver){
        native_sony_touch_event_driver=1;
        IOLog("[sony-touch-hid] event-driver=%s id=%llx\n",driver->getMetaClass()->getClassName(),driver->getRegistryEntryID());
    }
    OSNumber *page=OSDynamicCast(OSNumber,driver->getProperty("PrimaryUsagePage"));
    OSNumber *usage=OSDynamicCast(OSNumber,driver->getProperty("PrimaryUsage"));
    if(!page || page->unsigned32BitValue()!=13 || !usage || usage->unsigned32BitValue()!=4 ||
       driver->getProperty("Built-In")!=kOSBooleanTrue || driver->getProperty("DisplayIntegrated")!=kOSBooleanTrue) {
        driver->setProperty("Built-In",kOSBooleanTrue);driver->setProperty("DisplayIntegrated",kOSBooleanTrue);
        driver->setProperty("PrimaryUsagePage",13ULL,32);driver->setProperty("PrimaryUsage",4ULL,32);
        if(IORegistryEntry *interface=driver->getParentEntry(gIOServicePlane)) {
            interface->setProperty("Built-In",kOSBooleanTrue);interface->setProperty("DisplayIntegrated",kOSBooleanTrue);
            interface->setProperty("PrimaryUsagePage",13ULL,32);interface->setProperty("PrimaryUsage",4ULL,32);
        }
    }
    driver->release();
}
void usageGuard(void *context,wait_result_t) {
    IOService *device=static_cast<IOService *>(context);
    for(unsigned ms=0;ms<180000;ms+=2){publishUsage(device);IOSleep(2);}
    device->release();
    thread_terminate(current_thread());
}
void touchWorker() {
    Session session;
    native_sony_touch_stage=1;
    if(!session.clocks()){fail(-10);return;}
    native_sony_touch_stage=2;
    if(!session.prepare()){fail(-20);return;}
    native_sony_touch_stage=3;
    if(!session.initController()){fail(-30);return;}
    native_sony_touch_stage=4;
    IOLog("[sony-touch] SW82907 scan started I2C=28 X=1644 Y=3840 IRQ=GPIO25(level-poll)\n");
    unsigned failures=0;
    for(;;) {
        native_sony_touch_last_irq=session.gpio.read(0x1004)&1u;
        if(native_sony_touch_last_irq){IOSleep(2);continue;}
        native_sony_touch_irq_low=native_sony_touch_irq_low+1;
        // One atomic full report avoids mixing two flexible reads from different scans.
        if(!session.read(SW82907_REPORT_REG,sizeof(session.bytes),session.bytes)) {
            publish(Sw82907FrameData{});fail(-40);return;
        }
        native_sony_touch_frames=native_sony_touch_frames+1;
        native_sony_touch_last_ic=(uint32_t)session.bytes[0]|(uint32_t)session.bytes[1]<<8|(uint32_t)session.bytes[2]<<16|(uint32_t)session.bytes[3]<<24;
        native_sony_touch_last_status=(uint32_t)session.bytes[4]|(uint32_t)session.bytes[5]<<8|(uint32_t)session.bytes[6]<<16|(uint32_t)session.bytes[7]<<24;
        native_sony_touch_last_info=(uint32_t)session.bytes[8]|(uint32_t)session.bytes[9]<<8|(uint32_t)session.bytes[10]<<16|(uint32_t)session.bytes[11]<<24;
        Sw82907FrameData frame={};
        const int result=sw82907_decode(session.bytes,sizeof(session.bytes),&frame);
        if(result==Sw82907Frame) {
            native_sony_touch_valid=native_sony_touch_valid+1;failures=0;publish(frame);
            if(frame.count){native_sony_touch_last_x=frame.contacts[0].x;native_sony_touch_last_y=frame.contacts[0].y;}
        } else if(result<0) {
            native_sony_touch_bad=native_sony_touch_bad+1;
            if(++failures==3){publish(Sw82907FrameData{});fail(result);return;}
        }
        IOSleep(1);
    }
}
void touchThread(void *,wait_result_t) {touchWorker();thread_terminate(current_thread());}
}

extern "C" void native_touch_set_sink(void (*sink)(void *),void *context) {
    __atomic_store_n(&gSink,nullptr,__ATOMIC_RELEASE);
    __atomic_store_n(&gContext,context,__ATOMIC_RELEASE);
    __atomic_store_n(&gSink,sink,__ATOMIC_RELEASE);
}
extern "C" void native_touch_published(void) {
    if(void (*sink)(void *)=__atomic_load_n(&gSink,__ATOMIC_ACQUIRE))
        sink(__atomic_load_n(&gContext,__ATOMIC_ACQUIRE));
}
extern "C" void native_hid_input_observed(unsigned event,int result) {
    if(event<8){native_hid_input_events[event]=native_hid_input_events[event]+1;native_hid_input_results[event]=result;}
    if(event==6)native_sony_touch_hid_result=result;
}
extern "C" bool native_hid_input_requested(void){return false;}
extern "C" void native_hid_live_checkpoint(IOService *device) {
    publishUsage(device);
}
static void touchStartupWorker() {
    // Shared069 config mutex is acquired by the actual SMMU/GCC operations.
    native_sony_touch_hid_load=OSKextLoadKextWithIdentifier("com.apple.iokit.IOHIDFamily");
    if(native_sony_touch_hid_load){fail(-1);return;}
    const OSSymbol *name=OSSymbol::withCString("IOHIDDevice");
    const OSMetaClass *meta=name?OSMetaClass::getMetaClassWithName(name):nullptr;
    const bool valid=meta && meta->getClassSize()==208;OSSafeReleaseNULL(name);
    native_sony_touch_hid_size=meta?meta->getClassSize():0;
    if(!valid){fail(-2);return;}
    void *handle=OSMetaClass::preModLoad(g_kernel_kmod_info.name);
    if(!handle){fail(-3);return;}
    native_sony_hid_static_init();native_sony_touch_hid_meta=OSMetaClass::postModLoad(handle);
    if(native_sony_touch_hid_meta){fail(-4);return;}
    OSDictionary *matching=IOService::serviceMatching("IOHIDResource");
    IOService *parent=matching?IOService::waitForMatchingService(matching,5000000000ULL):nullptr;
    OSSafeReleaseNULL(matching);
    native_sony_touch_hid_resource=parent!=nullptr;
    IOService *device=native_hid_input_allocate();bool attached=false;
    if(!parent || !device || !device->init() || !(attached=device->attach(parent)) || !device->start(parent)) {
        if(attached)device->detach(parent);OSSafeReleaseNULL(device);OSSafeReleaseNULL(parent);fail(-5);return;
    }
    OSSafeReleaseNULL(parent);
    native_sony_touch_hid_started=1;
    // Device and its provider attachment remain retained for the boot. No scripted Home input.
    thread_t thread=nullptr;
    device->retain();
    if(kernel_thread_start(usageGuard,device,&thread)==KERN_SUCCESS)thread_deallocate(thread);
    else device->release();
    if(kernel_thread_start(touchThread,nullptr,&thread)==KERN_SUCCESS)thread_deallocate(thread);
    else fail(-6);
}
static void touchStartup(void *,wait_result_t) {touchStartupWorker();thread_terminate(current_thread());}
extern "C" void native_sony_touch_start(void) {
    unsigned enabled=0;
    if(!PE_parse_boot_argn("sony-touch",&enabled,sizeof(enabled)) || enabled!=1)return;
    static bool started=false;if(__atomic_exchange_n(&started,true,__ATOMIC_ACQ_REL))return;
    thread_t thread=nullptr;
    if(kernel_thread_start(touchStartup,nullptr,&thread)==KERN_SUCCESS)thread_deallocate(thread);
    else fail(-7);
}
