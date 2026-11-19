// SPDX-License-Identifier: BSD-2-Clause-Patent
// Production Session is extracted by check-sony-touch-chain.py. Only platform
// services and hardware responses below are models, not successful phone evidence.
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <map>
#include <vector>
#include <string>
#include "Sw82907.h"
#if defined(SONY_BOOT_POLICY_FIXTURE)
#include "Sw82907Boot.h"
#endif
#include "GeniI2c.h"
#include "GeniInit.h"
#include "SonyTouchIrq.h"
#include "HidTouchReport.h"
#include "SmmuBypass.h"
using IOReturn=int;
using IOOptionBits=unsigned;
using addr64_t=uint64_t;
constexpr int kIOReturnSuccess=0,kIODirectionInOut=1,kIOMemoryPhysicallyContiguous=2;
static void *kernel_task=nullptr;
constexpr uint64_t kGpioBase=0x0f100000,kGccBase=0x00100000,kEngineBase=0x00a90000;
constexpr uint32_t kVote=(1u<<18)|(1u<<19)|(1u<<20)|(1u<<21)|(1u<<26);
static unsigned sleeps,reads,completedWrites,irqRoutes;
static bool badProduct,negativeBoot,forceNack,forceSmmuConflict,dmaSelected;
static uint32_t bootValue=4,versionValue=0x040a0112,preCodeStatus=0x00508060,driveStatus=0x00558062;
static unsigned bootReads;
static bool recoverBootCrc;
static unsigned resetLow,resetHigh;
static std::map<uint64_t,uint32_t> regs;
static std::map<unsigned,uint32_t> sensor;
static std::vector<uint8_t> tx,rx;
static unsigned sensorAddress,rxAt;
static uint8_t scanFrame[SW82907_FRAME_BYTES];
static uint8_t dmaBytes[32768];
static constexpr uint64_t dmaPhysical=0x980000000ull;
static void IOLog(const char *,...) {}
static void IOSleep(unsigned ms){sleeps+=ms;assert(sleeps<10000);}
static void IODelay(unsigned us){(void)us;}
static void put32(uint8_t *p,uint32_t n){for(unsigned i=0;i<4;++i)p[i]=(uint8_t)(n>>(i*8));}
static void dmaCache(void *,uint32_t,unsigned){}
static void dmaClean(void *,void *,uint32_t){}
static void dmaPrepareRx(void *,void *,uint32_t){}
static void dmaInvalidate(void *,void *,uint32_t){}
struct IOBufferMemoryDescriptor {
    static IOBufferMemoryDescriptor *inTaskWithPhysicalMask(void *,IOOptionBits,unsigned size,uint64_t mask){
        assert(size==sizeof(dmaBytes) && mask==0xfffffff000ull);return new IOBufferMemoryDescriptor;
    }
    int prepare(){return 0;}
    int complete(){return 0;}
    uint64_t getPhysicalSegment(unsigned offset,addr64_t *length){assert(!offset);*length=sizeof(dmaBytes);return dmaPhysical;}
    void *getBytesNoCopy(){return dmaBytes;}
    void release(){delete this;}
};
static IOBufferMemoryDescriptor *native_sony_touch_pinned_dma;
class SonySmmuGuard {public:bool ready() const{return true;}};
extern const uint8_t native_sony_geni_firmware[];
extern const uint32_t native_sony_geni_firmware_size;
/* PRODUCTION_GLOBALS */
static void acceptTx(){
    assert(tx.size()>=2);sensorAddress=((tx[0]&15u)<<8)|tx[1];
    if(forceNack){regs[kEngineBase+0x610]=(1u<<3)|(1u<<10);return;}
    if(tx[0]&0x40u){
        assert(tx.size()==6);sensor[sensorAddress]=(uint32_t)tx[2]|(uint32_t)tx[3]<<8|(uint32_t)tx[4]<<16|(uint32_t)tx[5]<<24;
        ++completedWrites;
    }else assert(tx.size()==2);
}
static void prepareRx(unsigned count){
    ++reads;rx.assign(count,0);rxAt=0;
    if(sensorAddress==0){assert(count==4);std::memcpy(rx.data(),"1067",4);}
    else if(sensorAddress==0x644){assert(count==8);std::memcpy(rx.data(),badProduct?"INVALID0":"S2X65234",8);}
    else if(sensorAddress==0x011){assert(count==4);++bootReads;put32(rx.data(),negativeBoot?0xc:recoverBootCrc && bootReads==1?0xc:bootValue);}
    else if(sensorAddress==0x642){assert(count==4);put32(rx.data(),versionValue);}
    else if(sensorAddress==0xd00){assert(count==4);put32(rx.data(),(3840u<<16)|1644u);}
    else if(sensorAddress==0x601){assert(count==4);put32(rx.data(),sensor[0xc03]==0x301?driveStatus:preCodeStatus);}
    else if(sensorAddress==0x600){assert(count==sizeof(scanFrame));std::memcpy(rx.data(),scanFrame,count);}
    else {assert(count==4);put32(rx.data(),sensor[sensorAddress]);}
}
struct Region {
    uint64_t base=0;unsigned size=0;
    bool open(uint64_t at,uint64_t bytes){base=at;size=(unsigned)bytes;return true;}
    uint32_t read(uint32_t offset) const {
        assert(offset<size);const uint64_t at=base+offset;
        if(base==kEngineBase){
            assert(offset<0x2000 || offset>0x2008);
            if(offset==0x610 && !(regs[base+0xe1c]&4))return 0;
            if(offset==0xc40 && !(regs[base+0xe1c]&2))return 0;
            if(offset==0xd40 && !(regs[base+0xe1c]&1))return 0;
            if(offset==0x804){unsigned n=(unsigned)rx.size()-rxAt;return n?((n+3)/4)|(1u<<31)|((n%4)<<28):0;}
            if(offset==0x780){uint32_t word=0;for(unsigned i=0;i<4 && rxAt<rx.size();++i)word|=(uint32_t)rx[rxAt++]<<(i*8);return word;}
        }
        return regs[at];
    }
    void write(uint32_t offset,uint32_t value) const {
        assert(offset<size);const uint64_t at=base+offset;
        if(base==kEngineBase){
            assert(offset<0x2000 || offset>0x2008);
            if(offset==0x618){regs[base+0x610]&=~value;return;}
            if(offset==0xc44){regs[base+0xc40]&=~value;return;}
            if(offset==0xd44){regs[base+0xd40]&=~value;return;}
            regs[at]=value;
            if(offset==0x600){
                assert(irqRoutes && native_sony_touch_irq_masked);unsigned opcode=value>>27;
                assert(((value>>9)&127)==0x28);
                if(opcode==1){tx.clear();if(!dmaSelected)regs[base+0x610]=1u<<30;}
                else if(opcode==2){prepareRx(regs[base+0x270]);if(!dmaSelected)regs[base+0x610]=(1u<<27)|1;}
                else assert(false);
            }
            if(offset==0x700){
                for(unsigned i=0;i<4 && tx.size()<regs[base+0x26c];++i)tx.push_back((uint8_t)(value>>(i*8)));
                if(tx.size()==regs[base+0x26c]){acceptTx();if(!forceNack)regs[base+0x610]|=1;}
            }
            if(offset==0xc3c){
                uint64_t physical=((uint64_t)regs[base+0xc34]<<32)|regs[base+0xc30];assert(physical==dmaPhysical && value<=8);
                tx.assign(dmaBytes,dmaBytes+value);acceptTx();if(!forceNack)regs[base+0xc40]=1;
            }
            if(offset==0xd3c){
                uint64_t physical=((uint64_t)regs[base+0xd34]<<32)|regs[base+0xd30];assert(physical==dmaPhysical+16384 && value==rx.size());
                std::memcpy(dmaBytes+16384,rx.data(),value);regs[base+0xd40]=1;
            }
            if(offset==0x604)regs[base+0x610]|=value==4?1u<<4:1u<<5;
            return;
        }
        if(at==kGpioBase+24*4096+4){if(value&2)++resetHigh;else ++resetLow;}
        regs[at]=value;
        if(at==kGccBase+0x184f0)regs[at]&=~1u;
    }
};
static int attachImpl(uint32_t id,bool,void (*)(void *),void *,uint32_t *rb,uint64_t *route){assert(id==389 && !regs[kEngineBase+0xe1c]);irqRoutes=1;*rb=0;*route=0;return 0;}
static int maskImpl(uint32_t id,bool){assert(id==389);return irqRoutes?0:-2;}
static auto armcpu_spi_attach=&attachImpl;
static auto armcpu_spi_mask=&maskImpl;
/* PRODUCTION_CALLBACKS */
/* PRODUCTION_SESSION */
static void initialize(bool dma){
    assert(!native_sony_touch_pinned_dma);regs.clear();sensor.clear();tx.clear();rx.clear();rxAt=0;sleeps=reads=completedWrites=irqRoutes=resetLow=resetHigh=bootReads=0;
    native_sony_touch_error=0;native_sony_touch_irq_masked=0;dmaSelected=dma;
    regs[kGccBase]=1u<<31;regs[0xac0004]=0x300a0000;
    regs[kEngineBase+0x68]=0x303;regs[kEngineBase+0x64]=dma?1:0;
    regs[kEngineBase+0xe24]=regs[kEngineBase+0xe28]=(32u<<24)|(64u<<16);
    regs[0x15000020]=(1u<<30)|8;regs[0x15000024]=(2u<<28)|16;regs[0x15000028]=0x1222;
    if(forceSmmuConflict){regs[0x15000800]=0x800000a3;regs[0x15000c00]=3;}
    std::memset(scanFrame,0,sizeof(scanFrame));put32(scanFrame,6);put32(scanFrame+4,0x00558062);
}
static void point(unsigned event,unsigned x,unsigned y){
    put32(scanFrame+8,1u<<8);scanFrame[12]=(uint8_t)((event<<4)|1);scanFrame[13]=2;
    scanFrame[14]=(uint8_t)x;scanFrame[15]=(uint8_t)(x>>8);scanFrame[16]=(uint8_t)y;scanFrame[17]=(uint8_t)(y>>8);
}
int main(int argc,char **argv){
    if(argc>1 && !std::strcmp(argv[1],"old-boot")){
        bootValue=0;initialize(true);Session s;assert(s.clocks() && s.prepare() && !s.initController());
        assert(native_sony_touch_error==-33 && native_sony_touch_chip_id==0x37363031 &&
            !std::strcmp(native_sony_touch_product,"S2X65234") && native_sony_touch_boot_status==0 && !completedWrites && !s.bus.error);
        puts("PASS exact065 actualSession reproduces runtime chip37363031/productS2X65234/boot0 -> error-33 before scan commands");return 0;
    }
    if(argc>1 && !std::strcmp(argv[1],"old-timeout")){
        initialize(true);Session s;assert(s.clocks() && s.prepare());assert(!s.initController());
        assert(s.bus.timeouts && reads==0 && s.bus.tx_done==0);puts("PASS old064 actualSession times out on TX DMA_DONE-only before the first sensor read");
        // Fixture owns its fake DMA buffer and has completed the modeled abort.
        s.bus.dma_started=0;return 0;
    }
    for(bool dma:{false,true}){
        initialize(dma);Session s;assert(s.clocks() && s.prepare() && s.initController());
        assert(resetLow==1 && resetHigh==1 && reads>=4 && sensor[0xc00]==1 && sensor[0xc03]==0x301 && sensor[0xd03]==2 && sensor[0xd06]==2);
        SonyHidTouchState previous={};
        for(unsigned frame=0;frame<3;++frame){
            point(frame==2?3:frame==1?2:1,822,frame?2000:3840);
            assert(s.read(SW82907_REPORT_REG,sizeof(s.bytes),s.bytes));Sw82907FrameData contacts={};
            assert(!sw82907_decode(s.bytes,sizeof(s.bytes),&contacts));SonyHidContact normalized[10]={};
            for(unsigned i=0;i<contacts.count;++i)normalized[i]={contacts.contacts[i].id,(uint16_t)((uint64_t)contacts.contacts[i].x*32767/1644),(uint16_t)((uint64_t)contacts.contacts[i].y*32767/3840)};
            SonyHidTouchPlan plan={};assert(!sony_hid_touch_plan(&previous,normalized,contacts.count,&plan) && plan.count==1);
            assert(plan.reports[0][0]==3 && plan.reports[0][61]==1 && plan.reports[0][1]==(frame==2?2:3) && plan.reports[0][2]==2);
            previous=plan.after[0];
        }
        assert(!previous.count);printf("PASS actualSession %s clock/reset/identity/scan and sensor down-move-up -> HID reports\n",dma?"DMA_DONE-only":"FIFO");
    }
    badProduct=true;initialize(false);{Session s;assert(s.clocks()&&s.prepare()&&!s.initController() && completedWrites==0);}badProduct=false;
    negativeBoot=true;initialize(false);{Session s;assert(s.clocks()&&s.prepare()&&!s.initController() && completedWrites==0);}negativeBoot=false;
    forceNack=true;initialize(false);{Session s;assert(s.clocks()&&s.prepare()&&!s.initController() && s.bus.error==SonyGeniBusError);}forceNack=false;
    forceSmmuConflict=true;initialize(true);{Session s;assert(s.clocks()&&!s.prepare() && reads==0);}forceSmmuConflict=false;
    puts("PASS actualSession refuses wrong product/CRC/NACK/SMMU conflict without starting scanning");
#if defined(SONY_BOOT_POLICY_FIXTURE)
    for(uint32_t status:{0u,0xffffffffu,2u,6u,0x10u,4u}){
        bootValue=status;initialize(true);Session s;assert(s.clocks()&&s.prepare()&&s.initController());
        assert(sensor[0xc03]==0x301 && native_sony_touch_drive_status==driveStatus && native_sony_touch_sensor_version==versionValue);
    }
    bootValue=4;recoverBootCrc=true;initialize(true);{Session s;assert(s.clocks()&&s.prepare()&&s.initController() && bootReads==2);}recoverBootCrc=false;
    for(uint32_t version:{0u,0xffffffffu,0x030a0112u,0x040b0112u}){
        versionValue=version;initialize(true);Session s;assert(s.clocks()&&s.prepare()&&!s.initController());assert(native_sony_touch_error==-35 && !completedWrites);
    }
    versionValue=0x040a0112;preCodeStatus=0x00508020;initialize(true);{Session s;assert(s.clocks()&&s.prepare()&&!s.initController() && native_sony_touch_error==-36 && !completedWrites);}
    preCodeStatus=0x00508060;
    for(uint32_t status:{0u,0xffffffffu,0x00558060u,0x0055806fu,0x00558070u,0x00558022u}){
        driveStatus=status;bootValue=0;initialize(true);Session s;assert(s.clocks()&&s.prepare()&&!s.initController() && native_sony_touch_error==-34);
    }
    puts("PASS vendor boot zero/busy/unavailable/no-done policy, CRC retry/failure, chip/protocol mismatch and independent post-scan running/CRC gate");
#endif
}
