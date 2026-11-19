// SPDX-License-Identifier: GPL-2.0-only
// Verbatim Sony Linux C read functions with modeled controller/MMIO services.
// Compare the unchanged official br_read8 opcode/status/data contract.
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "BootResetCore.h"
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
enum pmic_arb_channel { PMIC_ARB_CHANNEL_RW, PMIC_ARB_CHANNEL_OBS };
enum {
    PMIC_ARB_CMD=0, PMIC_ARB_STATUS=8, PMIC_ARB_RDATA0=0x18, PMIC_ARB_RDATA1=0x1c,
    PMIC_ARB_TIMEOUT_US=1000, PMIC_ARB_MAX_TRANS_BYTES=8,
    PMIC_ARB_STATUS_DONE=1, PMIC_ARB_STATUS_FAILURE=2, PMIC_ARB_STATUS_DENIED=4, PMIC_ARB_STATUS_DROPPED=8,
    PMIC_ARB_OP_READ=15, PMIC_ARB_OP_EXT_READ=13, PMIC_ARB_OP_EXT_READL=1
};
struct spmi_pmic_arb;
struct pmic_arb_ver_ops {
    int (*ppid_to_apid)(struct spmi_pmic_arb *,u16);
    int (*offset)(struct spmi_pmic_arb *,u8,u16,enum pmic_arb_channel);
    u32 (*fmt_cmd)(u8,u8,u16,u8);
};
struct apid_data { u8 write_ee; };
struct spmi_pmic_arb {
    uint8_t *rd_base;
    u8 ee;
    struct apid_data apid_data[1024];
    struct pmic_arb_ver_ops *ver_ops;
    unsigned lock;
};
struct spmi_controller { struct spmi_pmic_arb *data; int dev; };
static struct spmi_pmic_arb *spmi_controller_get_drvdata(struct spmi_controller *ctrl) { return ctrl->data; }
static unsigned commandWrites, statusReads, dataReads, delays, locked, readyAfter;
static uint32_t finalStatus, commandValue, modelData=0xc0;
static uintptr_t expectedChannel;
static void writel_relaxed(uint32_t value, void *address) {
    assert(locked && (uintptr_t)address==expectedChannel);
    commandValue=value; ++commandWrites;
}
static uint32_t readl_relaxed(void *address) {
    assert(locked && commandWrites==1 && (uintptr_t)address==expectedChannel+8);
    ++statusReads;
    return statusReads>readyAfter?finalStatus:0;
}
static uint32_t __raw_readl(void *address) {
    assert(locked && commandWrites==1 && (uintptr_t)address==expectedChannel+0x18);
    assert((finalStatus&1) && !(finalStatus&14)); ++dataReads; return modelData;
}
static void udelay(unsigned us) { assert(us==1 && locked); ++delays; }
#define dev_err(...) ((void)0)
#define WARN_ON(value) ((void)(value))
#define __iomem
#define min_t(type,a,b) ((type)(a)<(type)(b)?(type)(a):(type)(b))
#define raw_spin_lock_irqsave(ptr,flags) do { (flags)=0; assert(!*(ptr) && !locked); *(ptr)=1; locked=1; } while(0)
#define raw_spin_unlock_irqrestore(ptr,flags) do { (void)(flags); assert(*(ptr) && locked); *(ptr)=0; locked=0; } while(0)

#include "actual-sony-linux-read.inc"

static int findNamed(struct spmi_pmic_arb *arb,u16 ppid) { (void)arb; assert(ppid==0x13); return 560; }
static void reset(unsigned delay,uint32_t status) {
    commandWrites=statusReads=dataReads=delays=locked=0;
    readyAfter=delay; finalStatus=status; commandValue=0;
}
static int normalizedLinux(int rc) { return !rc?0:rc==-ETIMEDOUT?1:2; }
int main(void) {
    uint32_t observer[0x8000/4]={0};
    struct pmic_arb_ver_ops ops={findNamed,pmic_arb_offset_v7,pmic_arb_fmt_cmd_v2};
    struct spmi_pmic_arb arb={0}; arb.rd_base=(uint8_t *)observer;arb.ver_ops=&ops;arb.ee=0;
    struct spmi_controller ctrl={&arb,0};
    expectedChannel=(uintptr_t)observer+0x20*560;
    assert(pmic_arb_offset_v7(&arb,0,0x1310,PMIC_ARB_CHANNEL_OBS)==0x4600);
    assert(pmic_arb_fmt_cmd_v2(1,0,0x1310,0)==0x08000100);
    // Linux OBS access itself does not require write_ee or IRQ-owner. Native
    // adds stricter same-boot metadata selection before its first CMD.
    arb.apid_data[560].write_ee=4;
    assert(pmic_arb_offset_v7(&arb,0,0x1310,PMIC_ARB_CHANNEL_OBS)==0x4600);
    assert(pmic_arb_offset_v7(&arb,0,0x1310,PMIC_ARB_CHANNEL_RW)==-EPERM);
    arb.apid_data[560].write_ee=0;
    assert(pmic_arb_offset_v7(&arb,0,0x1310,PMIC_ARB_CHANNEL_RW)==0x230000);
    uint32_t *channel=observer+0x4600/4;
    struct br_arbiter native={NULL,NULL,0};
    for (uint32_t status=0;status<16;++status) {
        reset(0,status);uint8_t linuxData=0x55;
        const int linuxResult=pmic_arb_read_cmd(&ctrl,0x38,0,0x1310,&linuxData,1);
        assert(commandWrites==1 && commandValue==0x08000100 && !locked);
        const bool success=(status&1) && !(status&14);
        assert(dataReads==(success?1u:0u) && linuxData==(success?0xc0:0x55));
        channel[BR_STATUS/4]=status;channel[BR_RDATA0/4]=modelData;uint8_t nativeData=0x55;
        const int nativeResult=br_read8(observer,&native,560,0x10,&nativeData);
        assert(channel[0]==commandValue && nativeResult==normalizedLinux(linuxResult));
        assert(nativeData==linuxData);
        if (!(status&1)) assert(statusReads==1000 && delays==1000);
    }
    const unsigned readyDelays[]={1,25,999};
    for (unsigned i=0;i<3;++i) {
        unsigned delay=readyDelays[i];reset(delay,1);uint8_t raw=0;
        assert(!pmic_arb_read_cmd(&ctrl,0x38,0,0x1310,&raw,1));
        assert(raw==0xc0 && statusReads==delay+1 && delays==delay && dataReads==1);
    }
    reset(1000,1);uint8_t raw=0x55;
    assert(pmic_arb_read_cmd(&ctrl,0x38,0,0x1310,&raw,1)==-ETIMEDOUT && raw==0x55 && !dataReads);
    puts("PASS verbatim Sony Linux v7 offset/fmt/read/wait vs official br_read8: APID560 OBS4600/CMD08000100/STATUS8/RDATA18/all16status outcomes; Linux1000x1us deadline, native100000polls (not a calibrated1ms equivalence); no STATUSclear/WDATA/PMICwrite");
}
