/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/* Register layout/AMC protocol: Linux rpmh-rsc.c, locked Ath12k Linux source;
 * read response path follows RPMh read-message protocol (8-byte v3 messages).
 * New code uses non-destructive dynamic reservation, never private TCS0. */
#include "SonyRpmh.h"
#ifdef KERNEL
#include <sys/errno.h>
#else
#include <errno.h>
#endif
#include <string.h>
static uint32_t rd(struct sony_rpmh *r,uint32_t o){return r->io.read(r->io.context,r->tcs_base+o);}
static void wr(struct sony_rpmh *r,uint32_t o,uint32_t v){r->io.write(r->io.context,r->tcs_base+o,v);}
static int sync_write(struct sony_rpmh *r,uint32_t o,uint32_t v){
    wr(r,o,v);
    for(unsigned n=0;n<1000;n++){if(rd(r,o)==v)return 0;r->io.delay_us(r->io.context,1);}
    return EIO;
}
int sony_rpmh_init(struct sony_rpmh *r,const struct sony_rpmh_io *io,uint32_t base,unsigned drv,uint32_t active){
    if(!r || !io || !io->read || !io->write || !io->delay_us || !active || drv>2 || base%4)return EINVAL;
    memset(r,0,sizeof(*r));r->io=*io;r->tcs_base=base;r->active_mask=active;
    uint32_t id=io->read(io->context,0),major=(id>>16)&255;
    if(id==UINT32_MAX || major<2 || major>3)return ENOTSUP;
    uint32_t cfg=io->read(io->context,0x0c);
    unsigned count=(cfg>>(6*drv))&63;r->ncpt=(cfg>>27)&31;
    if(!count || count>16 || !r->ncpt || r->ncpt>16 || active&~((1u<<count)-1))return ENOTSUP;
    r->cmd_stride=major>=3?24:20;
    r->wait=major>=3?0x20:0x10;r->control=major>=3?0x24:0x14;
    r->status=major>=3?0x28:0x18;r->cmd_enable=major>=3?0x2c:0x1c;
    r->msgid=major>=3?0x34:0x30;r->cmd_addr=major>=3?0x38:0x34;
    r->cmd_data=major>=3?0x3c:0x38;r->cmd_status=major>=3?0x40:0x3c;r->resp_data=major>=3?0x44:0x40;
    return 0;
}
int sony_rpmh_transfer(struct sony_rpmh *r,uint32_t address,bool write,uint32_t *value){
    if(!r || !value || !address || address%4)return EINVAL;
    unsigned selected=32;
    /* Reserve only an actually idle ACTIVE TCS. Never touch solver sleep/wake
     * tables, pending retained commands, or an earlier uncertain transaction. */
    for(int i=31;i>=0;i--){
        uint32_t bit=1u<<(unsigned)i,b=(unsigned)i*672u;
        if(!(r->active_mask&bit) || ((r->claimed|r->poisoned)&bit))continue;
        if(rd(r,b+r->cmd_enable) || (rd(r,b+r->control)&((1u<<16)|(1u<<24))) || !(rd(r,b+r->status)&1u))continue;
        selected=(unsigned)i;break;
    }
    if(selected==32)return EBUSY;
    const uint32_t bit=1u<<selected,b=selected*672u;
    r->claimed|=bit;r->last_tcs=selected;r->last_address=address;
    const uint32_t irq=rd(r,0);r->irq_original=irq;
    int e=sync_write(r,0,irq|bit);
    if(!e){wr(r,8,bit);if(r->io.completed)(void)r->io.completed(r->io.context);}
    if(!e)e=sync_write(r,b+r->control,0);
    /* MSGID payload8, response required, write only when requested. Do not
     * fake boot vote zero if a read isn't supported by AOP/secure firmware. */
    if(!e)e=sync_write(r,b+r->msgid,8u|(1u<<8)|(write?(1u<<16):0));
    if(!e)e=sync_write(r,b+r->cmd_addr,address);
    if(!e && write)e=sync_write(r,b+r->cmd_data,*value);
    if(!e)e=sync_write(r,b+r->wait,1);
    if(!e)e=sync_write(r,b+r->cmd_enable,1);
    if(!e)e=sync_write(r,b+r->control,1u<<16);
    if(e){
        /* No trigger was issued. Return only our temporary configuration to
         * idle and restore IRQ bit; leave every other slot/IRQ owner alone. */
        wr(r,b+r->cmd_enable,0);wr(r,b+r->control,0);wr(r,0,(rd(r,0)&~bit)|(irq&bit));r->claimed&=~bit;
        r->last_error=e;return e;
    }
    wr(r,b+r->control,(1u<<16)|(1u<<24));
    bool done=false;
    for(unsigned poll=0;poll<100000;poll++){
        uint32_t observed=rd(r,4);if(r->io.completed)observed|=r->io.completed(r->io.context);
        if(observed&bit){done=true;break;}r->io.delay_us(r->io.context,1);
    }
    r->last_status=rd(r,b+r->status);r->last_command=rd(r,b+r->cmd_status);
    if(!done || !(r->last_status&1u) || (r->last_command&((1u<<8)|(1u<<16)))!=((1u<<8)|(1u<<16))){
        r->poisoned|=bit;r->last_error=!done?ETIMEDOUT:EIO;
        /* Must not cancel/reuse a TCS whose remote write might still commit. */
        return r->last_error;
    }
    if(!write)*value=rd(r,b+r->resp_data);
    e=sync_write(r,b+r->control,1u<<16);if(!e)e=sync_write(r,b+r->control,0);
    if(!e)e=sync_write(r,b+r->cmd_enable,0);
    wr(r,8,bit);wr(r,0,(rd(r,0)&~bit)|(irq&bit));
    if(e)r->poisoned|=bit;else r->claimed&=~bit;
    r->last_error=e;return e;
}
