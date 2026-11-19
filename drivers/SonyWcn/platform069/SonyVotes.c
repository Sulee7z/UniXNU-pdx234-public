/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include "SonyVotes.h"
#ifdef KERNEL
#include <sys/errno.h>
#else
#include <errno.h>
#endif
#include <string.h>
static int read_vote(struct sony_vote_resource *r,const struct sony_vote_io *io){
    struct sony_vote vote={0};
    int e=io->transfer(io->context,r->address,false,&vote.millivolts);
    if(!e)e=io->transfer(io->context,r->address+4,false,&vote.enabled);
    if(!e)e=io->transfer(io->context,r->address+8,false,&vote.mode);
    if(e)return e;
    /* RSC read returns boot AP resource settings. Preserve even an inherited
     * zero vote exactly; reject invalid values instead of coercing a read. */
    if(vote.enabled>1 || vote.mode>7 || vote.millivolts>6000)return EIO;
    r->boot=r->applied=vote;r->initialized=true;return 0;
}
static struct sony_vote aggregate(const struct sony_vote_resource *r){
    struct sony_vote result=r->boot;
    for(unsigned i=0;i<SONY_VOTE_CLIENTS;i++)if(r->client[i].enabled){
        result.enabled=1;
        if(r->client[i].mode>result.mode)result.mode=r->client[i].mode;
        if(r->client[i].millivolts>result.millivolts)result.millivolts=r->client[i].millivolts;
    }
    return result;
}
int sony_vote_update(struct sony_vote_resource *r,const struct sony_vote_io *io,unsigned client,unsigned mode,unsigned uv,bool enabled){
    if(!r || !io || !io->transfer || client>=SONY_VOTE_CLIENTS || !r->address || r->address%4 || mode>7)return EINVAL;
    if(enabled && (!mode || !uv || uv<r->min_uv || uv>r->max_uv))return ERANGE;
    if(r->poisoned)return EIO;
    if(!r->initialized){int e=read_vote(r,io);if(e)return e;}
    const struct sony_vote before=r->client[client];
    r->client[client]=(struct sony_vote){enabled?mode:0,enabled?(uv+999)/1000:0,enabled?1u:0u};
    const struct sony_vote want=aggregate(r),old=r->applied;
    if(!memcmp(&want,&old,sizeof(want)))return 0;
    /* Mode, voltage, then enable when powering/increasing. Disable first only
     * on last release to an originally disabled vote. All changes await ACK. */
    uint32_t addresses[3]={r->address+8,r->address,r->address+4};
    uint32_t values[3]={want.mode,want.millivolts,want.enabled};
    uint32_t previous[3]={old.mode,old.millivolts,old.enabled};
    if(!want.enabled){addresses[0]=r->address+4;values[0]=want.enabled;previous[0]=old.enabled;
        addresses[1]=r->address;values[1]=want.millivolts;previous[1]=old.millivolts;
        addresses[2]=r->address+8;values[2]=want.mode;previous[2]=old.mode;}
    unsigned done=0;int e=0;
    for(;done<3;done++){
        if(values[done]==previous[done])continue;
        e=io->transfer(io->context,addresses[done],true,&values[done]);if(e)break;
    }
    if(e){
        r->client[client]=before;
        /* Timeout can mean the remote write commits later. Never claim that
         * restoring a software snapshot undid that transaction. */
        if(e==ETIMEDOUT){r->poisoned=true;return e;}
        while(done){--done;if(values[done]!=previous[done]){
            int restore=io->transfer(io->context,addresses[done],true,&previous[done]);
            if(restore)r->poisoned=true;
        }}
        return e;
    }
    r->applied=want;return 0;
}
static uint32_t field(uint64_t kbps,uint32_t width,uint32_t unit){
    /* Same dimensions as qcom_icc_bcm_voter: kB/s*BCM_width/buswidth16,
     * convert to B/s then divide unit; saturating14-bit vote. */
    if(!kbps)return 0;
    if(kbps>UINT64_MAX/width/1000)return 0x3fff;
    uint64_t scaled=(kbps*width+15)/16;
    if(scaled>UINT64_MAX/1000)return 0x3fff;
    uint64_t vote=(scaled*1000+unit-1)/unit;
    return vote>0x3fff?0x3fff:vote?((uint32_t)vote):1;
}
int sony_bcm_update(struct sony_bcm_resource *r,const struct sony_vote_io *io,unsigned client,uint64_t avg,uint64_t peak){
    if(!r || !io || !io->transfer || client>=SONY_VOTE_CLIENTS || !r->address || !r->width || !r->unit)return EINVAL;
    if(r->poisoned)return EIO;
    if(!r->initialized){int e=io->transfer(io->context,r->address,false,&r->boot);if(e)return e;
        r->applied=r->boot;r->initialized=true;}
    struct sony_bcm_vote old=r->client[client];r->client[client]=(struct sony_bcm_vote){avg,peak};
    uint64_t average=0,maximum=0;bool any=false;
    for(unsigned i=0;i<SONY_VOTE_CLIENTS;i++){
        any|=r->client[i].average||r->client[i].peak;
        if(UINT64_MAX-average<r->client[i].average)average=UINT64_MAX;else average+=r->client[i].average;
        if(r->client[i].peak>maximum)maximum=r->client[i].peak;
    }
    uint32_t want=r->boot;
    if(any){uint32_t x=field(average,r->width,r->unit),y=field(maximum,r->width,r->unit);
        if((want>>14&0x3fff)>x)x=want>>14&0x3fff;if((want&0x3fff)>y)y=want&0x3fff;
        want=(1u<<30)|(1u<<29)|(x<<14)|y;}
    if(want==r->applied)return 0;
    int e=io->transfer(io->context,r->address,true,&want);
    if(e){r->client[client]=old;if(e==ETIMEDOUT)r->poisoned=true;return e;}
    r->applied=want;return 0;
}
int sony_arc_update(struct sony_arc_resource *r,const struct sony_vote_io *io,unsigned client,uint32_t index,bool enabled){
    if(!r||!io||!io->transfer||client>=SONY_VOTE_CLIENTS||!r->address||(r->address&3)||index>15)return EINVAL;
    if(r->poisoned)return EIO;
    if(!r->initialized){int e=io->transfer(io->context,r->address,false,&r->boot);if(e)return e;
        if(r->boot>15)return EIO;r->applied=r->boot;r->initialized=true;}
    const uint32_t old=r->client[client];const bool old_enabled=r->enabled[client];
    r->client[client]=index;r->enabled[client]=enabled;uint32_t want=r->boot;
    for(unsigned i=0;i<SONY_VOTE_CLIENTS;i++)if(r->enabled[i]&&r->client[i]>want)want=r->client[i];
    if(want==r->applied)return 0;
    int e=io->transfer(io->context,r->address,true,&want);
    if(e){r->client[client]=old;r->enabled[client]=old_enabled;r->poisoned=true;return e;}
    r->applied=want;return 0;
}
