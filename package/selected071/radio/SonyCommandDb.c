/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include "SonyCommandDb.h"
#ifdef KERNEL
#include <sys/errno.h>
#else
#include <errno.h>
#endif
#include <string.h>
static uint16_t u16(const uint8_t *p){return (uint16_t)p[0]|(uint16_t)p[1]<<8;}
static uint32_t u32(const uint8_t *p){return (uint32_t)u16(p)|(uint32_t)u16(p+2)<<16;}
static int fits(size_t at,size_t n,size_t size){return at<=size&&n<=size-at;}
int sony_cmd_db_find(const uint8_t *db,size_t bytes,const char *name,unsigned wanted,struct sony_cmd_resource *out){
    if(!db||!name||!out||!name[0]||strlen(name)>8||!wanted)return EINVAL;
    if(bytes<144||u32(db+4)!=0x0c0330dbu)return EINVAL;
    uint8_t key[8]={0};memcpy(key,name,strlen(name));struct sony_cmd_resource found={0};
    for(unsigned i=0;i<8;i++){
        const uint8_t *s=db+8+16*i;unsigned slave=u16(s);if(!slave)break;
        size_t heads=144u+u16(s+2),aux=144u+u16(s+4),count=u16(s+6);
        if(!fits(heads,count*24u,bytes)||!fits(aux,0,bytes))return EINVAL;
        for(size_t j=0;j<count;j++){
            const uint8_t *e=db+heads+j*24;if(memcmp(e,key,8))continue;
            size_t length=u16(e+20),at=aux+u16(e+22);uint32_t address=u32(e+16);
            if(found.address)return EEXIST;
            if(slave!=wanted||!address||(address&3)||((address>>16)&7)!=slave||!fits(at,length,bytes))return EINVAL;
            for(unsigned k=0;k<8;k++){
                const uint8_t *other=db+8+k*16;if(!u16(other))break;
                size_t begin=144u+u16(other+2),n=(size_t)u16(other+6)*24;
                if(!fits(begin,n,bytes)||(length&&n&&at<begin+n&&begin<at+length))return EINVAL;
            }
            found=(struct sony_cmd_resource){address,db+at,length,slave};
        }
    }
    if(!found.address)return ENOENT;*out=found;return 0;
}
int sony_cmd_arc_index(const struct sony_cmd_resource *r,uint32_t corner,uint32_t *index){
    if(!r||!index||r->slave!=3||!r->aux||!r->aux_bytes||r->aux_bytes>32||(r->aux_bytes&1))return EINVAL;
    uint32_t previous=0,selected=UINT32_MAX;int padding=0;
    for(size_t i=0;i<r->aux_bytes/2;i++){
        uint32_t value=u16(r->aux+i*2);
        if(i&&!value){padding=1;continue;}
        if(padding||value<previous)return EINVAL;
        if(selected==UINT32_MAX&&value>=corner)selected=(uint32_t)i;previous=value;
    }
    if(selected==UINT32_MAX)return ERANGE;*index=selected;return 0;
}
int sony_cmd_bcm_aux(const struct sony_cmd_resource *r,uint32_t *unit,uint32_t *width,uint32_t *vcd){
    if(!r||!unit||!width||!vcd||r->slave!=5||!r->aux||r->aux_bytes!=8||r->aux[7])return EINVAL;
    uint32_t u=u32(r->aux),w=u16(r->aux+4);if(!u||!w)return EINVAL;
    *unit=u;*width=w;*vcd=r->aux[6];return 0;
}
