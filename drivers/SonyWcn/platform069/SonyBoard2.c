/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <sys/errno.h>
#include <sys/systm.h>
#include <IOKit/IOLib.h>
#include "SonyBoard2.h"
extern int sony069_wifi_read_raw(const char *,uint8_t **,size_t *);
static uint32_t chip,board,soc;
static unsigned identity_valid;
enum {SONY_BOARD=0,SONY_REGDB=1};
static char keys[2][2][200];
static unsigned key_counts[2];
static unsigned selected_kind;
static uint8_t *blobs[2];static size_t blob_sizes[2];
static void le32(uint8_t *p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(i*8));}
static size_t aligned(size_t size){return (size+3)&~(size_t)3;}
static uint8_t *element(uint8_t *at,uint32_t id,const void *data,size_t size){
    le32(at,id);le32(at+4,(uint32_t)size);memcpy(at+8,data,size);memset(at+8+size,0,aligned(size)-size);return at+8+aligned(size);
}
int sony069_wifi_qmi_identity(uint32_t c,uint32_t b,uint32_t s){
    /* WCN7850 hw2.0 query supplies its chip/board/soc IDs. All32bit values are
     * preserved in exact decimal board keys. Reject missing/all-ones replies. */
    if(c==UINT32_MAX || b==UINT32_MAX || !s || s==UINT32_MAX)return EINVAL;
    if(__atomic_load_n(&identity_valid,__ATOMIC_ACQUIRE))return chip==c && board==b && soc==s?0:EBUSY;
    chip=c;board=b;soc=s;__atomic_store_n(&identity_valid,1,__ATOMIC_RELEASE);
    IOLog("[sony069-wifi-qmi] chip=%u board=%u soc=%x\n",chip,board,soc);return 0;
}
int sony069_wifi_board_key(unsigned kind,const char *name){
    if(!__atomic_load_n(&identity_valid,__ATOMIC_ACQUIRE))return EAGAIN;
    if(kind>SONY_REGDB)return EINVAL;
    if(!name)return EINVAL;
    size_t bytes=strnlen(name,sizeof(keys[kind][0]));
    if(bytes>=sizeof(keys[kind][0]))return EINVAL;
    if((bytes<8 || strncmp(name,"bus=pci,",8)) &&
       !(kind==SONY_REGDB && !strcmp(name,"bus=pci")))return EINVAL;
    for(unsigned i=0;i<key_counts[kind];++i)if(!strcmp(name,keys[kind][i])){selected_kind=kind;return 0;}
    if(blobs[kind])return EBUSY;
    if(key_counts[kind]>=2)return ENOSPC;
    memcpy(keys[kind][key_counts[kind]++],name,bytes+1);selected_kind=kind;return 0;
}
int sony069_wifi_board2(const uint8_t **data,size_t *length){
    if(!data || !length)return EINVAL;*data=NULL;*length=0;
    if(!__atomic_load_n(&identity_valid,__ATOMIC_ACQUIRE) || !key_counts[selected_kind])return EAGAIN;
    if(blobs[selected_kind]){*data=blobs[selected_kind];*length=blob_sizes[selected_kind];return 0;}
    uint8_t *bdf=NULL,*reg=NULL;size_t bdf_size=0,reg_size=0;
    int e=sony069_wifi_read_raw("sony-board.elf",&bdf,&bdf_size);
    if(!e)e=sony069_wifi_read_raw("sony-regdb.bin",&reg,&reg_size);
    if(e)goto done;
    if(bdf_size!=88760 || bdf_size<52 || memcmp(bdf,"\177ELF\1\1",6) || reg_size!=24278){e=EINVAL;goto done;}
    size_t inner_board=0,inner_reg=0;
    for(unsigned i=0;i<key_counts[SONY_BOARD];++i)inner_board+=8+aligned(strlen(keys[SONY_BOARD][i]))+8+aligned(bdf_size);
    for(unsigned i=0;i<key_counts[SONY_REGDB];++i)inner_reg+=8+aligned(strlen(keys[SONY_REGDB][i]))+8+aligned(reg_size);
    // ATH12K_BOARD_MAGIC has16 visible bytes plus NUL, padded to20.
    const size_t magic_bytes=aligned(sizeof("QCA-ATH12K-BOARD"));
    const size_t payload=selected_kind==SONY_BOARD?inner_board:inner_reg;
    if(!payload||payload>UINT32_MAX){e=EINVAL;goto done;}
    blob_sizes[selected_kind]=magic_bytes+8+aligned(payload);
    blobs[selected_kind]=IOMallocData(blob_sizes[selected_kind]);if(!blobs[selected_kind]){e=ENOMEM;goto done;}
    memset(blobs[selected_kind],0,blob_sizes[selected_kind]);memcpy(blobs[selected_kind],"QCA-ATH12K-BOARD",sizeof("QCA-ATH12K-BOARD"));
    uint8_t *at=blobs[selected_kind]+magic_bytes;
    if(selected_kind==SONY_BOARD){
        le32(at,0);le32(at+4,(uint32_t)inner_board);
        at+=8;
        for(unsigned i=0;i<key_counts[SONY_BOARD];++i){
            uint8_t *nested=element(at,0,keys[SONY_BOARD][i],strlen(keys[SONY_BOARD][i]));
            at=element(nested,1,bdf,bdf_size);
        }
    }else{
        le32(at,1);le32(at+4,(uint32_t)inner_reg);
        at+=8;
        for(unsigned i=0;i<key_counts[SONY_REGDB];++i){
            uint8_t *nested=element(at,0,keys[SONY_REGDB][i],strlen(keys[SONY_REGDB][i]));
            at=element(nested,1,reg,reg_size);
        }
    }
    *data=blobs[selected_kind];*length=blob_sizes[selected_kind];
    IOLog("[sony069-wifi-board2] role=%u keys=%u ELF=%zu regdb=%zu bytes=%zu\n",
        selected_kind,key_counts[selected_kind],bdf_size,reg_size,blob_sizes[selected_kind]);
done:
    if(bdf)IOFreeData(bdf,bdf_size);if(reg)IOFreeData(reg,reg_size);return e;
}
