/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include "sony_radio069_host.h"
#include <stdarg.h>
// Include the unmodified actual source so a new test case can reset its static
// boot-lifetime state. Production never calls the reset routine below.
#include "SonyBoard2.c"
#ifdef SONY_RADIO069_OLD16_NEGATIVE
enum {SONY_BOARD=0,SONY_REGDB=1};
static int remember_key(unsigned kind,const char *name){return kind==SONY_BOARD?sony069_wifi_board_key(name):EINVAL;}
#else
static int remember_key(unsigned kind,const char *name){return sony069_wifi_board_key(kind,name);}
#endif
typedef uint8_t u8;
typedef uint32_t u32;
#define ALIGN(n,a) (((n)+(a)-1)&~((a)-1))
#define le32_to_cpu(n) (n)
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define ath12k_dbg(...) ((void)0)
#define ath12k_dbg_dump(...) ((void)0)
#define ath12k_err(...) ((void)0)
#define ath12k_warn(...) ((void)0)
#define ATH12K_DBG_BOOT 0
struct firmware {size_t size;const u8 *data;};
struct ath12k_board_data {const struct firmware *fw;const void *data;size_t len;};
struct ath12k_base {
    struct {unsigned bdf_search,vendor,device,subsystem_vendor,subsystem_device;} id;
    struct {struct {char bdf_ext[32];u32 chip_id,board_id;} target;} qmi;
    struct {int bus;} hif;
};
static int scnprintf(char *out,size_t size,const char *format,...) {
    va_list ap;va_start(ap,format);int n=vsnprintf(out,size,format,ap);va_end(ap);
    return n<0?0:(size_t)n>=size?(size?((int)size-1):0):n;
}
static const char *ath12k_bus_str(int bus){CHECK(bus==0);return "pci";}
static const char *ath12k_bd_ie_type_str(int id){return id?"regdb":"board";}
static unsigned releases;
static struct firmware supplied;
#ifndef SONY_RADIO069_OLD16_NEGATIVE
static bool fetch_from_provider, miss_primary;
static unsigned request_count, role_vectors;
#endif
static const struct firmware *ath12k_core_firmware_request(struct ath12k_base *ab,const char *name) {
    (void)ab;CHECK(!strcmp(name,"board-2.bin"));
#ifndef SONY_RADIO069_OLD16_NEGATIVE
    if(fetch_from_provider){
        CHECK(!sony069_wifi_board2(&supplied.data,&supplied.size));
        if(request_count++==0 && miss_primary){
            // Valid empty API2 container: the locked parser reports no match.
            static const uint8_t empty[20]="QCA-ATH12K-BOARD";
            supplied=(struct firmware){sizeof(empty),empty};
        }
    }
#endif
    return &supplied;
}
static void release_firmware(const struct firmware *fw){CHECK(fw==&supplied);releases++;}
static void ath12k_core_create_firmware_path(struct ath12k_base *ab,const char *name,char *out,size_t n) {
    (void)ab;snprintf(out,n,"ath12k/WCN7850/hw2.0/%s",name);
}
#include "ath12k-board-verbatim.inc"
#ifndef SONY_RADIO069_OLD16_NEGATIVE
// The host logging stub discards the production bd_api diagnostic.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-but-set-variable"
#include "ath12k-api2-callsites.inc"
#pragma clang diagnostic pop
#endif
static unsigned raw_reads;
static int raw_error;
static const char *raw_error_name;
static int raw_elf_tamper,raw_wrong_size;
int sony069_wifi_read_raw(const char *name,uint8_t **data,size_t *size) {
    raw_reads++;*data=NULL;*size=0;
    if(raw_error && (!raw_error_name || !strcmp(name,raw_error_name)))return raw_error;
    struct host_fixture *f=host_find(name);CHECK(f && f->wifi);
    size_t n=f->bytes;if(raw_wrong_size && !strcmp(name,"sony-board.elf"))n--;
    uint8_t *p=IOMallocData(n);if(!p)return ENOMEM;
    memcpy(p,f->data,n);if(raw_elf_tamper && !strcmp(name,"sony-board.elf"))p[0]=0;
    *data=p;*size=n;return 0;
}
static void reset_board(void) {
#ifdef SONY_RADIO069_OLD16_NEGATIVE
    if(blob)IOFreeData(blob,blob_bytes);
    blob=NULL;blob_bytes=0;chip=board=soc=identity_valid=0;memset(key,0,sizeof(key));
#else
    for(unsigned i=0;i<2;i++)if(blobs[i])IOFreeData(blobs[i],blob_sizes[i]);
    memset(blobs,0,sizeof(blobs));memset(blob_sizes,0,sizeof(blob_sizes));
    memset(keys,0,sizeof(keys));memset(key_counts,0,sizeof(key_counts));selected_kind=0;
    chip=board=soc=identity_valid=0;
#endif
    host_reset();raw_reads=0;raw_error=raw_elf_tamper=raw_wrong_size=0;raw_error_name=NULL;releases=0;
}
static struct ath12k_base base(unsigned search,const char *variant) {
    struct ath12k_base ab={0};ab.id.bdf_search=search;ab.id.vendor=0x17cb;ab.id.device=0x1107;
    ab.id.subsystem_vendor=0x104d;ab.id.subsystem_device=0x0601;
    ab.qmi.target.chip_id=2;ab.qmi.target.board_id=0xe31;
    snprintf(ab.qmi.target.bdf_ext,sizeof(ab.qmi.target.bdf_ext),"%s",variant);return ab;
}
static int parse(struct ath12k_base *ab,const uint8_t *data,size_t length,const char *name,bool reg,const void **out,size_t *bytes) {
    supplied=(struct firmware){length,data};struct ath12k_board_data bd={0};
    int e=ath12k_core_fetch_board_data_api_n(ab,&bd,name,reg?ATH12K_BD_IE_REGDB:ATH12K_BD_IE_BOARD,0,1);
    if(!e){*out=bd.data;*bytes=bd.len;}else CHECK(!bd.fw && !bd.data && !bd.len);
    return e;
}
static void identity_test(void) {
    reset_board();const uint8_t *data=(void *)1;size_t n=1;
    CHECK(sony069_wifi_board2(NULL,&n)==EINVAL && sony069_wifi_board2(&data,NULL)==EINVAL);
    CHECK(sony069_wifi_board2(&data,&n)==EAGAIN && !data && !n && !raw_reads);
    CHECK(remember_key(SONY_BOARD,"bus=pci,qmi-chip-id=2,qmi-board-id=3633")==EAGAIN);
    CHECK(sony069_wifi_qmi_identity(UINT32_MAX,1,1)==EINVAL);
    CHECK(sony069_wifi_qmi_identity(1,UINT32_MAX,1)==EINVAL);
    CHECK(sony069_wifi_qmi_identity(1,1,0)==EINVAL);
    CHECK(sony069_wifi_qmi_identity(1,1,UINT32_MAX)==EINVAL);
    CHECK(!sony069_wifi_qmi_identity(2,0xe31,0x12345678));
    CHECK(!sony069_wifi_qmi_identity(2,0xe31,0x12345678));
    CHECK(sony069_wifi_qmi_identity(3,0xe31,0x12345678)==EBUSY);
    CHECK(sony069_wifi_board2(&data,&n)==EAGAIN && !raw_reads);
    CHECK(remember_key(2,"bus=pci,x")==EINVAL);
    CHECK(remember_key(SONY_BOARD,NULL)==EINVAL && remember_key(SONY_BOARD,"bus=ahb,x")==EINVAL);
    char long_name[250];memset(long_name,'x',sizeof(long_name));memcpy(long_name,"bus=pci,",8);long_name[249]=0;
    CHECK(remember_key(SONY_BOARD,long_name)==EINVAL);
}
static void roundtrip(unsigned search,const char *variant) {
    reset_board();struct ath12k_base ab=base(search,variant);char requested[200],fallback[200],busname[200];
    CHECK(!__ath12k_core_create_board_name(&ab,requested,sizeof(requested),true,false,false));
    CHECK(strstr(requested,"qmi-chip-id=2") && strstr(requested,"qmi-board-id=3633"));
    if(search==ATH12K_BDF_SEARCH_BUS_AND_BOARD)CHECK(strstr(requested,"vendor=17cb,device=1107,subsystem-vendor=104d,subsystem-device=0601"));
    if(variant[0])CHECK(strstr(requested,",variant=sony-test"));
    CHECK(!ath12k_core_create_fallback_board_name(&ab,fallback,sizeof(fallback)));
    CHECK(!ath12k_core_create_bus_type_board_name(&ab,busname,sizeof(busname)));
    CHECK(!sony069_wifi_qmi_identity(2,0xe31,0x12345678));
#ifdef SONY_RADIO069_OLD16_NEGATIVE
    CHECK(!remember_key(SONY_BOARD,requested));
#else
    CHECK(!remember_key(SONY_BOARD,requested));CHECK(!remember_key(SONY_BOARD,fallback));
    CHECK(!remember_key(SONY_REGDB,requested));CHECK(!remember_key(SONY_REGDB,busname));
    CHECK(!remember_key(SONY_BOARD,requested));
#endif
    const uint8_t *data=NULL;size_t n=0;CHECK(!sony069_wifi_board2(&data,&n));
#ifdef SONY_RADIO069_OLD16_NEGATIVE
    const void *old_payload=NULL;size_t old_bytes=0;
    CHECK(parse(&ab,data,n,requested,false,&old_payload,&old_bytes)!=0);
    CHECK(parse(&ab,data,n,requested,true,&old_payload,&old_bytes)!=0);
    CHECK(raw_reads==2 && host_live_allocations==1);
#else
    CHECK(sizeof(ATH12K_BOARD_MAGIC)==17 && !memcmp(data,ATH12K_BOARD_MAGIC,17));
    CHECK(data[17]==0 && data[18]==0 && data[19]==0);
    CHECK(raw_reads==2 && host_live_allocations==1);
    const uint8_t *again=NULL;size_t again_n=0;CHECK(!sony069_wifi_board2(&again,&again_n) && again==data && again_n==n && raw_reads==2);
    const void *payload=NULL;size_t bytes=0;struct host_fixture *f=host_find("sony-board.elf");
    for(const char *candidate[2]={requested,fallback},**at=candidate;at<candidate+2;at++){
        CHECK(!parse(&ab,data,n,*at,false,&payload,&bytes));
        CHECK(bytes==f->bytes && !memcmp(payload,f->data,bytes));
        CHECK((const uint8_t *)payload>=data+20 && (const uint8_t *)payload+bytes<=data+n);
    }
    CHECK(parse(&ab,data,n,"bus=pci,qmi-chip-id=999,qmi-board-id=3633",false,&payload,&bytes)==-ENODATA);
    char changed[200];snprintf(changed,sizeof(changed),"%s",requested);changed[strlen(changed)-1]^=1;
    CHECK(parse(&ab,data,n,changed,false,&payload,&bytes)==-ENODATA);
    CHECK(!remember_key(SONY_REGDB,requested));CHECK(!sony069_wifi_board2(&data,&n));f=host_find("sony-regdb.bin");
    CHECK(raw_reads==4 && host_live_allocations==2);
    const char *regkeys[2]={requested,busname};
    for(unsigned i=0;i<2;i++){
        CHECK(!parse(&ab,data,n,regkeys[i],true,&payload,&bytes));
        CHECK(bytes==f->bytes && !memcmp(payload,f->data,bytes));
    }
    CHECK(parse(&ab,data,n,changed,true,&payload,&bytes)==-ENODATA);
    // Per-key blobs cannot be silently rebuilt after the firmware reader returns one.
    CHECK(sony069_wifi_board_key(SONY_BOARD,"bus=pci,later") == EBUSY);
    // Exact old bug: only the visible16bytes preceded the first IE. Its first
    // id0 byte happens to satisfy the NUL comparison but offset20 loses the IE.
    data=blobs[SONY_BOARD];n=blob_sizes[SONY_BOARD];
    uint8_t *old=malloc(n-4);CHECK(old);memcpy(old,data,16);memcpy(old+16,data+20,n-20);
    const void *out=NULL;bytes=0;
    CHECK(parse(&ab,old,n-4,requested,false,&out,&bytes)!=0);
    CHECK(parse(&ab,old,n-4,requested,true,&out,&bytes)!=0);free(old);
    uint8_t *bad=malloc(n);CHECK(bad);memcpy(bad,data,n);bad[16]=1;
    CHECK(parse(&ab,bad,n,requested,false,&out,&bytes)==-EINVAL);
    memcpy(bad,data,n);memset(bad+24,0xff,4);CHECK(parse(&ab,bad,n,requested,false,&out,&bytes)==-EINVAL);
    memcpy(bad,data,n);memset(bad+32,0xff,4);CHECK(parse(&ab,bad,n,requested,false,&out,&bytes)==-EINVAL);
    CHECK(parse(&ab,data,16,requested,false,&out,&bytes)==-EINVAL);
    CHECK(parse(&ab,data,19,requested,false,&out,&bytes)==-EINVAL);
    free(bad);
#endif
}
#ifndef SONY_RADIO069_OLD16_NEGATIVE
static void fetch_vector(unsigned search,const char *variant,unsigned role,bool fallback){
    reset_board();struct ath12k_base ab=base(search,variant);struct ath12k_board_data bd={0};
    char primary[BOARD_NAME_SIZE],secondary[BOARD_NAME_SIZE];
    CHECK(!ath12k_core_create_board_name(&ab,primary,sizeof(primary)));
    CHECK(!(role==SONY_BOARD?ath12k_core_create_fallback_board_name(&ab,secondary,sizeof(secondary)):
          ath12k_core_create_bus_type_board_name(&ab,secondary,sizeof(secondary))));
    CHECK(!sony069_wifi_qmi_identity(2,0xe31,0x12345678));
    request_count=0;fetch_from_provider=true;miss_primary=fallback;
    CHECK(!(role==SONY_BOARD?ath12k_core_fetch_bdf(&ab,&bd):ath12k_core_fetch_regdb(&ab,&bd)));
    fetch_from_provider=false;
    struct host_fixture *f=host_find(role==SONY_BOARD?"sony-board.elf":"sony-regdb.bin");
    CHECK(bd.len==f->bytes && !memcmp(bd.data,f->data,bd.len));
    CHECK(request_count==(fallback?2u:1u) && releases==(fallback?1u:0u));
    CHECK(key_counts[1-role]==0 && key_counts[role]==(strcmp(primary,secondary)?2u:1u));
    CHECK(!strcmp(keys[role][0],primary));
    if(key_counts[role]==2)CHECK(!strcmp(keys[role][1],secondary));
    ath12k_core_free_bdf(&ab,&bd);
    ++role_vectors;
    printf("{\"role\":\"%s\",\"search\":%u,\"variant\":\"%s\",\"primary\":\"%s\",\"fallback\":\"%s\",\"used_fallback\":%s,\"requests\":%u}\n",
           role==SONY_BOARD?"board":"regdb",search,variant,primary,secondary,fallback?"true":"false",request_count);
}
#endif
static void failure_test(void) {
    for(unsigned fault=0;fault<7;fault++) {
        reset_board();CHECK(!sony069_wifi_qmi_identity(2,0xe31,1));
        CHECK(!remember_key(SONY_BOARD,"bus=pci,qmi-chip-id=2,qmi-board-id=3633"));
        int expected=0;
        switch(fault) {
        case 0:raw_error=EAGAIN;expected=EAGAIN;break;
        case 1:raw_error=EIO;raw_error_name="sony-regdb.bin";expected=EIO;break;
        case 2:host_fault.fail_allocation=1;expected=ENOMEM;break;
        case 3:host_fault.fail_allocation=2;expected=ENOMEM;break;
        case 4:host_fault.fail_allocation=3;expected=ENOMEM;break;
        case 5:raw_elf_tamper=1;expected=EINVAL;break;
        case 6:raw_wrong_size=1;expected=EINVAL;break;
        }
        const uint8_t *data=(void *)1;size_t bytes=1;
        CHECK(sony069_wifi_board2(&data,&bytes)==expected && !data && !bytes && !host_live_allocations);
        raw_error=raw_elf_tamper=raw_wrong_size=0;host_fault.fail_allocation=0;
        CHECK(!sony069_wifi_board2(&data,&bytes) && data && bytes && host_live_allocations==1);
    }
}
int main(void) {
    host_init();identity_test();
    roundtrip(0,"");roundtrip(0,"sony-test");roundtrip(ATH12K_BDF_SEARCH_BUS_AND_BOARD,"");roundtrip(ATH12K_BDF_SEARCH_BUS_AND_BOARD,"sony-test");
    failure_test();
#ifndef SONY_RADIO069_OLD16_NEGATIVE
    for(unsigned i=0;i<16;i++)fetch_vector((i&8)?ATH12K_BDF_SEARCH_BUS_AND_BOARD:0,
        (i&4)?"sony-test":"",(i>>1)&1u,(i&1)!=0);
#endif
    reset_board();host_fini();
#ifdef SONY_RADIO069_OLD16_NEGATIVE
    puts("{\"passed\":true,\"old16_magic_rejected\":true,\"fault_cleanup_cases\":7}");
#else
    printf("{\"passed\":true,\"role_vectors\":%u,\"roundtrips\":4,\"fault_cleanup_cases\":7,\"old16_magic_rejected\":true,\"raw_bytes_preserved\":true}\n",role_vectors);
#endif
}
