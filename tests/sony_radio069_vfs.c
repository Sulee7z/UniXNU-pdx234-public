/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include "sony_radio069_host.h"
#include "WifiFirmware.h"
#include "BluetoothFirmware.h"
#include <stdarg.h>
#include "fixtures.inc"
const size_t host_file_count=sizeof(host_files)/sizeof(host_files[0]);
struct host_faults host_fault;
unsigned host_opens,host_closes,host_reads,host_allocations,host_live_allocations;
volatile int native_gpu_addon_stage=1;
static unsigned handles;
static struct { void *pointer; size_t bytes; } allocations[64];

void host_reset(void) {
    CHECK(!host_live_allocations && !handles);
    memset(&host_fault,0,sizeof(host_fault));
    host_fault.attr_size=-1;host_fault.vtype=VREG;
    host_opens=host_closes=host_reads=host_allocations=0;
    native_gpu_addon_stage=1;
}
void host_init(void) {
    for(size_t i=0;i<host_file_count;i++) {
        struct host_fixture *f=&host_files[i];
        FILE *in=fopen(f->path,"rb");CHECK(in);
        f->data=malloc(f->bytes);CHECK(f->data);
        CHECK(fread(f->data,1,f->bytes,in)==f->bytes);
        CHECK(fgetc(in)==EOF);CHECK(!fclose(in));
    }
    host_reset();
}
void host_fini(void) {
    host_reset();
    for(size_t i=0;i<host_file_count;i++){free(host_files[i].data);host_files[i].data=NULL;}
}
struct host_fixture *host_find(const char *name) {
    for(size_t i=0;i<host_file_count;i++)if(!strcmp(name,host_files[i].name))return &host_files[i];
    return NULL;
}
void *IOMallocData(size_t bytes) {
    host_allocations++;
    if(host_fault.fail_allocation==host_allocations)return NULL;
    CHECK(bytes>0);
    for(size_t i=0;i<64;i++)if(!allocations[i].pointer) {
        void *p=malloc(bytes);CHECK(p);
        allocations[i].pointer=p;allocations[i].bytes=bytes;host_live_allocations++;
        return p;
    }
    CHECK(false);return NULL;
}
void IOFreeData(void *p,size_t bytes) {
    CHECK(p);
    for(size_t i=0;i<64;i++)if(allocations[i].pointer==p) {
        CHECK(allocations[i].bytes==bytes);
        free(p);allocations[i].pointer=NULL;host_live_allocations--;return;
    }
    CHECK(false);
}
int IOLog(const char *format,...) { (void)format; return 0; }
vfs_context_t vfs_context_kernel(void){return (void *)1;}
void *vfs_context_ucred(vfs_context_t c){CHECK(c==(void *)1);return (void *)2;}
void *vfs_context_proc(vfs_context_t c){CHECK(c==(void *)1);return (void *)3;}
int vnode_open(const char *path,int flags,int mode,int options,vnode_t *vp,vfs_context_t c) {
    CHECK(flags==FREAD && !mode && !options && c==(void *)1);
    host_opens++;*vp=NULL;if(host_fault.open_error)return host_fault.open_error;
    for(size_t i=0;i<host_file_count;i++) {
        struct host_fixture *f=&host_files[i];char expected[256];
        snprintf(expected,sizeof(expected),"%s/%s",f->wifi?SHENG_WIFI_FIRMWARE_ROOT:SHENG_BT_FIRMWARE_ROOT,f->wifi?f->name:f->name+4);
        if(strcmp(path,expected))continue;
        if(host_fault.missing && !strcmp(host_fault.missing,f->name))return ENOENT;
        CHECK(!handles);handles++;*vp=f;return 0;
    }
    return ENOENT;
}
int vnode_getattr(vnode_t f,struct vnode_attr *va,vfs_context_t c) {
    CHECK(handles==1 && f && c==(void *)1);
    if(host_fault.getattr_error)return host_fault.getattr_error;
    va->va_data_size=host_fault.attr_size<0?f->bytes:(uint64_t)host_fault.attr_size;return 0;
}
int vnode_vtype(vnode_t f){CHECK(f && handles==1);return host_fault.vtype;}
int vnode_close(vnode_t f,int flags,vfs_context_t c) {
    CHECK(f && handles==1 && flags==FREAD && c==(void *)1);
    handles--;host_closes++;return 0;
}
int vn_rdwr(int op,vnode_t f,caddr_t out,int length,off_t offset,int segment,int flags,void *cred,int *resid,void *proc) {
    CHECK(op==UIO_READ && f && handles==1 && length>0 && !offset && segment==UIO_SYSSPACE && flags==IO_NOAUTH);
    CHECK(cred==(void *)2 && proc==(void *)3);
    host_reads++;
    size_t n=(size_t)length<f->bytes?(size_t)length:f->bytes;
    memset(out,0,(size_t)length);memcpy(out,f->data,n);
    if(host_fault.tamper && n)out[n/2]^=0x40;
    *resid=host_fault.resid?host_fault.resid:length-(int)n;
    return host_fault.read_error;
}
