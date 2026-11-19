/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef SONY_RADIO069_HOST_H
#define SONY_RADIO069_HOST_H
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#ifndef EAUTH
#define EAUTH 80
#endif
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %s:%d: %s\n",__FILE__,__LINE__,#x); abort(); } } while (0)
#ifdef __cplusplus
extern "C" {
#endif
struct host_fixture { const char *name,*path; size_t bytes; int wifi; uint8_t *data; };
extern struct host_fixture host_files[];
extern const size_t host_file_count;
struct host_faults {
    int open_error,getattr_error,read_error,resid,tamper,vtype;
    int64_t attr_size;
    unsigned fail_allocation;
    const char *missing;
};
extern struct host_faults host_fault;
extern unsigned host_opens,host_closes,host_reads,host_allocations,host_live_allocations;
extern volatile int native_gpu_addon_stage;
void host_init(void);
void host_fini(void);
void host_reset(void);
struct host_fixture *host_find(const char *);
void *IOMallocData(size_t);
void IOFreeData(void *,size_t);
int IOLog(const char *,...);
typedef void *vfs_context_t;
typedef struct host_fixture *vnode_t;
struct vnode_attr { uint64_t va_data_size; };
#define VATTR_INIT(p) memset((p),0,sizeof(*(p)))
#define VATTR_WANTED(p,f) ((void)(p))
#define FREAD 1
#define VREG 1
#define UIO_READ 0
#define UIO_SYSSPACE 0
#define IO_NOAUTH 0
vfs_context_t vfs_context_kernel(void);
void *vfs_context_ucred(vfs_context_t);
void *vfs_context_proc(vfs_context_t);
int vnode_open(const char *,int,int,int,vnode_t *,vfs_context_t);
int vnode_getattr(vnode_t,struct vnode_attr *,vfs_context_t);
int vnode_vtype(vnode_t);
int vnode_close(vnode_t,int,vfs_context_t);
int vn_rdwr(int,vnode_t,caddr_t,int,off_t,int,int,void *,int *,void *);
int sony_wcn_wifi_inputs_ready(void);
int sony_wcn_bluetooth_inputs_ready(void);
int sony069_wifi_verify_firmware(const char *,const uint8_t *,size_t);
int sony069_bt_verify_firmware(const char *,const uint8_t *,size_t);
#ifdef __cplusplus
}
#endif
#endif
