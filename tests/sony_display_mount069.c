/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef void *proc_t;
typedef uintptr_t user_addr_t;
typedef const char *vnode_t;
#define NULLVP NULL
#define VREG 1
#define MNT_NOFOLLOW 1
struct unmount_args { user_addr_t path; int flags; };
static int native_gpu_addon_files=71, native_gpu_addon_failed, native_gpu_addon_error;
static int enabled=1, control=1, mounts, rollbacks, lib_stage_result=5, bin_stage_result=5;
static int lib_error, bin_error, rollback_error, vnodes;
static const char *missing, *rollback_path;
static int hide_wifi, hide_backboard;

static int PE_parse_boot_argn(const char *name, uint32_t *value, size_t size) {
    assert(size==sizeof(*value));
    *value=!strcmp(name,"backlight")?enabled:control;
    return 1;
}
static int vfs_context_current(void) {return 0;}
static int vnode_lookup(const char *path, int flags, vnode_t *vp, int context) {
    assert(!flags && !context);
    if ((missing && !strcmp(path,missing)) ||
        (mounts==2 && hide_wifi && !strcmp(path,"/usr/libexec/unixnu-wpa_supplicant")) ||
        (mounts==2 && hide_backboard && !strcmp(path,"/usr/libexec/backboardd"))) return ENOENT;
    *vp=path;++vnodes;return 0;
}
static int vnode_vtype(vnode_t vp){assert(vp);return VREG;}
static void vnode_put(vnode_t vp){assert(vp && vnodes>0);--vnodes;}
static int copyout(const char *path, user_addr_t destination, size_t size){
    assert(destination==0x1620 && strlen(path)+1==size);rollback_path=path;return 0;
}
static int unmount(proc_t p, struct unmount_args *request, int32_t *result){
    assert(!p && request->flags==MNT_NOFOLLOW && !*result);++rollbacks;return rollback_error;
}
static void native_gpu_addon_mount(proc_t p, user_addr_t scratch, user_addr_t offset,
    const char *source, size_t source_size, const char *point, size_t point_size,
    const char *visible, const char *own, volatile int *stage, volatile int *status) {
    assert(!p && scratch==0x1000 && offset==0x600 && strlen(source)+1==source_size && strlen(point)+1==point_size);
    if (++mounts==1) {
        assert(!strcmp(source,"/private/var/ngpu/display-lib") && !strcmp(point,"/usr/lib"));
        assert(!strcmp(visible,"/usr/lib/dyld") && !strcmp(own,"/usr/lib/UniXNUBacklight.dylib"));
        *stage=lib_stage_result;*status=lib_error;
    } else {
        assert(mounts==2 && lib_stage_result==5 && !lib_error);
        assert(!strcmp(source,"/private/var/ngpu/display-bin") && !strcmp(point,"/usr/libexec"));
        assert(!strcmp(visible,"/usr/libexec/launchd_cache_loader") && !strcmp(own,"/usr/libexec/SonyBacklight069.runtime"));
        *stage=bin_stage_result;*status=bin_error;
    }
}
#include "display_mount_actual.inc"

int main(int argc,char **argv){
    assert(argc==2);const char *name=argv[1], *undo=NULL;
    int count=0;
    if(!strcmp(name,"success")) count=2;
    else if(!strcmp(name,"disabled")) enabled=0;
    else if(!strcmp(name,"control-off")) control=0;
    else if(!strcmp(name,"no-addon")) native_gpu_addon_files=-1;
    else if(!strcmp(name,"incomplete-addon")) native_gpu_addon_failed=1;
    else if(!strcmp(name,"missing-daemon")) missing="/private/var/ngpu/display-bin/backboardd";
    else if(!strcmp(name,"missing-marker")) missing="/private/var/ngpu/display-bin/SonyBacklight069.runtime";
    else if(!strcmp(name,"library-eagain")){count=1;lib_stage_result=2;lib_error=EAGAIN;}
    else if(!strcmp(name,"library-hidden")){count=1;lib_stage_result=4;lib_error=ENOENT;undo="/usr/lib";}
    else if(!strcmp(name,"exec-eagain")){count=2;bin_stage_result=2;bin_error=EAGAIN;}
    else if(!strcmp(name,"exec-hidden")){count=2;bin_stage_result=4;bin_error=ENOENT;undo="/usr/libexec";}
    else if(!strcmp(name,"wifi-hidden")){count=2;hide_wifi=1;undo="/usr/libexec";}
    else if(!strcmp(name,"backboard-hidden")){count=2;hide_backboard=1;undo="/usr/libexec";}
    else if(!strcmp(name,"rollback-denied")){count=2;hide_wifi=1;rollback_error=EPERM;undo="/usr/libexec";}
    else assert(0);
    native_display069_runtime(NULL,0x1000,1);
    assert(mounts==count && rollbacks==(undo!=NULL) && !vnodes);
    if(undo)assert(rollback_path && !strcmp(undo,rollback_path));
    return 0;
}
