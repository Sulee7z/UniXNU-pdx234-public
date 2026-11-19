"""Bounded shutdown/parent context at the already-invalid release boundary."""


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Unexpected VFS diagnostic source anchor')
    return text.replace(old, new, 1)


def adapt_shutdown(text):
    if 'pdx_shutdown_pid' in text:
        raise ValueError('Shutdown diagnostic already applied')
    text = replace_once(text, 'uint32_t system_inshutdown = 0;', '''/* Diagnostic snapshot of the request that wins shutdown ownership. */
int pdx_shutdown_pid = -1;
int pdx_shutdown_howto;
char pdx_shutdown_comm[32];
uint64_t pdx_shutdown_time;
uint32_t system_inshutdown = 0;''')
    return replace_once(text, '\tlck_mtx_lock(&vm_swap_data_lock);\n\n\t/* Turn OFF future swapfile reclaimation / compaction etc.*/', '''\tpdx_shutdown_pid = proc_selfpid();
\tpdx_shutdown_howto = howto;
\tproc_selfname(pdx_shutdown_comm, sizeof(pdx_shutdown_comm));
\tpdx_shutdown_time = mach_absolute_time();
\tprintf("PDX reboot pid=%d comm=%s howto=0x%x abstime=0x%llx\\n",
\t    pdx_shutdown_pid, pdx_shutdown_comm, pdx_shutdown_howto, pdx_shutdown_time);

\tlck_mtx_lock(&vm_swap_data_lock);

\t/* Turn OFF future swapfile reclaimation / compaction etc.*/''')


def adapt_cache(text):
    if 'pdx_identity_child' in text:
        raise ValueError('Parent diagnostic already applied')
    text = replace_once(text, '#include <sys/paths.h>', '''#include <sys/paths.h>
#include <sys/proc.h>
extern int pdx_shutdown_pid;
extern int pdx_shutdown_howto;
extern char pdx_shutdown_comm[32];
extern uint64_t pdx_shutdown_time;''')
    text = replace_once(text, '\tvnode_t old_parentvp = NULLVP;', '''\tvnode_t old_parentvp = NULLVP;
\tvnode_t pdx_identity_child = vp;
\tunsigned pdx_child_id = vp->v_id, pdx_child_type = vp->v_type, pdx_child_tag = vp->v_tag;
\tvnode_t pdx_child_parent = vp->v_parent;
\tchar pdx_fs[16] = "none", pdx_mount[64] = "none";
\t/* Copy mount identity while this operation still owns its child vnode. */
\tif (vp->v_mount) {
\t\tstrlcpy(pdx_fs, vp->v_mount->mnt_vfsstat.f_fstypename, sizeof(pdx_fs));
\t\tstrlcpy(pdx_mount, vp->v_mount->mnt_vfsstat.f_mntonname, sizeof(pdx_mount));
\t}''')
    return replace_once(text, '\t\t\tvnode_rele_internal(vp, 0, 0, 1);', '''\t\t\t/* An invalid parent release is already fatal. Preserve its context
\t\t\t * before the generic decrement/panic loses the child and mount. */
\t\t\tif (os_atomic_load(&vp->v_usecount, relaxed) < 1) {
\t\t\t\tchar comm[32];
\t\t\t\tproc_selfname(comm, sizeof(comm));
\t\t\t\tpanic("PDX parent-underflow before release\\n"
\t\t\t\t    "reboot pid=%d comm=%.31s how=0x%x at=0x%llx\\n"
\t\t\t\t    "current pid=%d comm=%.31s fs=%.15s mount=%.63s\\n"
\t\t\t\t    "child=%p id=%u type=%u tag=%u parent=%p flags=0x%x\\n"
\t\t\t\t    "oldparent=%p id=%u use=0x%x io=%u kuse=%u type=%u tag=%u lf=0x%x vf=0x%x next=%p\\n"
\t\t\t\t    "defer=%u head=%p stream=%u",
\t\t\t\t    pdx_shutdown_pid, pdx_shutdown_comm, pdx_shutdown_howto, pdx_shutdown_time,
\t\t\t\t    proc_selfpid(), comm, pdx_fs, pdx_mount,
\t\t\t\t    pdx_identity_child, pdx_child_id, pdx_child_type, pdx_child_tag,
\t\t\t\t    pdx_child_parent, flags,
\t\t\t\t    vp, vp->v_id, (unsigned)os_atomic_load(&vp->v_usecount, relaxed),
\t\t\t\t    vp->v_iocount, vp->v_kusecount, vp->v_type, vp->v_tag,
\t\t\t\t    vp->v_lflag, vp->v_flag, vp->v_parent,
\t\t\t\t    ut->uu_defer_reclaims, ut->uu_vreclaims, isstream);
\t\t\t}
\t\t\tvnode_rele_internal(vp, 0, 0, 1);''')
