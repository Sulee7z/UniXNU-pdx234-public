"""Bounded PID1 output and syscall-error snapshots, independent of USB."""
from vfs_shutdown_diagnostic import replace_once


def adapt_source(text):
    if 'pdx_launchd_text' in text:
        raise ValueError('PID1 trace already applied')
    marker = 'static int      arm_get_syscall_args'
    if text.count(marker) != 1:
        raise ValueError('Unexpected syscall declarations')
    declarations = '''/* PID1 evidence only: bounded buffers, no syscall result changes. */
char pdx_launchd_text[769];
char pdx_launchd_errors[257];
uint64_t pdx_launchd_reboot_pc, pdx_launchd_reboot_lr;
static unsigned pdx_launchd_guard;
static unsigned pdx_launchd_copy_failures;
static void pdx_launchd_append(char *dst, unsigned cap, const char *src, unsigned n)
{
    unsigned used = (unsigned)strnlen(dst, cap - 1);
    if (n >= cap) { src += n - (cap - 1); n = cap - 1; }
    if (used + n >= cap) {
        unsigned drop = used + n - (cap - 1);
        memmove(dst, dst + drop, used - drop);
        used -= drop;
    }
    memcpy(dst + used, src, n);
    dst[used + n] = 0;
}
static void pdx_launchd_write(user_addr_t address, user_size_t count)
{
    char bytes[256];
    unsigned n = count > sizeof(bytes) ? sizeof(bytes) : (unsigned)count;
    if (!n) return;
    /* copyin can fault: do it before acquiring the nonspinning CPU guard. */
    if (copyin(address, bytes, n)) {
        __atomic_fetch_add(&pdx_launchd_copy_failures, 1u, __ATOMIC_RELAXED);
        return;
    }
    for (unsigned i = 0; i < n; ++i)
        if ((unsigned char)bytes[i] < 32 && bytes[i] != '\\n' && bytes[i] != '\\t') bytes[i] = '.';
    if (__atomic_exchange_n(&pdx_launchd_guard, 1u, __ATOMIC_ACQUIRE)) return;
    pdx_launchd_append(pdx_launchd_text, sizeof(pdx_launchd_text), bytes, n);
    __atomic_store_n(&pdx_launchd_guard, 0u, __ATOMIC_RELEASE);
}
static void pdx_launchd_error(unsigned code, int error)
{
    char line[48];
    int n = snprintf(line, sizeof(line), "%u:%d ", code, error);
    if (n <= 0 || n >= (int)sizeof(line)) return;
    if (__atomic_exchange_n(&pdx_launchd_guard, 1u, __ATOMIC_ACQUIRE)) return;
    pdx_launchd_append(pdx_launchd_errors, sizeof(pdx_launchd_errors), line, (unsigned)n);
    __atomic_store_n(&pdx_launchd_guard, 0u, __ATOMIC_RELEASE);
}

'''
    text = text.replace(marker, declarations + marker, 1)
    text = replace_once(text, '\tpid = proc_pid(proc);', '''\tpid = proc_pid(proc);
\tif (pid == 1) {
\t\tif ((code == SYS_write || code == SYS_write_nocancel) && uthread->uu_arg[0] <= 2)
\t\t\tpdx_launchd_write((user_addr_t)uthread->uu_arg[1], (user_size_t)uthread->uu_arg[2]);
\t\tif (code == SYS_reboot) {
\t\t\tpdx_launchd_reboot_pc = get_saved_state_pc(state);
\t\t\tpdx_launchd_reboot_lr = get_saved_state_lr(state);
\t\t}
\t}''')
    return replace_once(text, '\terror = (*(callp->sy_call))(proc, &uthread->uu_arg[0], &(uthread->uu_rval[0]));\n\tAUDIT_SYSCALL_EXIT(code, proc, uthread, error);', '''\terror = (*(callp->sy_call))(proc, &uthread->uu_arg[0], &(uthread->uu_rval[0]));
\tAUDIT_SYSCALL_EXIT(code, proc, uthread, error);
\tif (pid == 1 && error) pdx_launchd_error(code, error);''')


def add_panic_context(text):
    text = replace_once(text, '#include <sys/proc.h>', '''#include <sys/proc.h>
extern char pdx_launchd_text[769], pdx_launchd_errors[257];
extern uint64_t pdx_launchd_reboot_pc, pdx_launchd_reboot_lr;''')
    old = '"PDX parent-underflow before release\\nUSB phase='
    new = ('"PDX PID1 reboot pc=%llx lr=%llx\\nOUTPUT: %.768s\\nERRORS: %.256s\\n"\n'
           '\t\t\t\t    "PDX parent-underflow before release\\nUSB phase=')
    if text.count(old) != 2:
        raise ValueError('Expected USB log and panic diagnostic')
    text = text.replace(old, new)
    args = '    usb.phase, usb.error,'
    if text.count(args) != 2:
        raise ValueError('Expected diagnostic argument lists')
    return text.replace(args, '    pdx_launchd_reboot_pc, pdx_launchd_reboot_lr, pdx_launchd_text, pdx_launchd_errors,\n\t\t\t\t    usb.phase, usb.error,')


def adapt_vfs(text):
    from usb_console import adapt_vfs as usb_vfs
    return add_panic_context(usb_vfs(text))
