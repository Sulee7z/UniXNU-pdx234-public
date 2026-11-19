"""021: bounded PID1 sendto/writev capture, retaining the 020 overlay recipe."""
from launchd_trace import adapt_source as trace020, adapt_vfs as vfs020
from vfs_shutdown_diagnostic import replace_once


HELPERS = r'''
char pdx_launchd_send[1025], pdx_launchd_destination[129];
unsigned pdx_launchd_last_code, pdx_launchd_last_error, pdx_launchd_repeat;
static void pdx_launchd_capture(char *dst, unsigned cap, unsigned code, int fd,
    user_addr_t address, user_size_t count)
{
    char bytes[512], label[32];
    unsigned n = count > sizeof(bytes) ? sizeof(bytes) : (unsigned)count;
    if (!n) return;
    if (copyin(address, bytes, n)) {
        __atomic_fetch_add(&pdx_launchd_copy_failures, 1u, __ATOMIC_RELAXED);
        return;
    }
    for (unsigned i = 0; i < n; ++i)
        if (((unsigned char)bytes[i] < 32 && bytes[i] != '\n' && bytes[i] != '\t') ||
            (unsigned char)bytes[i] > 126) bytes[i] = '.';
    int size = snprintf(label, sizeof(label), "\n%u fd%d: ", code, fd);
    if (size <= 0 || size >= (int)sizeof(label)) return;
    if (__atomic_exchange_n(&pdx_launchd_guard, 1u, __ATOMIC_ACQUIRE)) return;
    pdx_launchd_append(dst, cap, label, (unsigned)size);
    pdx_launchd_append(dst, cap, bytes, n);
    __atomic_store_n(&pdx_launchd_guard, 0u, __ATOMIC_RELEASE);
}
static void pdx_launchd_vector(unsigned code, int fd, user_addr_t address, int count)
{
    unsigned budget = 1024;
    if (count <= 0) return;
    for (unsigned i = 0; i < (unsigned)count && i < 8 && budget; ++i) {
        struct user64_iovec vector;
        user_addr_t at = address + i * sizeof(vector);
        if (at < address || copyin(at, &vector, sizeof(vector))) {
            __atomic_fetch_add(&pdx_launchd_copy_failures, 1u, __ATOMIC_RELAXED);
            return;
        }
        unsigned n = vector.iov_len > 512 ? 512 : (unsigned)vector.iov_len;
        if (n > budget) n = budget;
        pdx_launchd_capture(pdx_launchd_text, sizeof(pdx_launchd_text), code, fd,
            vector.iov_base, n);
        budget -= n;
    }
}
static void pdx_launchd_error(unsigned code, int error, uint64_t arg0)
{
    char line[64];
    int n = snprintf(line, sizeof(line), "%u:%d a0=%llx ", code, error, arg0);
    if (n <= 0 || n >= (int)sizeof(line)) return;
    if (__atomic_exchange_n(&pdx_launchd_guard, 1u, __ATOMIC_ACQUIRE)) return;
    if (pdx_launchd_last_code == code && pdx_launchd_last_error == (unsigned)error) {
        if (pdx_launchd_repeat != ~0u) ++pdx_launchd_repeat;
    } else {
        pdx_launchd_last_code = code;
        pdx_launchd_last_error = (unsigned)error;
        pdx_launchd_repeat = 1;
        pdx_launchd_append(pdx_launchd_errors, sizeof(pdx_launchd_errors), line, (unsigned)n);
    }
    __atomic_store_n(&pdx_launchd_guard, 0u, __ATOMIC_RELEASE);
}
'''


def adapt_source(text):
    text = trace020(text)
    text = replace_once(text, '#include <sys/user.h>', '#include <sys/user.h>\n#include <sys/uio_internal.h>')
    start = text.index('static void pdx_launchd_write(')
    end = text.index('static int      arm_get_syscall_args', start)
    text = text[:start] + HELPERS + '\n' + text[end:]
    text = replace_once(text, '''		if ((code == SYS_write || code == SYS_write_nocancel) && uthread->uu_arg[0] <= 2)
			pdx_launchd_write((user_addr_t)uthread->uu_arg[1], (user_size_t)uthread->uu_arg[2]);''', '''		if (code == SYS_write || code == SYS_write_nocancel)
			pdx_launchd_capture(pdx_launchd_text, sizeof(pdx_launchd_text), code,
			    (int)uthread->uu_arg[0], uthread->uu_arg[1], uthread->uu_arg[2]);
		if (code == SYS_sendto || code == SYS_sendto_nocancel) {
			pdx_launchd_capture(pdx_launchd_send, sizeof(pdx_launchd_send), code,
			    (int)uthread->uu_arg[0], uthread->uu_arg[1], uthread->uu_arg[2]);
			if (uthread->uu_arg[4] && uthread->uu_arg[5])
				pdx_launchd_capture(pdx_launchd_destination, sizeof(pdx_launchd_destination), code,
				    (int)uthread->uu_arg[0], uthread->uu_arg[4],
				    uthread->uu_arg[5] > 104 ? 104 : uthread->uu_arg[5]);
		}
		if ((code == SYS_writev || code == SYS_writev_nocancel) && IS_64BIT_PROCESS(proc))
			pdx_launchd_vector(code, (int)uthread->uu_arg[0], uthread->uu_arg[1], (int)uthread->uu_arg[2]);''')
    return replace_once(text, 'pdx_launchd_error(code, error);', 'pdx_launchd_error(code, error, uthread->uu_arg[0]);')


def adapt_vfs(text):
    text = vfs020(text)
    text = replace_once(text, 'extern char pdx_launchd_text[769], pdx_launchd_errors[257];', '''extern char pdx_launchd_text[769], pdx_launchd_errors[257];
extern char pdx_launchd_send[1025], pdx_launchd_destination[129];
extern unsigned pdx_launchd_last_code, pdx_launchd_last_error, pdx_launchd_repeat;''')
    old = r'\nOUTPUT: %.768s\nERRORS: %.256s\n'
    new = r'\nSEND: %.1024s\nTO: %.128s\nOUTPUT: %.768s\nERRORS: %.256s\nLAST: %u:%u x%u\n'
    if text.count(old) != 2:
        raise ValueError('Expected two PID1 diagnostic formats')
    text = text.replace(old, new)
    old = 'pdx_launchd_reboot_pc, pdx_launchd_reboot_lr, pdx_launchd_text, pdx_launchd_errors,'
    if text.count(old) != 2:
        raise ValueError('Expected two PID1 argument lists')
    return text.replace(old, 'pdx_launchd_reboot_pc, pdx_launchd_reboot_lr, pdx_launchd_send, pdx_launchd_destination, pdx_launchd_text, pdx_launchd_errors, pdx_launchd_last_code, pdx_launchd_last_error, pdx_launchd_repeat,')
