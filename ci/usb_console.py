"""XNU12377/iOS27 source hooks for the pinned QcomXnuUsbDebug transport.

Adapted from its Darwin23 console hooks. Console producers only enqueue;
hardware polling belongs to the boot-CPU worker or bounded panic drain.
"""
from vfs_shutdown_diagnostic import replace_once, adapt_cache

UNITS = {'pe_kprintf.c': 'usb27-kprintf', 'serial_console.c': 'usb27-console',
         'serial_general.c': 'usb27-printbuf', 'bsd_init.c': 'usb27-worker'}


def adapt_kprintf(text):
    text = replace_once(text, 'static void serial_putc_crlf(char c);', '''static void serial_putc_crlf(char c);
#include <QcomXnuUsbDebug.h>
/* Preserve the current sink; avoid teeing twice through console fallback. */
static void pdx_usb_kputc(char c)
{
    if (PE_kputc != console_write_unbuffered) {
        (void)qcom_usb_debug_enqueue(&c, 1);
    }
    if (PE_kputc) PE_kputc(c);
}''')
    # Hardware initialization is in the bound normal worker, after kminit.
    # Early messages stay in the static CPU backlog, with no MMIO or cpu data.
    text = replace_once(text, '_doprnt_log(format, &listp, PE_kputc, 16);',
                        '_doprnt_log(format, &listp, pdx_usb_kputc, 16);')
    return replace_once(text, '_doprnt_log(fmt, &listp, PE_kputc, 16);',
                        '_doprnt_log(fmt, &listp, pdx_usb_kputc, 16);')


def adapt_console(text):
    return replace_once(text, 'static inline void\n_cnputs(char *c, int size, bool poll)\n{', '''#include <QcomXnuUsbDebug.h>
static inline void
_cnputs(char *c, int size, bool poll)
{
    if (c && size > 0) (void)qcom_usb_debug_enqueue(c, (size_t)size);''')


def adapt_printbuf(text):
    return replace_once(text, '\t\tif (serialmode & SERIALMODE_SYNCDRAIN) {',
                        '\t\t/* Flush a full buffer even without a newline for USB capture. */\n\t\t{')


def adapt_worker(text):
    return replace_once(text, '\tkminit();', '''\tkminit();
\textern void pdx_usb_start_worker(void);
\tpdx_usb_start_worker();''')


def adapt_vfs(text):
    text = adapt_cache(text)
    text = replace_once(text, '#include <sys/proc.h>', '''#include <sys/proc.h>
#include <QcomXnuUsbDebug.h>
extern void pdx_usb_panic_log(const char *, ...);''')
    start = text.index('\t\t\t\tpanic("PDX parent-underflow before release')
    end = text.index('ut->uu_defer_reclaims, ut->uu_vreclaims, isstream);', start)
    end += len('ut->uu_defer_reclaims, ut->uu_vreclaims, isstream);')
    call = text[start:end]
    call = call.replace('"PDX parent-underflow before release\\n"',
                        '"PDX parent-underflow before release\\nUSB phase=%u error=%u qcom=%u domain=%u stage=%u\\n"\n'
                        '\t\t\t\t    "core=0x%x io=%u cause=%u trace=%u a=0x%x b=0x%x\\n"\n'
                        '\t\t\t\t    "ID=%x VER=%x P1=%x P3=%x GCTL=%x DCTL=%x DSTS=%x\\n"\n'
                        '\t\t\t\t    "EPS=%x EP0=%x EP1=%x EVT=%x CNT=%x FSR=%x\\n"')
    call = call.replace('    pdx_shutdown_pid,',
                        '    usb.phase, usb.error, usb.qcom_result, usb.domain_result, usb.domain_stage,\n'
                        '\t\t\t\t    (unsigned)usb.core_result, usb.init_io_failed, usb.init_error, usb.last_trace, usb.trace_a, usb.trace_b,\n'
                        '\t\t\t\t    usb.init_regs[0], usb.init_regs[12], usb.init_regs[1], usb.init_regs[2], usb.init_regs[3], usb.init_regs[4], usb.init_regs[5],\n'
                        '\t\t\t\t    usb.init_regs[6], usb.init_regs[7], usb.init_regs[8], usb.init_regs[9], usb.init_regs[10], usb.init_regs[11],\n'
                        '\t\t\t\t    pdx_shutdown_pid,', 1)
    log = call.replace('panic(', 'pdx_usb_panic_log(', 1)
    return text[:start] + ('\t\t\t\tstruct qcom_usb_debug_status usb;\n'
                          '\t\t\t\tqcom_usb_debug_get_status(&usb);\n') + log + '\n' + call + text[end:]


ADAPTERS = {'usb27-kprintf': adapt_kprintf, 'usb27-console': adapt_console,
            'usb27-printbuf': adapt_printbuf, 'usb27-worker': adapt_worker,
            'vfs-parent-release-usb-diagnostic': adapt_vfs}
