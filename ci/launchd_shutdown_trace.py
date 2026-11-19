"""023: retain the PID1 text immediately before its first shutdown log."""
from launchd_transport_trace import adapt_source as transport_source, adapt_vfs as transport_vfs
from vfs_shutdown_diagnostic import replace_once


HELPERS = r'''
char pdx_launchd_before[1537], pdx_launchd_trigger[385];
unsigned pdx_launchd_shutdown_seen;
static int pdx_launchd_contains(const char *bytes, unsigned n, const char *needle)
{
    unsigned length = (unsigned)strlen(needle);
    if (length > n) return 0;
    for (unsigned i = 0; i <= n - length; ++i)
        if (!memcmp(bytes + i, needle, length)) return 1;
    return 0;
}
/* Called under the existing nonspinning guard; no user access or allocation. */
static void pdx_launchd_before_shutdown(char *dst, const char *label, unsigned size,
    const char *bytes, unsigned n)
{
    if (pdx_launchd_shutdown_seen) return;
    /* Only textual write output feeds this history: sendto also carries a
     * binary log envelope and duplicates the messages in the observed boot. */
    if (dst != pdx_launchd_text) return;
    if (pdx_launchd_contains(bytes, n, "(shutdown)") ||
        pdx_launchd_contains(bytes, n, "shutting down system") ||
        pdx_launchd_contains(bytes, n, "Rebooting to device recovery")) {
        pdx_launchd_append(pdx_launchd_trigger, sizeof(pdx_launchd_trigger), label, size);
        unsigned keep = n > 350 ? 350 : n;
        pdx_launchd_append(pdx_launchd_trigger, sizeof(pdx_launchd_trigger), bytes, keep);
        pdx_launchd_shutdown_seen = 1;
        return;
    }
    pdx_launchd_append(pdx_launchd_before, sizeof(pdx_launchd_before), label, size);
    pdx_launchd_append(pdx_launchd_before, sizeof(pdx_launchd_before), bytes, n);
}
'''


def adapt_source(text):
    text = transport_source(text)
    text = replace_once(text, 'char pdx_launchd_send[1025], pdx_launchd_destination[129];',
                        HELPERS + '\nchar pdx_launchd_send[1025], pdx_launchd_destination[129];')
    return replace_once(text, '    pdx_launchd_append(dst, cap, label, (unsigned)size);',
                        '    pdx_launchd_before_shutdown(dst, label, (unsigned)size, bytes, n);\n'
                        '    pdx_launchd_append(dst, cap, label, (unsigned)size);')


def adapt_vfs(text):
    text = transport_vfs(text)
    text = replace_once(text, 'extern char pdx_launchd_text[769], pdx_launchd_errors[257];',
                        'extern char pdx_launchd_text[769], pdx_launchd_errors[257];\n'
                        'extern char pdx_launchd_before[1537], pdx_launchd_trigger[385];\n'
                        'extern unsigned pdx_launchd_shutdown_seen;\n'
                        'extern volatile int sheng_watchdog_policy_status;')
    old = r'PDX PID1 reboot pc=%llx lr=%llx\nSEND: %.1024s\nTO: %.128s\nOUTPUT: %.768s\nERRORS: %.256s\nLAST: %u:%u x%u\n'
    new = r'PDX PID1 pc=%llx lr=%llx\nBEFORE: %.1536s\nFIRST SHUTDOWN: %.384s\nSEEN=%u POLICY=%d\nERRORS: %.256s\nLAST: %u:%u x%u\n'
    args = 'pdx_launchd_reboot_pc, pdx_launchd_reboot_lr, pdx_launchd_send, pdx_launchd_destination, pdx_launchd_text, pdx_launchd_errors, pdx_launchd_last_code, pdx_launchd_last_error, pdx_launchd_repeat,'
    new_args = 'pdx_launchd_reboot_pc, pdx_launchd_reboot_lr, pdx_launchd_before, pdx_launchd_trigger, pdx_launchd_shutdown_seen, sheng_watchdog_policy_status, pdx_launchd_errors, pdx_launchd_last_code, pdx_launchd_last_error, pdx_launchd_repeat,'
    if text.count(old) != 2 or text.count(args) != 2:
        raise ValueError('Expected two transport diagnostic formats and argument lists')
    return text.replace(old, new).replace(args, new_args)
