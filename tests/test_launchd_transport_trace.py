"""Exercise the exact capture C with a bounded, fault-injectable user address space."""
import sys
from pathlib import Path
import subprocess
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ci'))
from launchd_trace import adapt_source
from launchd_transport_trace import HELPERS
from launchd_shutdown_trace import HELPERS as SHUTDOWN_HELPERS


class TransportTrace(unittest.TestCase):
    def test_capture_faults_bounds_vectors_and_error_coalescing(self):
        original = 'static int      arm_get_syscall_args\n\tpid = proc_pid(proc);\n' + (
            '\terror = (*(callp->sy_call))(proc, &uthread->uu_arg[0], &(uthread->uu_rval[0]));\n'
            '\tAUDIT_SYSCALL_EXIT(code, proc, uthread, error);')
        generated = adapt_source(original)
        declarations = generated[generated.index('char pdx_launchd_text'):generated.index('static void pdx_launchd_write(')]
        source = r'''
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
typedef uint64_t user_addr_t;
typedef uint64_t user_size_t;
struct user64_iovec {uint64_t iov_base, iov_len;};
static unsigned char memory[8192];
static unsigned copied, reads;
static int copyin(user_addr_t address, void *dst, size_t size) {
    ++reads;
    if (!address || address >= sizeof(memory) || size > sizeof(memory) - address) return 1;
    memcpy(dst, memory + address, size); copied += size; return 0;
}
''' + declarations + SHUTDOWN_HELPERS + HELPERS.replace(
            '    pdx_launchd_append(dst, cap, label, (unsigned)size);',
            '    pdx_launchd_before_shutdown(dst, label, (unsigned)size, bytes, n);\n'
            '    pdx_launchd_append(dst, cap, label, (unsigned)size);') + r'''
int main(void) {
    memset(memory, 'A', sizeof(memory));
    memory[101] = 0; memory[102] = 255; memory[103] = '\n';
    pdx_launchd_capture(pdx_launchd_send, sizeof(pdx_launchd_send), 133, 7, 100, UINT64_MAX);
    assert(copied == 512 && strlen(pdx_launchd_send) == strlen("\n133 fd7: ") + 512);
    assert(strstr(pdx_launchd_send, "A.."));
    char saved[1025]; memcpy(saved, pdx_launchd_send, sizeof(saved));
    pdx_launchd_capture(pdx_launchd_send, sizeof(pdx_launchd_send), 133, 7, UINT64_MAX, 10);
    assert(pdx_launchd_copy_failures == 1 && !memcmp(saved, pdx_launchd_send, sizeof(saved)));
    pdx_launchd_guard = 1;
    pdx_launchd_capture(pdx_launchd_send, sizeof(pdx_launchd_send), 133, 7, 100, 10);
    assert(pdx_launchd_guard == 1 && !memcmp(saved, pdx_launchd_send, sizeof(saved)));
    pdx_launchd_guard = 0;
    for (unsigned i=0; i<1000; ++i)
        pdx_launchd_capture(pdx_launchd_send, sizeof(pdx_launchd_send), 133, 7, 200, i % 700);
    assert(strlen(pdx_launchd_send) == 1024);
    struct user64_iovec vectors[8];
    for (unsigned i=0; i<8; ++i) vectors[i]=(struct user64_iovec){200, UINT64_MAX};
    memcpy(memory+4096, vectors, sizeof(vectors));
    copied=reads=0;
    pdx_launchd_vector(121, 8, 4096, 1000);
    assert(copied == 1024 + 2*sizeof(vectors[0]) && reads == 4);
    assert(strlen(pdx_launchd_text) == 768);
    copied=reads=0; pdx_launchd_vector(121, 8, 4096, -1); assert(reads == 0);
    pdx_launchd_vector(121, 8, UINT64_MAX, 1); assert(pdx_launchd_copy_failures == 2);
    for (unsigned i=0; i<1000; ++i) pdx_launchd_error(133,55,7);
    assert(pdx_launchd_repeat == 1000 && !strcmp(pdx_launchd_errors,"133:55 a0=7 "));
    pdx_launchd_error(4,5,2);
    assert(pdx_launchd_repeat == 1 && strstr(pdx_launchd_errors,"4:5 a0=2 "));
    memset(pdx_launchd_before, 0, sizeof(pdx_launchd_before));
    const char preceding[] = "service failed before reboot";
    memcpy(memory+200, preceding, sizeof(preceding)-1);
    pdx_launchd_capture(pdx_launchd_text, sizeof(pdx_launchd_text), 4, 3, 200, sizeof(preceding)-1);
    assert(!pdx_launchd_shutdown_seen && strstr(pdx_launchd_before, preceding));
    char before[1537]; memcpy(before, pdx_launchd_before, sizeof(before));
    const char trigger[] = "com.apple.xpc.launchd (shutdown) transition";
    memcpy(memory+200, trigger, sizeof(trigger)-1);
    pdx_launchd_capture(pdx_launchd_send, sizeof(pdx_launchd_send), 133, 4, 200, sizeof(trigger)-1);
    assert(!pdx_launchd_shutdown_seen);
    pdx_launchd_capture(pdx_launchd_text, sizeof(pdx_launchd_text), 4, 3, 200, sizeof(trigger)-1);
    assert(pdx_launchd_shutdown_seen && strstr(pdx_launchd_trigger, trigger));
    for (unsigned i=0; i<1000; ++i)
        pdx_launchd_capture(pdx_launchd_text, sizeof(pdx_launchd_text), 4, 3, 200, 512);
    assert(!memcmp(before, pdx_launchd_before, sizeof(before)));
    assert(strstr(pdx_launchd_trigger, trigger));
    assert(!pdx_launchd_contains("short",5,"long needle"));
    assert(pdx_launchd_contains("xx(shutdown)",12,"(shutdown)"));
    puts("PASS exact C transport capture, copy faults, guards, vector budget and repeated errors");
    puts("PASS pre-shutdown history survives 1000 teardown writes; binary sends do not trigger it");
}
'''
        with tempfile.TemporaryDirectory(prefix='pid1-transport-') as directory:
            root = Path(directory)
            (root/'check.c').write_text(source)
            clang = '/mnt/e/UniXNU-sheng27-sony-20261113/tmp/clang18-host/clang'
            subprocess.run([clang, '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                            str(root/'check.c'), '-o', str(root/'check')], check=True)
            subprocess.run([str(root/'check')], check=True)


if __name__ == '__main__':
    unittest.main()
