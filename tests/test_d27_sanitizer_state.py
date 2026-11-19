"""Host checks for the source-backed D27 raw sanitizer import and spawn ABI.

These compile code extracted from the shipped patch with host boundary doubles;
they do not qualify a guest sanitizer, MAC policy result, or SpringBoard.
"""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / 'patches/xnu/ios27-d27-sanitizer-state.patch'


def added(member):
    section = PATCH.read_text().split(f'diff --git a/{member} b/{member}\n', 1)[1]
    section = section.split('\ndiff --git ', 1)[0]
    return '\n'.join(line[1:] for line in section.splitlines()
                     if line.startswith('+') and not line.startswith('+++')) + '\n'


class SanitizerStateTests(unittest.TestCase):
    def test_patch_is_selected_and_has_real_state_lifecycle(self):
        self.assertIn(PATCH.name, (ROOT / 'patches/xnu/series').read_text().splitlines())
        task = added('osfmk/kern/task.c')
        self.assertIn('new_task->sanitizer_config = 0;', task)
        self.assertIn('new_task->sanitizer_config = parent_task->sanitizer_config;', task)
        self.assertIn('return task->sanitizer_config;', task)
        self.assertIn('uint8_t sanitizer_config;', added('osfmk/kern/task.h'))
        self.assertNotIn('task_is_privileged(', task)
        exe = added('bsd/kern/kern_exec.c')
        self.assertIn('copyin(px_args.attrp, &d27_wire, sizeof(d27_wire))', exe)
        self.assertIn('sanitizer_config != 0', exe)
        self.assertIn('sanitizer_config=', exe)

    def test_all_fourteen_reviewed_imports_and_snapshot_hash(self):
        fixture = ROOT / 'ci/XnuPrelink/fixtures/fileset-24A446-d27-symbols.json'
        record = json.loads(fixture.read_text())
        functions = {row['original']: row for row in record['functions']}
        self.assertEqual(len(functions), len(record['functions']))
        expected = {
            '0xfffffff00a226184': '_task_get_sanitizer_config',
            '0xfffffff00a3ded64': '_vfs_name',
            '0xfffffff00a3dfacc': '_vfs_vnodecovered_noblock',
            '0xfffffff00a3e0d9c': '_vnode_isonexternalstorage',
            '0xfffffff00a6abce4': '_kauth_proc_label_update',
            '0xfffffff00a6e7638': '_proc_parent',
            '0xfffffff00a6e87a0': '_proc_getexecutablevnode_noblock',
            '0xfffffff00a6eb75c': '_proc_is_rsr',
            '0xfffffff00a6edf4c': '_proc_pgrpid',
            '0xfffffff00a6ee4fc': '_proc_get_syscall_filter_mask',
            '0xfffffff00a6ee778': '_proc_set_syscall_filter_index',
            '0xfffffff00a784064': '_sock_getsockname',
            '0xfffffff00a861814': '__ZN12OSDictionary14iterateObjectsEU13block_pointerFbPK8OSSymbolP8OSObjectE',
        }
        for address, symbol in expected.items():
            row = functions[address]
            self.assertEqual(row['native_symbol'], symbol)
            self.assertEqual(row['verification'], 'source-and-disassembly')
            self.assertRegex(row['original_sha256'], r'^[0-9a-f]{64}$')
        data = {row['original']: row for row in record['data']}
        self.assertEqual(data['0xfffffff00acfd738']['native_symbol'], '_audio_active')
        sanitizer = functions['0xfffffff00a226184']
        self.assertEqual(sanitizer['original_size'], 12)
        self.assertIn('ENOTSUP', sanitizer['evidence'])
        self.assertIn('descriptive compatibility API', sanitizer['evidence'])
        manifest = json.loads((ROOT / 'ci/source-overlays.json').read_text())
        entry = next(row for row in manifest['component_files']
                     if row['path'] == 'fixtures/fileset-24A446-d27-symbols.json')
        self.assertEqual(hashlib.sha256(fixture.read_bytes().replace(b'\r\n', b'\n')).hexdigest(),
                         entry['sha256_lf'])

    def test_extracted_wire_and_exec_code_preserve_raw_masks(self):
        compiler = shutil.which('cc')
        if compiler is None:
            self.skipTest('Host C compiler unavailable')
        header = added('bsd/sys/d27_spawn_wire.h')
        task = added('osfmk/kern/task.c')
        getters = task[task.index('uint8_t\ntask_get_sanitizer_config('):]
        exe = added('bsd/kern/kern_exec.c')
        start = exe.index('const struct _posix_spawnattr *sanitizer_spawn = imgp->ip_px_sa;')
        end_marker = 'task_set_sanitizer_config(new_task, sanitizer_config);'
        recompute = exe[start:exe.index(end_marker, start) + len(end_marker)]
        constants = '\n'.join(re.findall(r'^#define D27_SANITIZER_.*$', added('osfmk/kern/task.h'), re.M))
        code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
/* Explicit Darwin LP64 boundary fixture; actual XNU layout is separately
 * checked with its recorded arm64e compiler command. */
struct _posix_spawnattr {
    uint8_t prefix[168];
    uint8_t psa_launch_type, psa_d27_sanitizer_options;
    uint16_t psa_sec_flags;
    uint32_t psa_crash_count, psa_throttle_timeout;
    uint32_t psa_kqworkloop_soft_limit, psa_kqworkloop_hard_limit;
    uint32_t psa_conclave_mem_limit;
    void *psa_ports, *remaining_extensions[6];
};
_Static_assert(sizeof(struct _posix_spawnattr) == 248, "native LP64 attribute size");
struct task { uint8_t sanitizer_config; };
typedef struct task *task_t;
struct image_params { void *ip_px_sa; void *ip_vp; int64_t ip_arch_offset; };
static bool asan, tsan;
static bool IOVnodeHasEntitlement(void *vnode, int64_t offset, const char *name) {
    assert(vnode == (void *)0x1234 && offset == 0x4000);
    if (strcmp(name, "com.apple.security.developer-tools.address-sanitizer") == 0) return asan;
    assert(strcmp(name, "com.apple.security.developer-tools.thread-sanitizer") == 0);
    return tsan;
}
CONSTANTS
WIRE
GETTERS
static void recompute(struct image_params *imgp, task_t new_task) {
RECOMPUTE
}
int main(void) {
    struct d27_spawn_wire_prefix wire = {0};
    struct _posix_spawnattr native, unchanged;
    struct task task;
    struct image_params imgp = { &native, (void *)0x1234, 0x4000 };
    wire.crash_count = 0x11223344;
    wire.throttle_timeout = 0x55667788;
    wire.kqworkloop_soft_limit = 0x99aabbcc;
    wire.kqworkloop_hard_limit = 0xddeeff00;
    wire.conclave_mem_limit = 0x12345678;
    _Static_assert(_Generic(task_get_sanitizer_config(&task), uint8_t: 1, default: 0), "raw byte getter");
    for (unsigned flags = 0; flags < 4; ++flags) {
        asan = (flags & 1) != 0; tsan = (flags & 2) != 0;
        for (unsigned b = 0; b < 256; ++b) {
            wire.sanitizer_options = b;
            assert(d27_spawn_translate_prefix(&wire, &native) == 0);
            assert(native.psa_d27_sanitizer_options == b);
            assert(native.psa_crash_count == wire.crash_count);
            assert(native.psa_throttle_timeout == wire.throttle_timeout);
            assert(native.psa_kqworkloop_soft_limit == wire.kqworkloop_soft_limit);
            assert(native.psa_kqworkloop_hard_limit == wire.kqworkloop_hard_limit);
            assert(native.psa_conclave_mem_limit == wire.conclave_mem_limit);
            assert(native.psa_sec_flags == 0 && native.psa_ports == NULL);
            task_set_sanitizer_config(&task, b);
            assert(task_get_sanitizer_config(&task) == b);
            recompute(&imgp, &task);
            assert(task_get_sanitizer_config(&task) == ((b & 0x0e) | (asan ? 2 : 0) | (tsan ? 4 : 0)));
        }
        imgp.ip_px_sa = NULL;
        task_set_sanitizer_config(&task, 0xff);
        recompute(&imgp, &task);
        assert(task_get_sanitizer_config(&task) == ((asan ? 2 : 0) | (tsan ? 4 : 0)));
        imgp.ip_px_sa = &native;
    }
    unchanged = native;
    for (unsigned bit = 0; bit < 32; ++bit) {
        wire.policy_raw = UINT32_C(1) << bit;
        int expected = (wire.policy_raw & 0x1f01) ? ENOTSUP : EINVAL;
        assert(d27_spawn_translate_prefix(&wire, &native) == expected);
        assert(memcmp(&native, &unchanged, sizeof(native)) == 0);
    }
    puts("PASS: raw byte, 1024 recomputations, wire fields and explicit policy rejection");
    return 0;
}
'''
        for key, value in [('CONSTANTS', constants), ('WIRE', header),
                           ('GETTERS', getters), ('RECOMPUTE', recompute)]:
            code = code.replace(key, value)
        with tempfile.TemporaryDirectory() as directory:
            source, binary = Path(directory) / 'test.c', Path(directory) / 'test'
            source.write_text(code)
            built = subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                                    str(source), '-o', str(binary)], capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
