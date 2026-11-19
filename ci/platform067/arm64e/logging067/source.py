"""Composable official sheng logging overlays. No shared source mutation."""
from pathlib import Path
import hashlib
import re
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from audit import parse_patch

FRESH = Path('/mnt/f/UniXNU-Port-artifacts/platform067-20261118/sheng')
PATCHES = ('zzzzzz-sheng-bsd-checkpoints.patch', 'sheng-bootstrap-checkpoints.patch',
           'sheng-headless-startup-checkpoints.patch', 'sheng-startup-failure-log.patch',
           'sheng-process-exit-log.patch')


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Missing/ambiguous logging anchor: ' + repr(old[:120]))
    return text.replace(old, new, 1)


def apply_file(text, filename, patchname, skip=()):
    patch = FRESH / 'patches/xnu-12377' / patchname
    diffs = [d for d in parse_patch(patch.read_text()) if d.path == filename]
    if len(diffs) != 1:
        raise ValueError('Expected one official file diff')
    for index, hunk in enumerate(diffs[0].hunks):
        if index in skip:
            continue
        old, new = '\n'.join(hunk.old()) + '\n', '\n'.join(hunk.new()) + '\n'
        text = once(text, old, new)
    return text


def bsd_prerequisite(text):
    """Restore exact earlier official bringup checkpoint calls needed by new patch."""
    text = once(text, '#if DEVELOPMENT || DEBUG\n\tnative_apfs_load_probe();\n',
                '#if DEVELOPMENT || DEBUG\n'
                '\textern void boot_log_checkpoint(const char *) __attribute__((weak_import));\n'
                '\tif (&boot_log_checkpoint) boot_log_checkpoint("bsd-apfs-load");\n'
                '\tnative_apfs_load_probe();\n'
                '\tif (&boot_log_checkpoint) boot_log_checkpoint("bsd-apfs-ready");\n')
    for name, label in [('native_mobile_graphics_load_probe', 'bsd-mobile-graphics'),
                        ('native_iogpu_load_probe', 'bsd-iogpu')]:
        text = once(text, '\t' + name + '();\n',
                    '\tif (&boot_log_checkpoint) boot_log_checkpoint("' + label + '-load");\n' +
                    '\t' + name + '();\n' +
                    '\tif (&boot_log_checkpoint) boot_log_checkpoint("' + label + '-ready");\n')
    return text


def adapt_bsd_init(text):
    text = bsd_prerequisite(text)
    text = apply_file(text, 'bsd/kern/bsd_init.c', PATCHES[0])
    return apply_file(text, 'bsd/kern/bsd_init.c', PATCHES[1])


def adapt_startup(text):
    return apply_file(text, 'osfmk/kern/startup.c', PATCHES[1])


def adapt_header(text):
    return apply_file(text, 'osfmk/kern/boot_progress.h', PATCHES[2])


def adapt_exec(text):
    """Compose AFTER main's addon length fix; never re-create old kern_exec source."""
    if 'VATTR_SET(&va, va_data_size, size);' not in text or 'AGXMetalG14.bundle' not in text:
        raise ValueError('Main addon-length source and D27 lower-entry guard are prerequisites')
    text = apply_file(text, 'bsd/kern/kern_exec.c', PATCHES[2])
    # The current official hunk expects the newer source-storage #else branch.
    # D27 actually calls native_owner_data_prepare directly. Add only the sink
    # between that call and its existing stage/error handling, preserving both.
    old = ('\tint data_error = native_owner_data_prepare(p, (user_addr_t)scratch_addr);\n'
           '\tboot_progress_stage("Data mount returned");\n'
           '\tif (data_error) panic("offline scratch Data mount failed: %d", data_error);')
    new = ('\tint data_error = native_owner_data_prepare(p, (user_addr_t)scratch_addr);\n'
           '\textern void boot_log_startup_result(const char *, int) __attribute__((weak_import));\n'
           '\tif (&boot_log_startup_result) boot_log_startup_result("Data mount returned", data_error);\n'
           '\tboot_progress_stage("Data mount returned");\n'
           '\tif (data_error) panic("offline scratch Data mount failed: %d", data_error);')
    text = once(text, old, new)
    return apply_file(text, 'bsd/kern/kern_exec.c', PATCHES[3], skip=(0,))


def adapt_debug(text):
    return apply_file(text, 'osfmk/kern/debug.c', PATCHES[3])


def adapt_exit(text):
    return apply_file(text, 'bsd/kern/kern_exit.c', PATCHES[4])


def function(text, name):
    """These official C bodies close with an unindented brace; exact extraction."""
    matches = list(re.finditer(r'(?m)^(?:static )?[^\n;{}]*\b' + re.escape(name) + r'\([^;{}]*\)\s*\{', text))
    if len(matches) != 1:
        raise ValueError('Expected one function definition: ' + name)
    start = pos = matches[0].start()
    end = text.index('\n}', pos) + 3
    return text[start:end] + '\n'


def provider_parts(fresh):
    start = fresh.index('static IOLock *checkpoint_lock;')
    end = fresh.index('\nstatic volatile int boot_log_panicked;', start)
    checkpoint = fresh[start:end]
    panic = function(fresh, 'boot_log_panic_record')
    start = fresh.index('  uint32_t checkpoint_mode = 0;')
    end = fresh.index('\n#if defined(NATIVE_BOOT_PROCESS_CAPTURE)', start)
    init = fresh[start:end]
    return checkpoint, panic, init


def adapt_provider(text):
    fresh = (FRESH / 'package/BootLog.c').read_text()
    checkpoint, panic, init = provider_parts(fresh)
    text = once(text, '#include <kern/clock.h>\n', '#include <kern/clock.h>\n'
                '#include <mach/mach_time.h>\n#include <machine/machine_routines.h>\n')
    text = once(text, '#include <string.h>\n', '#include <string.h>\n#include <stdarg.h>\n'
                'extern int vsnprintf(char *, size_t, const char *, va_list);\n')
    old = 'static volatile int boot_log_panicked;   // set by boot_log_panic_flush: the writer no longer writes'
    text = once(text, old, checkpoint + '\n' + old)
    anchor = '// autoreset: mark the bootloader cell (any restart is fastboot)'
    if text.count(anchor) != 1:
        raise ValueError('Sony watchdog policy anchor changed')
    text = text.replace(anchor, panic + '\n' + anchor, 1)
    text = once(text, '  export_lock = IOLockAlloc();\n', '  export_lock = IOLockAlloc();\n' + init + '\n')
    return text


ADAPTERS = {'bsd/kern/bsd_init.c': adapt_bsd_init, 'osfmk/kern/startup.c': adapt_startup,
            'osfmk/kern/boot_progress.h': adapt_header, 'bsd/kern/kern_exec.c': adapt_exec,
            'osfmk/kern/debug.c': adapt_debug, 'bsd/kern/kern_exit.c': adapt_exit,
            'package/BootLog.c': adapt_provider}
