"""Remove historical touch painters and their 30ms worker from a staged boot page.

The one-second boot/log worker, scanout handoff, CPU governor call and standalone
panic renderer are not touched. This edits only a caller-owned staged copy.
"""


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Unexpected touch diagnostic anchor: ' + old[:100])
    return text.replace(old, new)


def definition(text, signature):
    start = text.index(signature)
    brace = text.index('{', start)
    if ';' in text[start:brace]:
        raise ValueError('Expected a definition, not a declaration: ' + signature)
    end, depth = brace + 1, 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


def clean_boot_progress(text):
    # Keep the old diagnostic formatters available for the boot-page reader;
    # only their removed painter/worker references had kept them compiler-live.
    text = replace_once(text, '#include "PdxGpuProgressCache.h"',
                        '#pragma clang diagnostic ignored "-Wunused-function"\n#include "PdxGpuProgressCache.h"')
    start = text.index('  if(&native_touch_rows && native_touch_rows[0][0]) {')
    end = text.index('  if(&native_ufs_verify_ticks', start)
    text = text[:start] + '  line(43,b,0xffaaaaaa);\n' + text[end:]
    text = replace_once(text, 'static void touch_overlay_locked(void);\n', '')
    for signature in ('static void touch_fill(', 'static void touch_overlay(void)',
                      'static void touch_overlay_locked(void)', 'static void touch_monitor('):
        text = replace_once(text, definition(text, signature), '')
    text = replace_once(text,
        '  if(kernel_thread_start_priority(touch_monitor,0,BASEPRI_KERNEL,&thread)==KERN_SUCCESS)thread_deallocate(thread);\n', '')
    for line in (
        'static volatile unsigned touch_passes,touch_dots,touch_pad_w;\n',
        'extern char native_touch_rows[4][120] __attribute__((weak_import));\n',
        'extern volatile uint32_t native_touch_loop_step __attribute__((weak_import));\n',
        'extern volatile uint32_t native_touch_seq,native_touch_count __attribute__((weak_import));\n',
        'extern volatile int native_touch_xs[12],native_touch_ys[12],native_touch_ids[12] __attribute__((weak_import));\n',
        'extern volatile unsigned native_touch_stage_req __attribute__((weak_import));\n',
        'extern volatile uint32_t native_hid_input_events[8] __attribute__((weak_import));\n',
        'extern volatile int native_hid_input_results[8] __attribute__((weak_import));\n',
    ):
        text = replace_once(text, line, '')
    # Remaining SCHED fields are retained historical counters, not a running probe.
    # Keep their representation compatible with existing boot/log readers.
    for marker in ('touch_monitor', 'touch_overlay', 'touch_fill', 'native_touch_rows',
                   'touch_dots', 'touch_pad_w', 'native_touch_stage_req'):
        if marker in text:
            raise ValueError('Touch diagnostic survived cleanup: ' + marker)
    return text
