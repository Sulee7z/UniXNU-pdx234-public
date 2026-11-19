/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Boot-CPU logging worker, adapted from QcomXnuUsbDebug's Darwin23 worker.
 * No control commands or reset callback. Device state is qualified at runtime.
 */
#include <stdarg.h>
#include <kern/misc_protos.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/cpu_number.h>
#include <kern/sched_prim.h>
#include <kern/clock.h>
#include <pexpert/pexpert.h>
#include <QcomXnuUsbDebug.h>
#include "PdxUsbDisplay.h"

static unsigned pdx_usb_worker_state;
static unsigned pdx_usb_reset_event;
static struct pdx_usb_display pdx_usb_display;
extern int snprintf(char *, size_t, const char *, ...) __printflike(3, 4);
extern int vsnprintf(char *, size_t, const char *, va_list) __printflike(3, 0);

void pdx_usb_reset_wait_ms(void *cookie __unused, uint32_t ms)
{
    uint64_t deadline;
    clock_interval_to_deadline(ms, NSEC_PER_MSEC, &deadline);
    if (assert_wait_deadline((event_t)&pdx_usb_reset_event, THREAD_UNINT, deadline) == THREAD_WAITING)
        thread_block(THREAD_CONTINUE_NULL);
}

/* Retain a visible failure even when the transport itself cannot send it. */
void boot_progress_persist(const char *text, uint32_t row __unused)
{
    if (!text) return;
    (void)pdx_usb_display_set(&pdx_usb_display, 0, text);
    size_t length = 0;
    while (length < 384 && text[length]) ++length;
    (void)qcom_usb_debug_enqueue(text, length);
    (void)qcom_usb_debug_enqueue("\n", 1);
}

int pdx_usb_screen_snapshot(char out[PDX_USB_ROWS][PDX_USB_COLS])
{
    return pdx_usb_display_get(&pdx_usb_display, out);
}

static void pdx_usb_status_rows(void)
{
    struct qcom_usb_debug_status s = {0};
    char text[PDX_USB_COLS];
    qcom_usb_debug_get_status(&s); /* Boot CPU, outside the USB guard. */
    snprintf(text, sizeof text, "USB phase=%u err=%u core=%d qcom=%u domain=%u/%u bank=%u slot=%u poll=%u pending=%llu",
             s.phase,s.error,s.core_result,s.qcom_result,s.domain_result,s.domain_stage,
             s.domain_bank,s.domain_slot,s.poll_calls,s.buffer_pending);
    (void)pdx_usb_display_set(&pdx_usb_display, 1, text);
    snprintf(text, sizeof text, "USB reset ID=%x VER=%x GCTL=%x DCTL=%x DSTS=%x tr=%u:%x/%x io=%u PHY=%x VBUS=%x",
             s.init_regs[0],s.init_regs[12],s.init_regs[3],s.init_regs[4],s.init_regs[5],
             s.last_trace,s.trace_a,s.trace_b,s.init_io_failed,s.phy_saved,s.vbus_saved);
    (void)pdx_usb_display_set(&pdx_usb_display, 2, text);
}

static void pdx_usb_worker(void *arg __unused, wait_result_t result __unused)
{
    processor_t processor = master_processor;
    struct qcom_usb_debug_status status;
    if (processor == PROCESSOR_NULL) goto done;
    thread_bind(processor);
    thread_block(THREAD_CONTINUE_NULL);
    if (cpu_number() != processor->cpu_id) goto done;
    (void)qcom_usb_debug_init();
    pdx_usb_status_rows();
    qcom_usb_debug_get_status(&status);
    printf("PDX USB phase=%u error=%u qcom=%u domain=%u stage=%u bank=%u slot=%u\n",
           status.phase, status.error, status.qcom_result, status.domain_result,
           status.domain_stage, status.domain_bank, status.domain_slot);
    if (status.phase != QCOM_USB_DEBUG_ACTIVE) goto done;
    pdx_usb_worker_state = 2;
    unsigned round = 0;
    for (;;) {
        uint64_t deadline;
        qcom_usb_debug_poll();
        if (++round == 200) { round = 0; pdx_usb_status_rows(); }
        clock_interval_to_deadline(5, NSEC_PER_MSEC, &deadline);
        if (assert_wait_deadline((event_t)&pdx_usb_worker_state, THREAD_UNINT, deadline) == THREAD_WAITING)
            thread_block(THREAD_CONTINUE_NULL);
    }
done:
    pdx_usb_worker_state = 3;
    thread_bind(PROCESSOR_NULL);
    thread_terminate_self();
}

void pdx_usb_start_worker(void)
{
    int enabled = 0;
    thread_t thread = THREAD_NULL;
    if (!PE_parse_boot_argn("qcom-usb-debug", &enabled, sizeof(enabled)) || enabled != 1) return;
    if (pdx_usb_worker_state) return;
    pdx_usb_worker_state = 1;
    (void)pdx_usb_display_set(&pdx_usb_display, 0, "USB worker requested; waiting for boot CPU initialization");
    if (kernel_thread_start(pdx_usb_worker, NULL, &thread) == KERN_SUCCESS) thread_deallocate(thread);
    else pdx_usb_worker_state = 3;
}

/* The official screen parks at panic entry. Queue the known VFS failure first
 * and drain synchronously, then let the original diagnostic render and park. */
void pdx_usb_panic_log(const char *fmt, ...)
{
    char text[1536];
    va_list args;
    va_start(args, fmt);
    int count = vsnprintf(text, sizeof(text), fmt, args);
    va_end(args);
    if (count > 0) {
        size_t bytes = (size_t)count < sizeof(text) ? (size_t)count : sizeof(text) - 1;
        (void)qcom_usb_debug_enqueue(text, bytes);
        (void)qcom_usb_debug_enqueue("\n", 1);
    }
    qcom_usb_debug_panic_drain();
}
