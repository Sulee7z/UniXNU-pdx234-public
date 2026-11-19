// SPDX-License-Identifier: BSD-2-Clause-Patent
#ifndef PDX_PERFORMANCE_TOUCH_H
#define PDX_PERFORMANCE_TOUCH_H
#include <stdint.h>

// Sony emits valid zero-contact scans too. Those must not keep the official
// one-second CPU/GPU touch boost alive. Read only the existing sequence/count
// snapshot; this neither changes the transport nor submits a HID report.
extern "C" {
extern volatile uint32_t native_touch_seq __attribute__((weak_import));
extern volatile uint32_t native_touch_count __attribute__((weak_import));
}
struct PdxPerformanceTouchState {
    uint32_t seen = 0, contacts = 0, pulse = 0;
    uint32_t observe(uint32_t before, uint32_t count, uint32_t after) {
        if ((before & 1u) || before != after || before == seen) return pulse;
        seen = before;
        if (count || contacts) ++pulse; // down, move, and the last contact's up
        contacts = count;
        return pulse;
    }
};
static PdxPerformanceTouchState gPdxPerformanceTouch;
static inline uint32_t pdx_performance_touch_sequence() {
    if (!&native_touch_seq || !&native_touch_count) return 0;
    const uint32_t before = __atomic_load_n(&native_touch_seq, __ATOMIC_ACQUIRE);
    const uint32_t count = __atomic_load_n(&native_touch_count, __ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    const uint32_t after = __atomic_load_n(&native_touch_seq, __ATOMIC_ACQUIRE);
    return gPdxPerformanceTouch.observe(before, count, after);
}
#endif
