// SPDX-License-Identifier: BSD-2-Clause-Patent
#ifndef SONY_TOUCH_BOOST069_H
#define SONY_TOUCH_BOOST069_H
#include "SonyGovernor069.h"
extern "C" {
extern volatile uint32_t native_touch_seq __attribute__((weak_import));
extern volatile uint32_t native_touch_count __attribute__((weak_import));
}
// The sampler state is owned by the sole CPU/GPU governor thread, on its own
// stack. No unsynchronized mutable per-translation-unit global state is shared
// by duplicate initialization callers or by a future recorder.
static inline uint32_t sony069_touch_sequence(Sony069TouchSample &sample) {
    if(!&native_touch_seq || !&native_touch_count)return sample.pulse;
    const uint32_t first=__atomic_load_n(&native_touch_seq,__ATOMIC_ACQUIRE);
    const uint32_t count=__atomic_load_n(&native_touch_count,__ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    const uint32_t last=__atomic_load_n(&native_touch_seq,__ATOMIC_ACQUIRE);
    return sample.observe(first,count,last);
}
#endif
