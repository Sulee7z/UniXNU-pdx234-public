/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef SONY_TOUCH_IRQ_H
#define SONY_TOUCH_IRQ_H
#include <stdint.h>
#include "GeniI2c.h"
#ifdef __cplusplus
extern "C" {
#endif
#define SONY_TOUCH_ENGINE_INTID (32u+357u)
typedef struct {
    int (*attach)(uint32_t,int,void (*)(void *),void *,uint32_t *,uint64_t *);
    int (*mask)(uint32_t,int);
} SonyTouchIrqOps;
typedef struct {
    int attach_result, mask_result;
    uint32_t registered, masked, readback;
    uint64_t router;
} SonyTouchIrqState;
/* Attach publishes the route before enabling its GIC line. Disable peripheral
 * sources before attach; the permanent handler never owns a transient Session.
 * Caller may enable GENI's polled status gates only after this succeeds. */
int sony_touch_irq_prepare(const SonyGeniIo *,const SonyTouchIrqOps *,
                           void (*handler)(void *),SonyTouchIrqState *);
#ifdef __cplusplus
}
#endif
#endif
