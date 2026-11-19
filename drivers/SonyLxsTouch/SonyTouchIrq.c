/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include "SonyTouchIrq.h"
int sony_touch_irq_prepare(const SonyGeniIo *se,const SonyTouchIrqOps *ops,
                           void (*handler)(void *),SonyTouchIrqState *state) {
    if(!se || !se->write || !ops || !ops->attach || !ops->mask || !handler || !state)return -1;
    *state=(SonyTouchIrqState){0};
    state->attach_result=state->mask_result=-1;
    se->write(se->context,0xe1c,0); /* quiet peripheral during registration */
    se->write(se->context,0xe18,0); /* GSI events are not this backend */
    state->attach_result=ops->attach(SONY_TOUCH_ENGINE_INTID,0,handler,0,&state->readback,&state->router);
    if(state->attach_result)return state->attach_result;
    state->registered=1;
    state->mask_result=ops->mask(SONY_TOUCH_ENGINE_INTID,1);
    if(state->mask_result)return state->mask_result;
    state->masked=1;
    return 0;
}
