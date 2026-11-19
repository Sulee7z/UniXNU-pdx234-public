// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include "Display069.h"
#ifdef __cplusplus
extern "C" {
#endif
D69Display *native_sony_display069_instance(void);
void native_sony_display069_start_backlight(void);
void native_sony_display069_notify_refresh(void);
int native_sony_display069_request(uint32_t level);
void native_sony_display069_power(unsigned ordinal);
void native_sony_display069_set_refresh_sink(void (*)(void *),void *);
#ifdef __cplusplus
}
#endif
