// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include "SonyDsi.h"
#ifdef __cplusplus
extern "C" {
#endif
// Called once by the display owner AFTER qualification. Callbacks/context must
// live for the whole boot. Never pass stack storage or claim qualification from
// Android DT alone. No provider is installed by the 067 staged archive itself.
int native_sony_oled_bind_transport(const SonyDsiIo *, const SonyDsiQualification *);
void native_sony_oled_backlight_probe(void);
extern volatile int32_t native_sony_oled_stats[24];
extern volatile int32_t native_sony_oled_request[6];
#ifdef __cplusplus
}
#endif
