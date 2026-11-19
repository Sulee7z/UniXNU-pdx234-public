// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
enum { SONY_OLED_MAX_LEVEL = 4095, SONY_OLED_SDR_MAX_DBV = 2047,
       SONY_OLED_SDR_MAX_INPUT = 1720, SONY_OLED_FADE_MS = 5000 };
// Nominal CoreBrightness slider coordinates, NOT measured panel luminance.
enum { SONY_OLED_NOMINAL_MIN = 2, SONY_OLED_NOMINAL_MID = 140,
       SONY_OLED_NOMINAL_MAX = 500 };
uint32_t sony_oled_level_for_nits(int32_t fixed);
uint32_t sony_oled_fade_ms(uint32_t fixed_seconds);
uint32_t sony_oled_fade_level(uint32_t from, uint32_t to, uint64_t elapsed_ms, uint32_t period_ms);
// Sony type1/HMD_OFF lower segment. DBV2048..4095 and all HBM control are
// deliberately unavailable; the segment boundary alone does not prove HBM mode.
uint16_t sony_oled_sdr_dbv(uint32_t level);
void sony_oled_encode_dbv(uint16_t dbv, uint8_t bytes[3]);
bool sony_oled_decode_dbv(const uint8_t bytes[2], uint16_t *dbv);
#ifdef __cplusplus
}
#endif
