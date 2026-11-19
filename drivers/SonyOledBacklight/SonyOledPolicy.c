// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "SonyOledPolicy.h"

uint32_t sony_oled_level_for_nits(int32_t fixed) {
    if (fixed <= 0) return 0;
    const uint64_t scale = (uint64_t)SONY_OLED_NOMINAL_MAX << 16;
    const uint64_t level = ((uint64_t)fixed * SONY_OLED_MAX_LEVEL + scale / 2) / scale;
    return level < 1 ? 1 : level > SONY_OLED_MAX_LEVEL ? SONY_OLED_MAX_LEVEL : (uint32_t)level;
}

uint32_t sony_oled_fade_ms(uint32_t fixed_seconds) {
    const uint64_t ms = ((uint64_t)fixed_seconds * 1000) >> 16;
    return ms > SONY_OLED_FADE_MS ? SONY_OLED_FADE_MS : (uint32_t)ms;
}

uint32_t sony_oled_fade_level(uint32_t from, uint32_t to, uint64_t elapsed_ms, uint32_t period_ms) {
    if (from > SONY_OLED_MAX_LEVEL) from = SONY_OLED_MAX_LEVEL;
    if (to > SONY_OLED_MAX_LEVEL) to = SONY_OLED_MAX_LEVEL;
    if (!period_ms || elapsed_ms >= period_ms) return to;
    return (uint32_t)((int64_t)from + ((int64_t)to - from) * (int64_t)elapsed_ms / period_ms);
}

uint16_t sony_oled_sdr_dbv(uint32_t level) {
    if (!level) return 0;
    if (level > SONY_OLED_MAX_LEVEL) level = SONY_OLED_MAX_LEVEL;
    // Scale the OS range to Sony's lower-segment input range, then apply type1's
    // HMD_OFF <=1720 branch. Integer division follows the vendor formula.
    const uint32_t input = (level * SONY_OLED_SDR_MAX_INPUT + SONY_OLED_MAX_LEVEL / 2) / SONY_OLED_MAX_LEVEL;
    if (input <= 9) return 4;
    return (uint16_t)(4 + (input - 9) * (SONY_OLED_SDR_MAX_DBV - 4) / (SONY_OLED_SDR_MAX_INPUT - 9));
}

void sony_oled_encode_dbv(uint16_t dbv, uint8_t bytes[3]) {
    bytes[0] = 0x51;
    bytes[1] = (uint8_t)(dbv >> 8);
    bytes[2] = (uint8_t)dbv;
}

bool sony_oled_decode_dbv(const uint8_t bytes[2], uint16_t *dbv) {
    if (!bytes || !dbv) return false;
    const uint16_t value = (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
    if (value > SONY_OLED_MAX_LEVEL) return false;
    *dbv = value;
    return true;
}
