/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef SONY_GENI_INIT_H
#define SONY_GENI_INIT_H
#include <stddef.h>
#include <stdint.h>
#include "GeniI2c.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    uint16_t words, word_offset, pairs, index_offset, value_offset;
    uint8_t revision, config_revision;
    uint32_t core_version;
} SonyGeniFirmware;
enum { SonyGeniInitOk=0, SonyGeniInitHeader=-101, SonyGeniInitBusy=-102,
       SonyGeniInitHardware=-103, SonyGeniInitReadback=-104, SonyGeniInitProtocol=-105 };
int sony_geni_firmware_parse(const uint8_t *, size_t, SonyGeniFirmware *);
/* Retain OEM-preloaded I2C firmware. The reference SEFW file is validated for
 * provenance but is never programmed from this non-secure kernel context. */
int sony_geni_firmware_init(const SonyGeniIo *se, const SonyGeniIo *wrapper,
                            const uint8_t *, size_t, unsigned *loaded);
/* TCXO only, verified from the per-engine RCG CFG. No assumed GPLL frequency. */
int sony_geni_tcxo_config(uint32_t cfg);
int sony_geni_tcxo_level(const uint32_t *configs, unsigned count);
#ifdef __cplusplus
}
#endif
#endif
