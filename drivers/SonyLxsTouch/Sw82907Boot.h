/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef SONY_SW82907_BOOT_H
#define SONY_SW82907_BOOT_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
enum {Sw82907BootOk=0,Sw82907BootSkip=1,Sw82907BootCrcError=-1};
/* Sony lxs_hal_chk_boot_result: reset/busy values are not a CRC verdict.
 * The SW82907 OLED policy has no empty-image or configuration-CRC mask. */
int sw82907_boot_result(uint32_t status);
int sw82907_code_crc_result(uint32_t status);
int sw82907_version_supported(uint32_t version);
#ifdef __cplusplus
}
#endif
#endif
