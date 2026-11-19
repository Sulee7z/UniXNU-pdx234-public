/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Called from one real QMI capability response before board-data request.
 * qmi board ID is never inferred from filenamee31 or WMI boardid0. */
int sony069_wifi_qmi_identity(uint32_t chip_id,uint32_t board_id,uint32_t soc_id);
/* The locked Ath12k core supplies primary and fallback names before API2. */
int sony069_wifi_board_key(unsigned kind,const char *key);
int sony069_wifi_board2(const uint8_t **data,size_t *length);
#ifdef __cplusplus
}
#endif
