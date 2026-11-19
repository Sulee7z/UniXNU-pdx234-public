/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
struct sony_cmd_resource {uint32_t address;const uint8_t *aux;size_t aux_bytes;unsigned slave;};
int sony_cmd_db_find(const uint8_t *,size_t,const char *,unsigned,struct sony_cmd_resource *);
int sony_cmd_arc_index(const struct sony_cmd_resource *,uint32_t,uint32_t *);
int sony_cmd_bcm_aux(const struct sony_cmd_resource *,uint32_t *,uint32_t *,uint32_t *);
#ifdef __cplusplus
}
#endif
