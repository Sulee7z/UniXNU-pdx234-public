/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#pragma once
#include "ArmSmmu4K.h"
#ifdef __cplusplus
extern "C" {
#endif
#define SONY_WIFI_DMA_IOVA UINT64_C(0x10000000)
#define SONY_WIFI_DMA_BYTES (128u*1024u*1024u)
#define SONY_WIFI_MSI_IOVA UINT64_C(0x1fff0000)
#define SONY_WIFI_MSI_PAGE UINT64_C(0x17150000)
#define SONY_WIFI_MSI_OFFSET 0x40u
#define SONY_WIFI_DMA_LEAVES (SONY_WIFI_DMA_BYTES/4096u+1u)
#define SONY_WIFI_DMA_TABLE_PAGES 67u
/* The official builder retains its normal-memory ABI. This board adapter
 * validates its exact MSI leaf, then selects MAIR index2 (Device-nGnRnE=0).
 * Indices0/1 and every RAM leaf retain the original NC/WB encodings. */
ArmSmmu4KStatus sony_wifi_dma_build(uint64_t physical,uint64_t table_physical,
    unsigned output_bits,uint64_t *tables,size_t capacity,ArmSmmu4KResult *result);
#ifdef __cplusplus
}
#endif
