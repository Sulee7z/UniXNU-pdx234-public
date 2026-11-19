/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#pragma once
#include <stdint.h>
#define SONY_ITS_VECTOR_COUNT 32u
#define SONY_ITS_LPI_BASE 8192u
#define SONY_ITS_DEVICE_ID 0x1401u
#define SONY_ITS_EVENT_BITS 5u
#define SONY_ITS_COLLECTION_ID 0u
#define SONY_ITS_PAGE_BYTES 65536u
#define SONY_ITS_PAGE_4K 4096u
#define SONY_ITS_PAGE_16K 16384u
#define SONY_ITS_PAGE_64K 65536u
#define SONY_ITS_QUEUE_BYTES 65536u
#define SONY_ITS_TABLE_BYTES_MAX (256u*SONY_ITS_PAGE_BYTES)
#define SONY_ITS_DEVICE_TABLE_BYTES 65536u
#define SONY_ITS_COLLECTION_TABLE_BYTES 65536u
#define SONY_ITS_PROPERTY_TABLE_BYTES 65536u
#define SONY_ITS_PENDING_TABLE_BYTES 65536u
#define SONY_ITS_REDIST_STRIDE 0x40000u
#define SONY_ITS_READER_OFFSET_MASK 0x000fffe0u
#define SONY_ITS_WRITER_OFFSET_MASK 0x000fffe0u
#define SONY_ITS_TABLE_PA_MASK 0x0000fffffffff000ULL
#define SONY_ITS_CBASER_PA_MASK 0x000ffffffffff000ULL
#define SONY_ITS_BASER_PA_MASK_64K 0x0000fffffffff000ULL
/* GITS_BASER[47:12] stores the address; with 64 KiB pages, bits [15:12]
 * carry physical address bits [51:48] and are part of the owner key. */
#define SONY_ITS_BASER_OWNER_MASK ((1ULL<<63)|SONY_ITS_BASER_PA_MASK_64K)
#define SONY_ITS_COLLECTION_ID_BITS 16u
#define SONY_ITS_GICR_CTLR_ENABLE_LPIS (1u<<0)
#define SONY_ITS_GICR_CTLR_RWP (1u<<3)
#define SONY_ITS_GICR_TYPER_PLPIS (1ULL<<0)
#define SONY_ITS_GICR_TYPER_VLPIS (1ULL<<1)
#define SONY_ITS_GICR_TYPER_LAST (1ULL<<4)
#define SONY_ITS_GICR_PWRR_OFF (3u<<2)
#define SONY_ITS_GICR_WAKER_SLEEP (1u<<1)
#define SONY_ITS_GICR_WAKER_CHILDREN_ASLEEP (1u<<2)
#define SONY_ITS_GICD_TYPER_LPIS (1u<<17)
#define SONY_ITS_GICD_TYPER_IDBITS_SHIFT 19u
#define SONY_ITS_GICD_TYPER_NUM_LPIS_SHIFT 11u
#define SONY_ITS_GICD_TYPER_NUM_LPIS_MASK (31u<<SONY_ITS_GICD_TYPER_NUM_LPIS_SHIFT)
#define SONY_ITS_GITS_TYPER_PTA (1ULL<<19)
#define SONY_ITS_GITS_TYPER_DEVBITS_SHIFT 13u
#define SONY_ITS_GITS_TYPER_IDBITS_SHIFT 8u
#define SONY_ITS_GITS_TYPER_ITT_ENTRY_SHIFT 4u
#define SONY_ITS_GITS_TYPER_HCC_SHIFT 24u
#define SONY_ITS_GITS_BASER_TYPE_DEVICE 1u
#define SONY_ITS_GITS_BASER_TYPE_COLLECTION 4u
#define SONY_ITS_GITS_BASER_INNER_NC (1ULL<<59)
#define SONY_ITS_GITS_BASER_PAGE_SIZE_SHIFT 8u
#define SONY_ITS_GITS_BASER_PAGE_SIZE_MASK (3ULL<<SONY_ITS_GITS_BASER_PAGE_SIZE_SHIFT)
#define SONY_ITS_GITS_BASER_PAGE_SIZE_4K (0ULL<<SONY_ITS_GITS_BASER_PAGE_SIZE_SHIFT)
#define SONY_ITS_GITS_BASER_PAGE_SIZE_16K (1ULL<<SONY_ITS_GITS_BASER_PAGE_SIZE_SHIFT)
#define SONY_ITS_GITS_BASER_PAGE_SIZE_64K (2ULL<<SONY_ITS_GITS_BASER_PAGE_SIZE_SHIFT)
#define SONY_ITS_GITS_BASER_VALID (1ULL<<63)
#define SONY_ITS_GITS_BASER_INDIRECT (1ULL<<62)
#define SONY_ITS_GITS_BASER_TYPE_MASK (7ULL<<56)
#define SONY_ITS_GITS_BASER_ENTRY_MASK (31ULL<<48)
#define SONY_ITS_GITS_BASER_SHARE_IS (1ULL<<10)
#define SONY_ITS_GITS_CBASER_VALID (1ULL<<63)
#define SONY_ITS_GITS_CBASER_SHARE_IS (1ULL<<10)
#define SONY_ITS_GICR_BASER_SHARE_IS (1ULL<<10)
#define SONY_ITS_GICR_BASER_INNER_NC (1ULL<<7)
#define SONY_ITS_GICR_PENDBASER_PTZ (1ULL<<62)
#define SONY_ITS_GITS_CMD_MAPD 0x08u
#define SONY_ITS_GITS_CMD_MAPC 0x09u
#define SONY_ITS_GITS_CMD_MAPTI 0x0au
#define SONY_ITS_GITS_CMD_INV 0x0cu
#define SONY_ITS_GITS_CMD_SYNC 0x05u
/* Architecturally defined GICv3 register fields exercised by the host tests. */
#define SONY_ITS_BASER_READBACK_MASK ((1ULL<<63)|(1ULL<<62)|(7ULL<<59)|(7ULL<<56)|(7ULL<<53)|(31ULL<<48)|(0x0000fffffffff000ULL)|(3ULL<<10)|(3ULL<<8)|0xffULL)
/* CBASER[52] is RES0; address bits are [51:12]. */
#define SONY_ITS_CBASER_READBACK_MASK ((1ULL<<63)|(1ULL<<62)|(7ULL<<59)|(7ULL<<56)|(1ULL<<52)|(SONY_ITS_CBASER_PA_MASK)|(3ULL<<10)|(3ULL<<8)|0xffULL)
#define SONY_ITS_PROPBASER_READBACK_MASK ((0x1fULL<<59)|(7ULL<<56)|(0xfULL<<52)|(0x000ffffffffff000ULL)|(3ULL<<10)|(7ULL<<7)|(3ULL<<5)|31ULL)
#define SONY_ITS_PENDBASER_READBACK_MASK ((1ULL<<63)|(7ULL<<59)|(7ULL<<56)|(0xfULL<<52)|(0x000fffffffff0000ULL)|(0xfULL<<12)|(3ULL<<10)|(7ULL<<7)|0x7fULL)
#ifdef __cplusplus
extern "C" {
#endif
struct sony_its_command {uint64_t word[4];};
int sony_its_register_matches(uint64_t actual,uint64_t expected,uint64_t mask);
int sony_its_baser_has_owner(uint64_t value);
int sony_its_baser_bytes(unsigned type,unsigned entry_bytes,uint32_t *bytes);
int sony_its_baser_bytes_for_page(unsigned type,unsigned entry_bytes,unsigned page_bytes,uint32_t *bytes);
int sony_its_baser_type_layout_valid(const uint64_t baser[8]);
int sony_its_gicd_supports_lpis(uint32_t typer);
unsigned sony_its_gicd_id_bits(uint32_t typer);
uint64_t sony_its_gicd_lpi_count(uint32_t typer);
unsigned sony_its_gits_device_id_bits(uint64_t typer);
unsigned sony_its_gits_event_id_bits(uint64_t typer);
unsigned sony_its_gits_itt_entry_bytes(uint64_t typer);
int sony_its_gits_typers_supported(uint64_t typer,uint32_t gicd_typer);
uint64_t sony_its_baser_pagesize_value(uint64_t before,unsigned page_bytes);
uint64_t sony_its_baser_pa_bits(uint64_t physical,unsigned page_bytes);
uint64_t sony_its_baser_decode_pa(uint64_t value,unsigned page_bytes);
int sony_its_device_table_bytes(unsigned device_bits,unsigned entry_bytes,uint32_t *bytes);
int sony_its_device_table_bytes_for_id(unsigned device_id,unsigned entry_bytes,unsigned page_bytes,uint32_t *bytes);
int sony_its_required_table_bytes(unsigned type,unsigned index,unsigned entry_bytes,unsigned page_bytes,uint32_t *bytes);
int sony_its_queue_reader_valid(uint64_t reader,uint32_t writer,uint32_t queue_bytes);
int sony_its_queue_writer_valid(uint64_t writer,uint32_t queue_bytes);
unsigned sony_its_init_state_after_failure(unsigned current,int programmed,int error);
int sony_its_init_claim(volatile uint32_t *state,volatile uint32_t *error,uint32_t *saved_error);
void sony_its_init_finish(volatile uint32_t *state,volatile uint32_t *error,int programmed,int failure);
int sony_its_callback_can_publish(int callback_present,int same_owner);
uint64_t sony_its_baser_value(uint64_t before,uint64_t physical,uint32_t bytes);
uint64_t sony_its_baser_value_for_page(uint64_t before,uint64_t physical,uint32_t bytes,unsigned page_bytes);
uint64_t sony_its_cbaser_value(uint64_t physical,uint32_t bytes);
uint64_t sony_its_propertybaser_value(uint64_t physical,unsigned id_bits);
uint64_t sony_its_pendingbaser_value(uint64_t physical);
uint32_t sony_its_redist_stride(uint64_t typer);
uint32_t sony_its_mpidr_affinity(uint32_t boot_mpidr_low);
int sony_its_redists_may_share_properties(uint64_t first,uint64_t second);
void sony_its_mapd(struct sony_its_command *,uint32_t device,uint64_t itt,unsigned event_bits);
void sony_its_mapc(struct sony_its_command *,uint16_t collection,uint64_t target);
void sony_its_mapti(struct sony_its_command *,uint32_t device,uint32_t event,uint32_t lpi,uint16_t collection);
void sony_its_inv(struct sony_its_command *,uint32_t device,uint32_t event);
void sony_its_sync(struct sony_its_command *,uint64_t target);
#ifdef __cplusplus
}
#endif
