/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
enum sony_shared_client {
    SONY_SHARED_WCN = 0, SONY_SHARED_DISPLAY = 1, SONY_SHARED_TOUCH = 2,
    SONY_SHARED_UFS = 3, SONY_SHARED_GPU = 4, SONY_SHARED_AUDIO = 5,
    SONY_SHARED_USB = 6, SONY_SHARED_CLIENTS = 8
};
/* Positive errno. Idempotent per client/resource. Mode is hardware VRM mode
 * (7 HPM, not Linux regulator-mode enum). Voltage is microvolts. cmd-db names
 * must resolve and be described by the captured Sony resource catalog.
 * Last release restores the exact boot AP vote read through RPMh, not zero.
 * Errors are not turned into a success vote; uncertain transactions poison
 * that TCS/resource and pin its ownership for diagnosis/recovery. */
int sony_shared_vote(unsigned client, const char *resource, unsigned mode,
                     unsigned microvolts, bool enabled);
/* BCM units are kB/s, as Linux icc units. Aggregate average=sum, peak=max.
 * Width/unit/vcd must be present in cmd-db BCM aux data. */
int sony_shared_bcm_vote(unsigned client, const char *resource,
                         uint64_t average_kbps, uint64_t peak_kbps);
/* ARC corner units are resolved through that exact cmd-db resource's aux
 * table. Missing/out-of-range corners fail before any vote is issued. */
int sony_shared_arc_vote(unsigned client,const char *resource,unsigned corner,bool enabled);
int sony_shared_gcc_update(uint32_t offset, uint32_t clear, uint32_t set);
/* Global worker-context configuration mutex for GCC/RPMh/SPMI/SMMU ownership.
 * Main must route touch/UFS configuration through these functions. A second
 * local config lock does not compose. No IRQ callback acquires this mutex. */
int sony_shared_config_lock(void);
void sony_shared_config_unlock(void);
/* Initializes mappings, generated Sony resource catalog, live RSC geometry and
 * clock baseline. No prior hardware-success certificate is required. */
int native_sony_shared_resources_init(void);
/* Installs real callbacks into frozen SonyWcnPlatform and publishes the BT
 * address/IOService with its errno checked. Call before starting userland. */
int native_sony_radio_platform069_init(void);
/* ArmCpu adapter invokes this before distributor handling, for INTID>=8192. */
bool sony_radio_lpi_dispatch(uint32_t intid);
int sony_radio_bluetooth_dma(uint64_t physical, uint32_t bytes,
                             unsigned *slot, unsigned *bank);
#ifdef __cplusplus
}
#endif
