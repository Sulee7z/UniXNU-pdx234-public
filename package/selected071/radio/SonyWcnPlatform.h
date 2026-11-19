/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Register once, before either radio starts. Callbacks return positive errno.
 * The platform owner, not this peripheral, arbitrates RPMh/TCS, shared PMIC
 * supplies, sleep clock and PCIe NoC votes with GPU/UFS/audio/USB.
 * on=false drops this WCN client's vote only, never another client's vote.
 * Each callback is transactional: an error leaves the prior client vote intact. */
struct sony_wcn_platform {
    uint32_t version;
    int (*rail_vote)(const char *resource, uint32_t microvolts, bool on);
    int (*pcie_vote)(bool on);
    int (*sleep_clock)(void);
    /* Sony live.dtb PCIe0 MSI uses GICv3 ITS @17140000, endpoint device 0x1401.
     * Register routes and deliver a vector-bit mask; never assume sheng SPI141.
     * The caller and callbacks have boot lifetime (no unload/release yet). */
    int (*wifi_msi_attach)(void (*deliver)(void *, uint32_t vectors), void *);
    int (*wifi_msi_target)(uint32_t *lo, uint32_t *hi, uint32_t *data);
    /* Prepare Sony QUP2 SID0x423 for this exact contiguous range under the real
     * shared SMMU owner (including Sony touch's context ownership). Never change
     * a nonmatching existing stream/bank. Returned slot/bank are diagnostic. */
    int (*bluetooth_dma_prepare)(uint64_t physical, uint32_t bytes, unsigned *slot, unsigned *bank);
    /* Register offsets are relative to Sony GCC @100000. Must serialize with
     * existing GPU/UFS/touch/USB consumers, not just this new radio archive. */
    int (*gcc_update)(uint32_t offset, uint32_t clear, uint32_t set);
    int (*uart14_clock_vote)(bool on);
};
int sony_wcn_platform_install(const struct sony_wcn_platform *);
/* No MMIO, thread, service or ownership change when the provider is absent. */
int sony_wcn_platform_ready(void);
int sony_wcn_platform_wifi_ready(void);
int sony_wcn_platform_bluetooth_ready(void);
int sony_wcn_bluetooth_dma_prepare(uint64_t, uint32_t, unsigned *, unsigned *);
int sony_wcn_gcc_update(uint32_t, uint32_t, uint32_t);
int sony_wcn_uart14_clock_vote(bool);
int sony_wcn_wifi_msi_attach(void (*deliver)(void *, uint32_t), void *);
int sony_wcn_wifi_msi_target(uint32_t *, uint32_t *, uint32_t *);
void native_sony_wifi_start(void);
void native_sony_bluetooth_start(void);
/* Required early for native Bluetooth, before userland startup. */
int native_sony_bluetooth_publish(void);
/* Generated firmware-manifest gates. 0: the exact Sony runtime set was built.
 * Bluetooth also requires the original D27 daemon hash-qualified to the adapter. */
int sony_wcn_wifi_inputs_ready(void);
int sony_wcn_bluetooth_inputs_ready(void);
#ifdef __cplusplus
}
#endif
