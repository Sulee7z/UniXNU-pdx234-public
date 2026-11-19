/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef SONY_WCN_POWER_H
#define SONY_WCN_POWER_H
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
enum { SONY_WCN_WLAN, SONY_WCN_BLUETOOTH, SONY_WCN_RAILS = 6 };
struct sony_wcn_rail {
    const char *resource;
    uint32_t microvolts;
    uint16_t phandle;
    uint8_t radios;
};
/* Physical inputs, NOT the on-chip PMU output names in qcom,pmu_vreg_map. */
extern const struct sony_wcn_rail sony_wcn_rails[SONY_WCN_RAILS];
struct sony_wcn_power_ops {
    void *context;
    /* All callbacks and the state below are serialized by the caller's WCN lock.
     * vote must retain the pre-boot vote, return positive errno, and never silently
     * accept a missing resource or an uncompleted RPMh transaction. */
    int (*vote)(void *, unsigned rail, bool on);
    int (*pcie)(void *, bool on);
    int (*sleep_clock)(void *);
};
struct sony_wcn_power {
    unsigned owners, live;
    int cleanup_error;
    bool pcie;
};
int sony_wcn_power_acquire(struct sony_wcn_power *, const struct sony_wcn_power_ops *, unsigned radio);
int sony_wcn_power_release(struct sony_wcn_power *, const struct sony_wcn_power_ops *, unsigned radio);
/* XNU board entry points. Idempotent ownership: one vote per radio, not per call. */
int sony_wcn_power_get(unsigned radio);
int sony_wcn_power_put(unsigned radio);
unsigned sony_wcn_power_owners(void);
#ifdef __cplusplus
}
#endif
#endif
