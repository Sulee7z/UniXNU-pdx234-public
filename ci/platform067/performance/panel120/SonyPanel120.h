// SPDX-License-Identifier: BSD-2-Clause-Patent
#ifndef SONY_PANEL120_H
#define SONY_PANEL120_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

// Pure preflight/plan ABI. This archive has NO MMIO/backend, boot hook or
// transmitter and cannot change refresh. A future single display owner supplies
// snapshots from the inherited hardware while holding its exclusive lease.
typedef struct SonyPanelModeFacts {
    uint32_t id, width_per_link, height, hz, bit_clock_hz, mdp_transfer_us;
    uint16_t h_front, h_pulse, h_back, v_front, v_pulse, v_back;
    uint16_t slice_width, slice_height, bits_per_component, bits_per_pixel;
    uint8_t links, encoders, slices_per_packet, block_prediction;
    uint8_t phy[14];
} SonyPanelModeFacts;
enum SonyPanel120Status {
    SonyPanel120PlanReady=0, SonyPanel120Disabled=1, SonyPanel120AlreadyRequestedMode=2,
    SonyPanel120Sample120=3,
    SonyPanel120Argument=-1, SonyPanel120UnknownInheritedMode=-2,
    SonyPanel120UnqualifiedOwner=-3, SonyPanel120IncompatibleMode=-4,
    SonyPanel120Unmeasured=-5, SonyPanel120Not120=-6
};
enum SonyPanel120Qualification {
    SonyPanel120PanelIdentified=1u<<0,
    SonyPanel120HostVersionsVerified=1u<<1,
    SonyPanel120ClockAndPhyReadback=1u<<2,
    SonyPanel120DscAndStreamsReadback=1u<<3,
    SonyPanel120ActiveMdpRouteReadback=1u<<4,
    SonyPanel120ExclusiveLease=1u<<5,
    SonyPanel120AllDmaQuiesced=1u<<6,
    SonyPanel120HsBroadcastQualified=1u<<7,
    SonyPanel120ExternalTeQualified=1u<<8,
    SonyPanel120SdrHmdOffVerified=1u<<9,
    SonyPanel120MdpBudgetBackend=1u<<10,
    SonyPanel120RequiredQualification=(1u<<11)-1
};
typedef struct SonyPanel120Snapshot {
    uint64_t owner_epoch;
    uint32_t qualification;
    uint32_t current_mode; // 0..3 only AFTER hardware readback, never inferred from GOP dimensions
    uint32_t gop_width, gop_height;
    uint32_t bit_clock_hz[2];
    uint32_t mdp_transfer_us;
    uint32_t reserved;
} SonyPanel120Snapshot;
typedef struct SonyPanel120Plan {
    uint64_t owner_epoch;
    uint32_t from_mode, to_mode, target_hz, mdp_transfer_us;
    const uint8_t *hs_switch;
    size_t hs_switch_bytes;
    uint32_t packet_count;
    uint8_t preserve_bit_clock, preserve_phy, preserve_dsc_and_pps, update_mdp_budget;
    uint8_t host_timing_update_required, synchronized_dual_host, external_te_proof_required, executable_backend_bound;
} SonyPanel120Plan;
// Explicit request and a complete owner qualification are required even for a
// plan. Only same-resolution 60->120 is supported. No state or registers change.
int native_sony_panel120_prepare(const SonyPanel120Snapshot *,unsigned request120,SonyPanel120Plan *);
const SonyPanelModeFacts *sony_panel120_mode(unsigned id);

// A transport completion and software vblank are NOT refresh proof. A future
// owner provides timestamps/counts from its identified EXTERNAL panel TE source
// on BOTH links, collected after the batch and MDP update completed.
typedef struct SonyPanel120TeSample {
    uint64_t owner_epoch, elapsed_us;
    uint32_t external_te_events[2], min_period_us[2], max_period_us[2];
    uint8_t external_source_verified, batch_completed_both, mdp_budget_verified, no_host_errors;
} SonyPanel120TeSample;
int sony_panel120_verify_external_te(const SonyPanel120Plan *,const SonyPanel120TeSample *);
#ifdef __cplusplus
}
#endif
#endif
