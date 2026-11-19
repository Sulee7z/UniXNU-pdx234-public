// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

enum SonyDsiResult {
    SonyDsiOK = 0, SonyDsiPending = 1, SonyDsiBusy = 2,
    SonyDsiUnqualified = -1, SonyDsiArgument = -2, SonyDsiInheritedState = -3,
    SonyDsiTimeout = -4, SonyDsiControllerError = -5, SonyDsiResponse = -6,
    SonyDsiMismatch = -7, SonyDsiPoisoned = -8, SonyDsiOwnershipLost = -9
};
enum SonyDsiRegister {
    SonyDsiVersion = 0x000, SonyDsiControl = 0x004, SonyDsiStatus = 0x008,
    SonyDsiFifoStatus = 0x00c, SonyDsiDmaControl = 0x03c,
    SonyDsiDmaLength = 0x04c, SonyDsiStreamTotal = 0x05c,
    SonyDsiAckError = 0x068, SonyDsiReadData = 0x06c,
    SonyDsiTriggerControl = 0x084, SonyDsiTrigger = 0x090,
    SonyDsiPhyError = 0x0b4, SonyDsiTimeoutStatus = 0x0c0,
    SonyDsiDmaSchedule = 0x100, SonyDsiDmaScheduleWindow = 0x104,
    SonyDsiInterrupt = 0x110, SonyDsiClockStatus = 0x120,
    SonyDsiTpgControl = 0x15c, SonyDsiTpgData = 0x17c,
    SonyDsiReadControl = 0x1d4, SonyDsiFifoReset = 0x1ec
};
enum {
    SonyDsiHosts = 2, SonyDsiDeadlineUs = 25000,
    SonyDsiHostBytes = 0x1000,
    // A declaration by the display owner, not a switch supplied by userspace.
    SonyDsiQualifiedHandoff = 1u << 0,
    SonyDsiQualifiedRead52 = 1u << 1,
    SonyDsiQualifiedBroadcast = 1u << 2,
    SonyDsiQualifiedSdrHmdOff = 1u << 3,
    SonyDsiQualificationAll = 15
};
#define SONY_DSI0_BASE UINT64_C(0x0ae94000)
#define SONY_DSI1_BASE UINT64_C(0x0ae96000)

typedef struct SonyDsiIo {
    void *context;
    uint32_t (*read)(void *, unsigned host, uint32_t reg);
    void (*write)(void *, unsigned host, uint32_t reg, uint32_t value);
    void (*delay_us)(void *, uint32_t us);
    // acquire returns 0 only after pinning rails/clocks, exiting ULPS, stopping
    // MDP command submission and excluding ALL other DSI command users/ISRs. A busy
    // return must not leave any resources acquired. No MMIO is touched on busy.
    int (*acquire)(void *, uint64_t *epoch);
    bool (*owned)(void *, uint64_t epoch);
    // A poisoned transaction retains the lease until the display owner recovers
    // the hosts; the engine never resets the whole DSI/PHY to hide a timeout.
    void (*release)(void *, uint64_t epoch);
} SonyDsiIo;

typedef struct SonyDsiQualification {
    uint32_t flags;
    uint32_t version[SonyDsiHosts];
    uint32_t stream_total[SonyDsiHosts];
    unsigned master;
    bool use_lpm;
} SonyDsiQualification;

typedef struct SonyDsi {
    SonyDsiIo io;
    SonyDsiQualification qualification;
    uint64_t epoch, deadline;
    uint32_t saved_dma[2], saved_length[2], saved_trigger[2], saved_tpg[2], saved_int_mask[2];
    uint32_t interrupt[2], errors[2];
    uint16_t requested, observed[2];
    uint8_t state, read_host;
    bool initialized, leased, poisoned, writing;
    uint32_t completed, timeouts, failures;
    int last_error;
} SonyDsi;

// Every deadline/now parameter uses monotonic microseconds. The caller runs the
// state machine on one work loop; acquire/owned excludes external command users.
int sony_dsi_init(SonyDsi *, const SonyDsiIo *, const SonyDsiQualification *);
int sony_dsi_start_read(SonyDsi *, uint64_t now_us);
int sony_dsi_start_write(SonyDsi *, uint16_t dbv, uint64_t now_us);
int sony_dsi_step(SonyDsi *, uint64_t now_us);
bool sony_dsi_busy(const SonyDsi *);
// MSM embedded command format, not on-wire DSI header/ECC.
void sony_dsi_packet51(uint16_t dbv, uint32_t words[2]);
void sony_dsi_packet52(uint32_t words[2]);
uint8_t sony_dsi_header_ecc(uint8_t type, uint8_t data0, uint8_t data1);
#ifdef __cplusplus
}
#endif
