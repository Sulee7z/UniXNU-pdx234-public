// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include "../SonyDsi.h"
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

enum SonyOwnerResult {
    SonyOwnerOK=0, SonyOwnerBusy=2, SonyOwnerNoPhysicalAccess=-100,
    SonyOwnerStopped=-101, SonyOwnerBadSnapshot=-102, SonyOwnerChanged=-103,
    SonyOwnerIrqEnabled=-104, SonyOwnerAutoRefresh=-105, SonyOwnerClock=-106,
    SonyOwnerUlps=-107, SonyOwnerPoisoned=-108, SonyOwnerArgument=-109
};
enum SonyOwnerField {
    OwnerVersion, OwnerControl, OwnerStatus, OwnerFifo, OwnerDmaControl,
    OwnerStreamTotal, OwnerAckError, OwnerTriggerControl, OwnerLaneStatus,
    OwnerLaneControl, OwnerPhyError, OwnerTimeout, OwnerSchedule, OwnerWindow,
    OwnerInterrupt, OwnerClockControl, OwnerClockStatus, OwnerTpg,
    OwnerPhyReset, OwnerSoftReset, OwnerReadDisable, OwnerSecure,
    OwnerFieldCount
};
typedef struct SonyDisplaySnapshot {
    uint32_t host[2][OwnerFieldCount];
    uint32_t autorefresh[2];
    uint32_t mdss_interrupt;
} SonyDisplaySnapshot;

// These operations must be implemented by the real supply/clock owner. The
// library has NO always-success implementation. Logical IOMFB powered=1 is not
// a substitute for try_hold, and a userspace boot argument cannot supply it.
typedef struct SonyDisplayPhysicalAccess {
    void *context;
    int (*try_hold)(void *, uint64_t *token);
    bool (*held)(void *, uint64_t token);
    void (*drop)(void *, uint64_t token);
    // Only reads exact documented controller/INTF/MDSS registers. Invoked only
    // while held(token); mapping must already belong to that physical owner.
    bool (*snapshot)(void *, SonyDisplaySnapshot *);
} SonyDisplayPhysicalAccess;

typedef struct SonyDisplayCommandOwner {
    SonyDisplayPhysicalAccess access;
    SonyDisplaySnapshot inherited;
    uint64_t token, generation;
    // gate0 stopped,1 running,2 draining,3 command,4 poisoned. users protects
    // presenter/mode/power producers against a command acquisition race.
    uint32_t gate, users, initialized;
    int last_error;
} SonyDisplayCommandOwner;

uint32_t sony_display_owner_host_register(unsigned field);
// Validates real snapshots, not a claimed qualification bit. No MMIO writes.
int sony_display_owner_snapshot_check(const SonyDisplaySnapshot *);
int sony_display_owner_init(SonyDisplayCommandOwner *, const SonyDisplayPhysicalAccess *);
int sony_display_owner_start(SonyDisplayCommandOwner *);
// Main must bracket ALL DPU commit/mode/power/stop/IRQ-ack producers using the
// same owner. CPU/GPU writes to already-owned framebuffer memory need not stop.
int sony_display_owner_producer_enter(SonyDisplayCommandOwner *);
void sony_display_owner_producer_leave(SonyDisplayCommandOwner *);
int sony_display_owner_stop(SonyDisplayCommandOwner *);
// SonyDsiIo-compatible callbacks. Polling-only: every host INT_CTRL enable bit
// must already be zero. This code NEVER disables GIC or DSI interrupt checks.
int sony_display_command_acquire(void *, uint64_t *epoch);
bool sony_display_command_owned(void *, uint64_t epoch);
void sony_display_command_release(void *, uint64_t epoch);
// Caller on transport fault pins the lease; no automatic reset/re-enable.
void sony_display_command_poison(SonyDisplayCommandOwner *);
#ifdef __cplusplus
}
#endif
