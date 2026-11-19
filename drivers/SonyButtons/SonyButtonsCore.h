// SPDX-License-Identifier: BSD-2-Clause-Patent
#ifndef SONY_BUTTONS_CORE_H
#define SONY_BUTTONS_CORE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

enum {
    SONY_BUTTON_POWER = 2, SONY_BUTTON_VOLUME_UP = 4, SONY_BUTTON_VOLUME_DOWN = 8,
    SONY_BUTTON_MASK = 14, SONY_BUTTON_REPORT_ID = 2, SONY_BUTTON_QUEUE = 32,
    SONY_BUTTON_DEBOUNCE_MS = 15, SONY_BUTTON_FAILURE_LIMIT = 3,
    SONY_BUTTON_PON_PPID = 0x013, SONY_BUTTON_GPIO_PPID = 0x18d,
    SONY_BUTTON_RT_STS = 0x10,
    SonyButtonsBadArgument = -1, SonyButtonsNotOwned = -2,
    SonyButtonsReadFailed = -3, SonyButtonsQueueFull = -4
};

// Full-state consumer report. Bit zero is CONSTANT, not Consumer Menu/Home.
static const uint8_t sony_buttons_descriptor[] = {
    0x05,0x0c,0x09,0x01,0xa1,0x01,0x85,0x02,
    0x15,0x00,0x25,0x01,0x75,0x01,0x95,0x01,0x81,0x03,
    0x09,0x30,0x09,0xe9,0x09,0xea,0x95,0x03,0x81,0x02,
    0x95,0x04,0x81,0x03,0xc0
};

typedef struct SonyButtonsReadOps {
    void *context;
    // Must check this EE's qualification before every read. Never reassign it.
    int (*read8)(void *, uint16_t ppid, uint8_t offset, uint8_t *value);
    uint8_t enabled_mask; // zero is neutral-registration mode; read8 must be null
} SonyButtonsReadOps;

typedef int (*SonyButtonsSubmit)(void *, const uint8_t *report, size_t bytes);

typedef struct SonyButtonsState {
    uint64_t candidate_since[3], last_time;
    uint32_t samples, reports, read_errors, submit_errors, overflows;
    int last_read_error, last_submit_error, terminal_error;
    uint8_t stable, candidate, enabled_mask, failures, stopped, time_valid;
    uint8_t queue[SONY_BUTTON_QUEUE], head, count, synchronized;
} SonyButtonsState;

// These functions are called on one serialized work loop, never in an IRQ.
int sony_buttons_init(SonyButtonsState *, uint8_t enabled_mask);
int sony_buttons_read(const SonyButtonsReadOps *, uint8_t *pressed);
int sony_buttons_poll(SonyButtonsState *, const SonyButtonsReadOps *, uint64_t now_ms);
int sony_buttons_flush(SonyButtonsState *, SonyButtonsSubmit, void *context, unsigned budget);
void sony_buttons_cancel(SonyButtonsState *, int reason);
// Checks one specifically supplied APID's metadata. Does not search peripherals.
int sony_buttons_qualify_apid(uint32_t version, uint32_t apids, uint32_t apid,
                             uint32_t map, uint32_t owner, uint16_t ppid, uint8_t ee);
#ifdef __cplusplus
}
#endif
#endif
