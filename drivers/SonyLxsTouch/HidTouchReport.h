/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef SONY_HID_TOUCH_REPORT_H
#define SONY_HID_TOUCH_REPORT_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define SONY_HID_CONTACTS 10
#define SONY_HID_REPORT_BYTES 62
typedef struct { uint8_t id; uint16_t x, y; } SonyHidContact;
typedef struct { uint8_t count; SonyHidContact contacts[SONY_HID_CONTACTS]; } SonyHidTouchState;
typedef struct {
    uint8_t count;
    uint8_t reports[2][SONY_HID_REPORT_BYTES];
    SonyHidTouchState after[2];
} SonyHidTouchPlan;
/* May emit a release-only transition before the new set when IDs turn over at
 * full capacity. Caller commits after[i] ONLY after handleReport succeeds. */
int sony_hid_touch_plan(const SonyHidTouchState *previous, const SonyHidContact *contacts,
                         unsigned count, SonyHidTouchPlan *plan);
#ifdef __cplusplus
}
#endif
#endif
