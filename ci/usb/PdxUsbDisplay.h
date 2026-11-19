/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Cached text only: a screen reader never takes the USB guard or reads MMIO. */
#ifndef PDX_USB_DISPLAY_H
#define PDX_USB_DISPLAY_H
#include <stdint.h>
enum { PDX_USB_ROWS = 3, PDX_USB_COLS = 192 };
struct pdx_usb_display { unsigned busy; char rows[PDX_USB_ROWS][PDX_USB_COLS]; };
static int pdx_usb_display_set(struct pdx_usb_display *state, unsigned row, const char *text)
{
    if (!text || row >= PDX_USB_ROWS || __atomic_exchange_n(&state->busy, 1u, __ATOMIC_ACQUIRE)) return 0;
    unsigned i = 0;
    for (; i + 1 < PDX_USB_COLS && text[i]; ++i) state->rows[row][i] = text[i];
    state->rows[row][i] = 0;
    __atomic_store_n(&state->busy, 0u, __ATOMIC_RELEASE);
    return 1;
}
static int pdx_usb_display_get(struct pdx_usb_display *state, char out[PDX_USB_ROWS][PDX_USB_COLS])
{
    if (__atomic_exchange_n(&state->busy, 1u, __ATOMIC_ACQUIRE)) return 0;
    for (unsigned r = 0; r < PDX_USB_ROWS; ++r)
        for (unsigned c = 0; c < PDX_USB_COLS; ++c) out[r][c] = state->rows[r][c];
    __atomic_store_n(&state->busy, 0u, __ATOMIC_RELEASE);
    return 1;
}
#endif
