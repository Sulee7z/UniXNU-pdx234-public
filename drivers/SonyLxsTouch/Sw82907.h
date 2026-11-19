/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/* Sony SW82907 protocol, independently expressed from the recorded vendor specification. */
#ifndef SONY_SW82907_H
#define SONY_SW82907_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define SW82907_CONTACTS 10u
#define SW82907_HEADER_BYTES 12u
#define SW82907_CONTACT_BYTES 12u
#define SW82907_FRAME_BYTES (SW82907_HEADER_BYTES + SW82907_CONTACTS * SW82907_CONTACT_BYTES)
#define SW82907_ADDRESS 0x28u
#define SW82907_REPORT_REG 0x600u
#define SW82907_STATUS_REG 0x601u
#define SW82907_DEVICE_CTL 0xc00u
#define SW82907_DRIVE_CTL 0xc03u
#define SW82907_WIDTH 1644u
#define SW82907_HEIGHT 3840u
enum { Sw82907Frame = 0, Sw82907Ignored = 1, Sw82907BadLength = -1,
       Sw82907BadStatus = -2, Sw82907BadCount = -3, Sw82907BadContact = -4 };
typedef struct {
    uint8_t id, event, tool, pressure;
    uint16_t x, y, major, minor;
    int8_t angle;
} Sw82907Contact;
typedef struct {
    uint32_t ic_status, device_status;
    uint16_t palm_mask;
    uint8_t count, wire_count, wakeup, cancelled;
    Sw82907Contact contacts[SW82907_CONTACTS];
} Sw82907FrameData;
/* Registers are 12-bit WORD addresses, high byte first; data words are little-endian.
 * Burst bit is required for lengths >4, not for a single word. No SPI headers. */
int sw82907_read_command(uint16_t reg, size_t length, uint8_t command[2]);
int sw82907_write_word(uint16_t reg, uint32_t value, uint8_t command[6]);
/* Complete, validated touch set. On any failure out is unmodified. Slot order is
 * canonical ID order, UP/IDLE are absent, PALM_ID 15 cancels the whole stroke. */
int sw82907_decode(const uint8_t *bytes, size_t length, Sw82907FrameData *out);
#ifdef __cplusplus
}
#endif
#endif
