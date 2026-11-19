/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include "Sw82907.h"

static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | (uint16_t)p[1] << 8); }
static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

int sw82907_read_command(uint16_t reg, size_t length, uint8_t command[2]) {
    if (!command || reg > 0xfffu || !length || length > 1024u) return -1;
    command[0] = (uint8_t)((reg >> 8) | (length > 4u ? 0x20u : 0u));
    command[1] = (uint8_t)reg;
    return 0;
}

int sw82907_write_word(uint16_t reg, uint32_t value, uint8_t command[6]) {
    if (!command || reg > 0xfffu) return -1;
    command[0] = (uint8_t)(0x40u | reg >> 8);
    command[1] = (uint8_t)reg;
    for (unsigned i = 0; i < 4; ++i) command[2+i] = (uint8_t)(value >> (i*8));
    return 0;
}

int sw82907_decode(const uint8_t *bytes, size_t length, Sw82907FrameData *out) {
    if (!bytes || !out || length < SW82907_HEADER_BYTES || length > SW82907_FRAME_BYTES)
        return Sw82907BadLength;
    Sw82907FrameData frame = {0};
    frame.ic_status = le32(bytes);
    frame.device_status = le32(bytes+4);
    const uint32_t info = le32(bytes+8);
    frame.wakeup = (uint8_t)info;
    frame.wire_count = (uint8_t)((info >> 8) & 31u);
    frame.palm_mask = (uint16_t)(info >> 16);
    /* OLED status type 1, t_sts_mask=0. Exact bit masks are specified in the
     * Sony status filter; non-report interrupts must never be interpreted as fingers. */
    const uint32_t required = (1u<<5) | (1u<<6) | (1u<<15) | (1u<<20) | (1u<<22);
    const uint32_t errors = (1u<<9) | (1u<<10) | (1u<<13);
    if (!frame.ic_status || frame.ic_status & ~0xffu || frame.ic_status & 0x29u ||
        !frame.device_status || frame.device_status == UINT32_MAX ||
        (frame.device_status & required) != required || frame.device_status & errors)
        return Sw82907BadStatus;
    if (((frame.device_status >> 16) & 15u) != 5u || frame.wakeup != 0u)
        return Sw82907Ignored;
    if (frame.wire_count > SW82907_CONTACTS) return Sw82907BadCount;
    if (length < SW82907_HEADER_BYTES + (size_t)frame.wire_count * SW82907_CONTACT_BYTES)
        return Sw82907BadLength;
    uint16_t seen = 0;
    Sw82907Contact slots[SW82907_CONTACTS] = {{0}};
    uint16_t active = 0;
    for (unsigned i = 0; i < frame.wire_count; ++i) {
        const uint8_t *p = bytes + SW82907_HEADER_BYTES + i*SW82907_CONTACT_BYTES;
        const unsigned event = p[0] >> 4, id = p[1];
        if (event > 3u) return Sw82907BadContact;
        if (id == 15u) {
            if (event == 1u || event == 2u) frame.cancelled = 1;
            continue;
        }
        if (id >= SW82907_CONTACTS || seen & (1u<<id)) return Sw82907BadContact;
        seen |= (uint16_t)(1u<<id);
        if (event != 1u && event != 2u) continue;
        const uint16_t x = le16(p+2), y = le16(p+4);
        /* Android ABS maxima are inclusive, confirmed in this phone's input caps. */
        if (x > SW82907_WIDTH || y > SW82907_HEIGHT) return Sw82907BadContact;
        if (frame.palm_mask & (1u<<id)) continue;
        slots[id] = (Sw82907Contact){(uint8_t)id,(uint8_t)event,(uint8_t)(p[0]&15u),p[6],
                                    x,y,le16(p+8),le16(p+10),(int8_t)p[7]};
        active |= (uint16_t)(1u<<id);
    }
    if (!frame.cancelled)
        for (unsigned id = 0; id < SW82907_CONTACTS; ++id)
            if (active & (1u<<id)) frame.contacts[frame.count++] = slots[id];
    *out = frame;
    return Sw82907Frame;
}
