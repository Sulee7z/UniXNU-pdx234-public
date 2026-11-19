// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "SonyButtonsCore.h"
#include <string.h>

static int enqueue(SonyButtonsState *s, uint8_t mask) {
    if (s->count == SONY_BUTTON_QUEUE) {
        ++s->overflows;
        sony_buttons_cancel(s, SonyButtonsQueueFull);
        return SonyButtonsQueueFull;
    }
    s->queue[(s->head + s->count) % SONY_BUTTON_QUEUE] = mask;
    ++s->count;
    return 0;
}

int sony_buttons_init(SonyButtonsState *s, uint8_t enabled) {
    if (!s || (enabled & ~SONY_BUTTON_MASK)) return SonyButtonsBadArgument;
    memset(s, 0, sizeof(*s));
    s->enabled_mask = enabled;
    // Establish neutral once the event service attaches, even if it attaches late.
    return enqueue(s, 0);
}

int sony_buttons_qualify_apid(uint32_t version, uint32_t apids, uint32_t apid,
                             uint32_t map, uint32_t owner, uint16_t ppid, uint8_t ee) {
    if (version < 0x70000000u || version >= 0x80000000u || !apids || apids > 1024 || apid >= apids || ee != 0)
        return SonyButtonsNotOwned;
    if (ppid != SONY_BUTTON_PON_PPID && ppid != SONY_BUTTON_GPIO_PPID) return SonyButtonsNotOwned;
    // Match the inherited HLOS channel AND IRQ-owner mapping, not just a PPID.
    // Bit24 is not observer permission; this extra restriction deliberately
    // rejects readable-but-not-owned channels instead of relaxing ownership.
    if (((map >> 8) & 0xfffu) != ppid || !(map & (1u << 24)) || (owner & 7u) != ee)
        return SonyButtonsNotOwned;
    return 0;
}

int sony_buttons_read(const SonyButtonsReadOps *ops, uint8_t *pressed) {
    if (!ops || !ops->read8 || !pressed || !ops->enabled_mask || (ops->enabled_mask & ~SONY_BUTTON_MASK))
        return SonyButtonsBadArgument;
    uint8_t mask = 0, raw = 0;
    if (ops->enabled_mask & (SONY_BUTTON_POWER | SONY_BUTTON_VOLUME_UP)) {
        const int result = ops->read8(ops->context, SONY_BUTTON_PON_PPID, SONY_BUTTON_RT_STS, &raw);
        if (result) return result;
        if (raw & 0x80u) mask |= SONY_BUTTON_POWER;
        // Sony's pmic_resin is KEY_VOLUMEUP. Sheng maps the same bit to DOWN.
        if (raw & 0x40u) mask |= SONY_BUTTON_VOLUME_UP;
    }
    if (ops->enabled_mask & SONY_BUTTON_VOLUME_DOWN) {
        const int result = ops->read8(ops->context, SONY_BUTTON_GPIO_PPID, SONY_BUTTON_RT_STS, &raw);
        if (result) return result;
        if (!(raw & 1u)) mask |= SONY_BUTTON_VOLUME_DOWN;
    }
    *pressed = mask & ops->enabled_mask;
    return 0;
}

void sony_buttons_cancel(SonyButtonsState *s, int reason) {
    if (!s) return;
    s->stopped = 1;
    s->terminal_error = reason;
    s->stable = s->candidate = 0;
    // Discard stale presses, including a possibly accepted failed submission.
    // This neutral is recovery/teardown, not a fabricated hardware release.
    s->head = 0;
    s->count = 1;
    s->queue[0] = 0;
}

int sony_buttons_poll(SonyButtonsState *s, const SonyButtonsReadOps *ops, uint64_t now) {
    if (!s || !ops || ops->enabled_mask != s->enabled_mask) return SonyButtonsBadArgument;
    if (s->stopped) return s->terminal_error;
    uint8_t raw = 0;
    const int result = sony_buttons_read(ops, &raw);
    if (result) {
        ++s->read_errors;
        s->last_read_error = result;
        s->candidate = s->stable;
        for (unsigned bit = 0; bit < 3; ++bit) s->candidate_since[bit] = now;
        if (++s->failures >= SONY_BUTTON_FAILURE_LIMIT) sony_buttons_cancel(s, result);
        return result;
    }
    ++s->samples;
    s->last_read_error = 0;
    s->failures = 0;
    if (!s->time_valid || now < s->last_time) {
        // An invalid/backwards clock must not manufacture an elapsed debounce.
        s->candidate = s->stable;
        for (unsigned bit = 0; bit < 3; ++bit) s->candidate_since[bit] = now;
    }
    s->last_time = now;
    s->time_valid = 1;
    uint8_t stable = s->stable;
    for (unsigned bit = 0; bit < 3; ++bit) {
        const uint8_t mask = (uint8_t)(2u << bit);
        if ((raw ^ s->candidate) & mask) {
            s->candidate ^= mask;
            s->candidate_since[bit] = now;
        } else if (((s->candidate ^ stable) & mask) && now - s->candidate_since[bit] >= SONY_BUTTON_DEBOUNCE_MS) {
            stable ^= mask;
        }
    }
    if (stable == s->stable) return 0; // Long hold: no repeated press or forced release.
    s->stable = stable;
    return enqueue(s, stable);
}

int sony_buttons_flush(SonyButtonsState *s, SonyButtonsSubmit submit, void *context, unsigned budget) {
    if (!s || !submit || !budget || budget > SONY_BUTTON_QUEUE) return SonyButtonsBadArgument;
    for (unsigned i = 0; i < budget && s->count; ++i) {
        const uint8_t report[2] = {SONY_BUTTON_REPORT_ID, s->queue[s->head]};
        const int result = submit(context, report, sizeof(report));
        if (result) {
            ++s->submit_errors;
            s->last_submit_error = result;
            return result; // Do not acknowledge a failed down OR release.
        }
        s->last_submit_error = 0;
        s->synchronized = 1;
        ++s->reports;
        s->head = (s->head + 1) % SONY_BUTTON_QUEUE;
        --s->count;
    }
    return 0;
}
