// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "SonyButtonsCore.h"
#include <cassert>
#include <cstdio>
#include <vector>

struct Hardware {
    uint8_t pon = 0, gpio = 1;
    bool owned = true;
    int error = 0;
    unsigned reads = 0;
    static int read(void *context, uint16_t ppid, uint8_t offset, uint8_t *out) {
        auto *h = static_cast<Hardware *>(context);
        assert(offset == 0x10);
        ++h->reads;
        if (!h->owned) return SonyButtonsNotOwned;
        if (h->error) return h->error;
        assert(ppid == 0x013 || ppid == 0x18d);
        *out = ppid == 0x013 ? h->pon : h->gpio;
        return 0;
    }
};
struct Sink {
    bool fail = false;
    std::vector<unsigned> masks;
    static int submit(void *context, const uint8_t *report, size_t bytes) {
        auto *s = static_cast<Sink *>(context);
        assert(bytes == 2 && report[0] == 2 && !(report[1] & ~14u));
        if (s->fail) return -42;
        s->masks.push_back(report[1]); return 0;
    }
};
int main() {
    for (unsigned mask = 0; mask < 256; ++mask) {
        Hardware h; h.pon = mask; SonyButtonsReadOps ops{&h, Hardware::read, 14}; uint8_t actual = 255;
        assert(!sony_buttons_read(&ops, &actual));
        assert(actual == ((mask & 0x80 ? 2 : 0) | (mask & 0x40 ? 4 : 0)));
        h.gpio = 0; assert(!sony_buttons_read(&ops, &actual)); assert(actual & 8);
    }
    Hardware h; SonyButtonsReadOps ops{&h, Hardware::read, 14}; SonyButtonsState state; Sink sink;
    assert(!sony_buttons_init(&state, 14));
    auto poll = [&](uint64_t now) { assert(!sony_buttons_poll(&state, &ops, now)); };
    auto flush = [&] { assert(!sony_buttons_flush(&state, Sink::submit, &sink, 8)); };
    poll(0); flush(); assert(sink.masks == std::vector<unsigned>{0});
    h.pon = 0x80; poll(1); h.pon = 0; poll(5); h.pon = 0x80; poll(8); poll(22); flush();
    assert(sink.masks.size() == 1); poll(23); flush(); assert(sink.masks.back() == 2);
    for (uint64_t ms = 24; ms < 30000; ++ms) poll(ms);
    flush(); assert(sink.masks.size() == 2); // genuine long hold, no auto-repeat/release/reset
    h.pon = 0xc0; h.gpio = 0; poll(30001); poll(30016); flush(); assert(sink.masks.back() == 14);
    h.pon = 0x40; poll(30020); poll(30035); flush(); assert(sink.masks.back() == 12);
    h.pon = 0; h.gpio = 1; poll(30036); poll(30051);
    sink.fail = true; assert(sony_buttons_flush(&state, Sink::submit, &sink, 8) == -42);
    assert(state.count == 1 && state.queue[state.head] == 0);
    sink.fail = false; flush(); assert(sink.masks.back() == 0);
    // A down and release that both precede event matching must not collapse.
    h.pon = 0x40; poll(30060); poll(30075); h.pon = 0; poll(30080); poll(30095);
    assert(state.count == 2); flush(); assert(sink.masks[sink.masks.size()-2] == 4 && !sink.masks.back());
    // Short error does not become a hardware release. A terminal error does
    // cause an explicitly marked neutral and permanently stops sampling.
    h.pon = 0x80; poll(30100); poll(30115); flush(); h.error = -102;
    for (unsigned i = 0; i < 3; ++i) assert(sony_buttons_poll(&state, &ops, 30120+i) == -102);
    assert(state.stopped && state.terminal_error == -102 && state.stable == 0); flush(); assert(!sink.masks.back());
    const unsigned reads = h.reads; assert(sony_buttons_poll(&state, &ops, 30200) == -102 && h.reads == reads);
    // Clock rollback cannot immediately accept a pending edge.
    assert(!sony_buttons_init(&state, 14)); h.error = 0; h.pon = 0; poll(1000); flush();
    h.pon = 0x80; poll(1010); poll(10); assert(!state.stable); poll(24); assert(!state.stable); poll(25); assert(state.stable == 2);
    h.owned = false; assert(sony_buttons_poll(&state, &ops, 26) == SonyButtonsNotOwned); h.owned = true;
    // Bounded late-match queue: overflow cancels instead of emitting stale presses.
    assert(!sony_buttons_init(&state, 14));
    for (unsigned i = 0; i < 40 && !state.stopped; ++i) {
        h.pon = i & 1 ? 0 : 0x80;
        assert(!sony_buttons_poll(&state, &ops, i*40));
        const int result = sony_buttons_poll(&state, &ops, i*40+15);
        assert(!result || result == SonyButtonsQueueFull);
    }
    assert(state.stopped && state.count == 1 && state.terminal_error == SonyButtonsQueueFull);
    // Exact qualifier: refuse foreign PPID/EE, missing IRQ owner, v8, bad extent.
    const uint32_t map = (1u<<24) | (0x13u<<8);
    assert(!sony_buttons_qualify_apid(0x70000000, 512, 9, map, 0, 0x13, 0));
    assert(sony_buttons_qualify_apid(0x70000000, 512, 9, map, 1, 0x13, 0));
    assert(sony_buttons_qualify_apid(0x70000000, 512, 9, map & ~(1u<<24), 0, 0x13, 0));
    assert(sony_buttons_qualify_apid(0x80000000, 512, 9, map, 0, 0x13, 0));
    assert(sony_buttons_qualify_apid(0x70000000, 512, 512, map, 0, 0x13, 0));
    assert(sony_buttons_qualify_apid(0x70000000, 512, 9, map, 0, 0x13, 1));
    assert(sony_buttons_qualify_apid(0x70000000, 512, 9, map, 0, 0x71, 0));
    // Deterministic status noise, each step goes through real callback decoding.
    assert(!sony_buttons_init(&state, 14)); uint32_t random = 0x12345678;
    for (unsigned i = 0; i < 100000; ++i) {
        random = random*1664525u + 1013904223u; h.pon = (uint8_t)(random>>16); h.gpio = random & 1;
        assert(!sony_buttons_poll(&state, &ops, i)); flush(); assert(!(state.stable & ~14u));
    }
    sony_buttons_cancel(&state, 0); flush(); assert(!sink.masks.back());
    puts("PASS callbacks: Sony PON power/up + PM8550 GPIO6 down, all256 RT_STS bytes, debounce/30s hold/independent-release/late-match/failed-release/revoke/clock/overflow/100k samples");
}
