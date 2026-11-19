// SPDX-License-Identifier: BSD-2-Clause-Patent
#ifndef SONY_GOVERNOR069_H
#define SONY_GOVERNOR069_H
#include <stdint.h>

// One owner per governor. A concurrent late-probe caller never mutates live
// configuration, allocates another lock or starts another sampling thread.
static inline bool sony069_start_once(uint32_t *state) {
    uint32_t expected=0;
    return __atomic_compare_exchange_n(state,&expected,1u,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);
}
struct Sony069IdleWindow {
    uint64_t idle=0,stamp=0;
    unsigned busy=1000;
    bool ready=false;
    // Time and idle are measured together per CPU, not against a timestamp
    // obtained before eight possibly preempted remote recount reads. A corrupt
    // or decreasing snapshot is not fabricated as an idle CPU. Keep the last
    // valid load for this window, reseed, and let the next real window decide.
    unsigned observe(uint64_t now,uint64_t value) {
        if(!ready){idle=value;stamp=now;ready=true;return busy;}
        const uint64_t dt=now-stamp;
        if(now<=stamp || value<idle || value-idle>dt) {
            idle=value;stamp=now;return busy;
        }
        const uint64_t di=value-idle;idle=value;stamp=now;
        if(!dt)return busy;
        busy=(unsigned)((dt-di)*1000/dt);
        return busy;
    }
};
struct Sony069TouchSample {
    uint32_t seen=0,count=0,pulse=0;
    bool seeded=false;
    uint32_t observe(uint32_t first,uint32_t current,uint32_t last) {
        if((first&1u) || first!=last || (seeded && first==seen))return pulse;
        if(!seeded){seeded=true;seen=first;count=current;return pulse;}
        seen=first;
        if(current || count)++pulse;
        count=current;return pulse;
    }
};
#endif
