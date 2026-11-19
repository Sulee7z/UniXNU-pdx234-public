/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#define SONY_VOTE_CLIENTS 8
#ifdef __cplusplus
extern "C" {
#endif
struct sony_vote {uint32_t mode,millivolts,enabled;};
struct sony_vote_resource {
    uint32_t address,min_uv,max_uv;
    struct sony_vote boot,applied,client[SONY_VOTE_CLIENTS];
    bool initialized,poisoned;
};
struct sony_vote_io {
    void *context;
    int (*transfer)(void *,uint32_t address,bool write,uint32_t *value);
};
int sony_vote_update(struct sony_vote_resource *,const struct sony_vote_io *,
                     unsigned client,unsigned mode,unsigned microvolts,bool enabled);
struct sony_bcm_vote {uint64_t average,peak;};
struct sony_bcm_resource {
    uint32_t address,boot,applied,unit,width,vcd;
    struct sony_bcm_vote client[SONY_VOTE_CLIENTS];
    bool initialized,poisoned;
};
int sony_bcm_update(struct sony_bcm_resource *,const struct sony_vote_io *,
                     unsigned client,uint64_t average,uint64_t peak);
struct sony_arc_resource {
    uint32_t address,boot,applied,client[SONY_VOTE_CLIENTS];
    bool enabled[SONY_VOTE_CLIENTS],initialized,poisoned;
};
int sony_arc_update(struct sony_arc_resource *,const struct sony_vote_io *,unsigned,uint32_t,bool);
#ifdef __cplusplus
}
#endif
