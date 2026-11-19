// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include "Display069.h"
#ifdef __cplusplus
extern "C" {
#endif
enum D69VoteKind {D69Vrm=1,D69Arc=2};
typedef struct D69VoteSpec {
    const char *resource; // CommandDB exact name, not PMIC Linux regulator alias
    uint32_t kind,voltage_mv,corner,enable,mode;
} D69VoteSpec;
// The shared native RPMh owner serializes all clients, resolves CommandDB and
// ARC aux-data, aggregates MAX votes and handles active/wake/sleep consistently.
// vote is all-or-error; on partial HW failure provider must pin its token.
typedef struct D69SharedPower {
    uint32_t abi_version,bytes;
    void *context;
    int (*vote)(void *,const char *client,const D69VoteSpec *,unsigned count,uint64_t *token);
    int (*release)(void *,uint64_t token);
    bool (*held)(void *,uint64_t token);
} D69SharedPower;
typedef struct D69Resources {
    D69Io io;D69SharedPower provider;
    D69VoteSpec votes[D69Rails];uint64_t token;
    uint32_t original_gcc[3],original_dispcc[13],gdsc_cfg[2];
    int last_error;
    bool ready,voted,clocks_on,pinned;
} D69Resources;
int d69_resources_init(D69Resources *,const D69Io *,const D69SharedPower *,const D69VoteSpec votes[D69Rails]);
int d69_resources_hold(D69Resources *);
int d69_resources_release(D69Resources *);
bool d69_resources_held(const D69Resources *);
uint32_t d69_vsync_rate(D69Resources *,uint32_t xo_hz);
int native_sony_display069_install_power(const D69SharedPower *);
#ifdef __cplusplus
}
#endif
