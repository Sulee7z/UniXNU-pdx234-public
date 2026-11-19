// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
enum D69Result {D69OK=0,D69Pending=1,D69Busy=2,D69Disabled=3,
    D69Argument=-200,D69Resource=-201,D69Mode=-202,D69Route=-203,D69Timeout=-204,
    D69Controller=-205,D69Epoch=-206,D69Poisoned=-207,D69Te=-208,D69Restore=-209};
enum D69Region {D69Gcc,D69Dispcc,D69Mdss,D69Dsi0,D69Dsi1,D69Phy0,D69Phy1,D69Pll0,D69Pll1,D69Regions};
enum {D69MaxPacket=16,D69MaxBatch=40,D69Rails=7,D69CtlCount=6,D69DscCount=4};
typedef struct D69Io {
    void *context;
    uint32_t (*read)(void *,unsigned region,uint32_t offset);
    void (*write)(void *,unsigned region,uint32_t offset,uint32_t value);
    uint64_t (*now_us)(void *);
    void (*delay_us)(void *,uint32_t);
    // Resource implementation votes shared RPMh before enabling branches and
    // mapping MDSS/DSI. hold/release return real status, never certificates.
    int (*hold)(void *);
    int (*release)(void *);
    bool (*held)(void *);
    void (*critical)(void *,bool enter);
    int (*config_lock)(void *);
    void (*config_unlock)(void *);
} D69Io;
typedef struct D69Board {
    uint32_t ctl[D69CtlCount],dsc[D69DscCount],dsc_enc[D69DscCount],pp[8],intf[2];
    uint32_t width,height,vsync_hz,timestamp_hz,bit_clock_hz,pll_ref_hz;
    uint32_t mdp_budget_60_us,mdp_budget_120_us,mdp_idle_timeout_us;
    uint8_t phy[14];
} D69Board;
typedef struct D69Packet {uint8_t type,vc,length,wait_ms;uint8_t data[D69MaxPacket];} D69Packet;
typedef struct D69Transaction {
    D69Packet packet[D69MaxBatch];
    uint32_t count,index,done_mask,master;
    uint32_t saved_dma[2],saved_trigger[2],saved_int[2],saved_length[2],saved_clk[2],saved_ctrl[2];
    uint32_t saved_autorefresh[2],saved_te_enable[2],saved_te_config[2],saved_timestamp[2];
    uint32_t ctl_mask,dsc_mask;
    uint64_t epoch,deadline,wait_until,te_since,te_last[2],te_first[2],te_period_min[2],te_period_max[2],te_last_seen[2];
    uint32_t te_events[2],te_target,mode_before,mdp_budget;
    bool switching,command_touched,ddic_touched,restoring,mdp_over_budget,timestamp_touched;
    uint8_t state;
} D69Transaction;
typedef struct D69Display {
    D69Io io;D69Board board;D69Transaction tx;
    uint32_t gate,producers,initialized,ready,poisoned;
    uint64_t generation;
    uint32_t requested,transmitted,current_verified,observed_hz,packets_sent,timeouts,failures,sending;
    int last_error;
} D69Display;

int d69_init(D69Display *,const D69Io *,const D69Board *);
int d69_probe(D69Display *);
int d69_producer_enter(D69Display *);
void d69_producer_leave(D69Display *);
// Begin/step run on the display command workloop. No other command engine.
int d69_brightness(D69Display *,uint32_t level);
int d69_switch120(D69Display *);
int d69_step(D69Display *);
bool d69_busy(const D69Display *);
int d69_stop(D69Display *);
int d69_resume(D69Display *);
int d69_pack(const D69Packet *,uint32_t words[5],unsigned *bytes);
uint16_t d69_sdr_dbv(uint32_t level);

// Native integration. Main installs provider once, then calls start after GOP
// initialized. No new TCS backend or shared display source edit is hidden here.
void native_sony_display069_probe(void);
int native_sony_display069_producer_enter(void);
void native_sony_display069_producer_leave(void);
int native_sony_display069_stop(void);
unsigned native_sony_display069_observed_hz(void);
extern volatile int32_t native_sony_display069_stats[32];
#ifdef __cplusplus
}
#endif
