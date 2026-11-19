/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
struct sony_rpmh_io {
    void *context;
    uint32_t (*read)(void *,uint32_t);
    void (*write)(void *,uint32_t,uint32_t);
    void (*delay_us)(void *,unsigned);
    /* IRQ-context ISR records only the owned TCS bit. Callback returns and
     * consumes observed bits; hardware IRQ status is also checked directly. */
    uint32_t (*completed)(void *);
};
struct sony_rpmh {
    struct sony_rpmh_io io;
    uint32_t tcs_base, active_mask, claimed, poisoned, irq_original;
    uint32_t control,status,cmd_enable,msgid,cmd_addr,cmd_data,cmd_status,resp_data,wait;
    unsigned cmd_stride, ncpt;
    int last_error;
    uint32_t last_tcs,last_address,last_status,last_command;
};
int sony_rpmh_init(struct sony_rpmh *,const struct sony_rpmh_io *,uint32_t tcs_base,
                   unsigned drv_id,uint32_t active_mask);
/* The caller holds the shared configuration mutex across the entire call.
 * A read is a real RPMh read command; unsupported/no-response is an error.
 * A failed in-flight command leaves its TCS reserved/poisoned, never reused. */
int sony_rpmh_transfer(struct sony_rpmh *,uint32_t address,bool write,uint32_t *value);
#ifdef __cplusplus
}
#endif
