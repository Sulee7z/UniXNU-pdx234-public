// SPDX-License-Identifier: BSD-2-Clause-Patent
// Register semantics cross-checked against Sony67.2.A.3.141 dsi_ctrl_hw_cmn.c,
// dsi_ctrl.c and Qualcomm HAL_DSI_WriteData (see the provenance document).
#include "SonyDsi.h"
#include "SonyOledPolicy.h"
#include <string.h>

#define BIT(n) (UINT32_C(1) << (n))
#define STATUS_BUSY (UINT32_C(0x000383f7))
#define INT_MASK UINT32_C(0xa222aa02)
#define INT_ERROR BIT(24)
#define INT_DONE BIT(0)
#define DMA_CHANGED (BIT(31) | BIT(30) | BIT(29) | BIT(28) | BIT(26) | BIT(24))
enum { StateIdle, StateWrite, StateRead0, StateRead1, StatePoisoned };

static uint32_t rd(SonyDsi *s, unsigned h, uint32_t reg) { return s->io.read(s->io.context, h, reg); }
static void wr(SonyDsi *s, unsigned h, uint32_t reg, uint32_t value) { s->io.write(s->io.context, h, reg, value); }
static void delay(SonyDsi *s) { s->io.delay_us(s->io.context, 1); }

void sony_dsi_packet51(uint16_t dbv, uint32_t words[2]) {
    uint8_t bytes[3]; sony_oled_encode_dbv(dbv, bytes);
    words[0] = UINT32_C(0xc0390003); // WC3, DCS long write, long+last
    words[1] = bytes[0] | ((uint32_t)bytes[1] << 8) | ((uint32_t)bytes[2] << 16) | UINT32_C(0xff000000);
}

void sony_dsi_packet52(uint32_t words[2]) {
    words[0] = UINT32_C(0x00370002); // maximum return packet size=2, not last
    words[1] = UINT32_C(0xa0060052); // DCS read 0x52, embedded BTA+last
}

uint8_t sony_dsi_header_ecc(uint8_t type, uint8_t data0, uint8_t data1) {
    // MIPI DSI 24-bit short-packet header parity. Reject corrupt brightness
    // samples even if firmware left hardware ECC checking disabled.
    const uint32_t data=type | ((uint32_t)data0<<8) | ((uint32_t)data1<<16);
    const uint32_t parity[6]={UINT32_C(0xf12cb7),UINT32_C(0xf2555b),UINT32_C(0x749a6d),
                              UINT32_C(0xb8e38e),UINT32_C(0xdf03f0),UINT32_C(0xeffc00)};
    uint8_t result=0;
    for(unsigned i=0;i<6;++i)result|=(uint8_t)((__builtin_popcount(data&parity[i])&1)<<i);
    return result;
}

static uint32_t errors(SonyDsi *s, unsigned h) {
    return (rd(s,h,SonyDsiInterrupt) & INT_ERROR) |
           (rd(s,h,SonyDsiAckError) & UINT32_C(0x0193ffff)) |
           (rd(s,h,SonyDsiTimeoutStatus) & UINT32_C(0x111)) |
           (rd(s,h,SonyDsiPhyError) & UINT32_C(0x11111)) |
           (rd(s,h,SonyDsiFifoStatus) & UINT32_C(0xcccc0480)) |
           (rd(s,h,SonyDsiClockStatus) & BIT(16)) |
           (rd(s,h,SonyDsiStatus) & BIT(31));
}

int sony_dsi_init(SonyDsi *s, const SonyDsiIo *io, const SonyDsiQualification *q) {
    if (!s || !io || !q || !io->read || !io->write || !io->delay_us ||
        !io->acquire || !io->owned || !io->release || q->master >= SonyDsiHosts) return SonyDsiArgument;
    memset(s,0,sizeof(*s));
    if (q->flags != SonyDsiQualificationAll || !q->version[0] || !q->version[1] ||
        q->version[0] == UINT32_MAX || q->version[1] == UINT32_MAX ||
        !q->stream_total[0] || !q->stream_total[1]) return SonyDsiUnqualified;
    s->io = *io; s->qualification = *q; s->initialized = true;
    return SonyDsiOK;
}

static void clear_own_status(SonyDsi *s, unsigned h) {
    // Preserve enable bits only; never acknowledge display/refresh/error flags.
    wr(s,h,SonyDsiInterrupt,(s->saved_int_mask[h] & ~(BIT(1) | BIT(21))) | INT_DONE | BIT(20));
}

static void fifo(SonyDsi *s, unsigned h, const uint32_t words[2], bool broadcast) {
    clear_own_status(s,h);
    wr(s,h,SonyDsiTpgControl,0);
    wr(s,h,SonyDsiFifoReset,1); delay(s); wr(s,h,SonyDsiFifoReset,0);
    wr(s,h,SonyDsiTpgControl,UINT32_C(0x30006));
    wr(s,h,SonyDsiTpgData,words[0]); wr(s,h,SonyDsiTpgData,words[1]);
    uint32_t dma = (s->saved_dma[h] & ~DMA_CHANGED) | BIT(28);
    if (s->qualification.use_lpm) dma |= BIT(26);
    if (broadcast) {
        dma |= BIT(31);
        if (h == s->qualification.master) dma |= BIT(30);
    }
    wr(s,h,SonyDsiDmaControl,dma);
    // All pixel-command producers are quiesced under the lease. Use SW trigger,
    // NOT an unqualified TE/DMA scheduling line copied from a different mode.
    wr(s,h,SonyDsiTriggerControl,(s->saved_trigger[h] & ~(UINT32_C(0xf) | BIT(16))) | 4);
    wr(s,h,SonyDsiDmaLength,8);
}

static int poison(SonyDsi *s, int error) {
    s->last_error = error; s->failures++; s->poisoned = true; s->state = StatePoisoned;
    if (error == SonyDsiTimeout) s->timeouts++;
    // Do not recycle FIFO/configuration or release a possibly still active host.
    return error;
}

static void restore(SonyDsi *s) {
    for (unsigned h=0; h<SonyDsiHosts; ++h) {
        clear_own_status(s,h);
        wr(s,h,SonyDsiTpgControl,0);
        wr(s,h,SonyDsiFifoReset,1); delay(s); wr(s,h,SonyDsiFifoReset,0);
        wr(s,h,SonyDsiDmaControl,s->saved_dma[h]);
        wr(s,h,SonyDsiDmaLength,s->saved_length[h]);
        wr(s,h,SonyDsiTriggerControl,s->saved_trigger[h]);
        wr(s,h,SonyDsiTpgControl,s->saved_tpg[h]);
        wr(s,h,SonyDsiInterrupt,s->saved_int_mask[h]);
    }
    s->io.release(s->io.context,s->epoch); s->leased = false; s->state = StateIdle;
}

static int acquire(SonyDsi *s) {
    if (!s || !s->initialized) return SonyDsiUnqualified;
    if (s->poisoned) return SonyDsiPoisoned;
    if (s->state != StateIdle) return SonyDsiBusy;
    const int result = s->io.acquire(s->io.context,&s->epoch);
    if (result) return result < 0 ? result : SonyDsiBusy;
    s->leased = true;
    if (!s->io.owned(s->io.context,s->epoch)) return poison(s,SonyDsiOwnershipLost);
    // Validate both hosts BEFORE the first register write. An unexpected mode,
    // stale error or busy host is never repaired speculatively by this driver.
    for (unsigned h=0; h<SonyDsiHosts; ++h) {
        if (rd(s,h,SonyDsiVersion) != s->qualification.version[h] ||
            rd(s,h,SonyDsiStreamTotal) != s->qualification.stream_total[h] ||
            (rd(s,h,SonyDsiControl) & 7) != 5 || (rd(s,h,SonyDsiStatus) & STATUS_BUSY) || errors(s,h) ||
            rd(s,h,SonyDsiTpgControl) || rd(s,h,SonyDsiDmaSchedule) || rd(s,h,SonyDsiDmaScheduleWindow)) {
            s->io.release(s->io.context,s->epoch); s->leased = false;
            s->last_error = SonyDsiInheritedState; return SonyDsiInheritedState;
        }
        s->saved_dma[h] = rd(s,h,SonyDsiDmaControl);
        s->saved_length[h] = rd(s,h,SonyDsiDmaLength);
        s->saved_trigger[h] = rd(s,h,SonyDsiTriggerControl);
        s->saved_tpg[h] = rd(s,h,SonyDsiTpgControl);
        s->saved_int_mask[h] = rd(s,h,SonyDsiInterrupt) & INT_MASK;
    }
    return SonyDsiOK;
}

static void read_start(SonyDsi *s, unsigned h, uint64_t now_us) {
    uint32_t words[2]; sony_dsi_packet52(words);
    s->read_host = (uint8_t)h; s->state = h ? StateRead1 : StateRead0;
    wr(s,h,SonyDsiReadControl,1); wr(s,h,SonyDsiReadControl,0);
    fifo(s,h,words,false); wr(s,h,SonyDsiTrigger,1);
    s->deadline = now_us + SonyDsiDeadlineUs;
}

int sony_dsi_start_read(SonyDsi *s, uint64_t now_us) {
    if (now_us > UINT64_MAX - SonyDsiDeadlineUs) return SonyDsiArgument;
    const int result = acquire(s); if (result) return result;
    s->writing = false; read_start(s,0,now_us); return SonyDsiPending;
}

int sony_dsi_start_write(SonyDsi *s, uint16_t dbv, uint64_t now_us) {
    if (dbv > SONY_OLED_SDR_MAX_DBV || now_us > UINT64_MAX - SonyDsiDeadlineUs) return SonyDsiArgument;
    const int result = acquire(s); if (result) return result;
    s->writing = true; s->requested = dbv;
    uint32_t words[2]; sony_dsi_packet51(dbv,words);
    for (unsigned h=0; h<SonyDsiHosts; ++h) fifo(s,h,words,true);
    wr(s,1-s->qualification.master,SonyDsiTrigger,1);
    wr(s,s->qualification.master,SonyDsiTrigger,1);
    s->state = StateWrite; s->deadline = now_us + SonyDsiDeadlineUs; return SonyDsiPending;
}

static bool done(SonyDsi *s, unsigned h) {
    s->interrupt[h] = rd(s,h,SonyDsiInterrupt); s->errors[h] = errors(s,h);
    return (s->interrupt[h] & INT_DONE) && !(rd(s,h,SonyDsiStatus) & STATUS_BUSY);
}

int sony_dsi_step(SonyDsi *s, uint64_t now_us) {
    if (!s || !s->initialized) return SonyDsiUnqualified;
    if (s->poisoned) return SonyDsiPoisoned;
    if (s->state == StateIdle) return SonyDsiOK;
    if (!s->io.owned(s->io.context,s->epoch)) return poison(s,SonyDsiOwnershipLost);
    bool ready;
    if (s->state == StateWrite) {
        const bool d0=done(s,0),d1=done(s,1); ready=d0 && d1;
        if (s->errors[0] || s->errors[1]) return poison(s,SonyDsiControllerError);
    } else {
        ready=done(s,s->read_host);
        if (s->errors[s->read_host]) return poison(s,SonyDsiControllerError);
        if (ready) ready=(rd(s,s->read_host,SonyDsiReadControl) >> 16) != 0;
    }
    if (!ready) return now_us >= s->deadline ? poison(s,SonyDsiTimeout) : SonyDsiPending;
    if (s->state == StateWrite) {
        if (now_us > UINT64_MAX - SonyDsiDeadlineUs) return poison(s,SonyDsiArgument);
        read_start(s,0,now_us); return SonyDsiPending;
    }
    const unsigned h=s->read_host;
    const uint32_t count=rd(s,h,SonyDsiReadControl) >> 16;
    const uint32_t reply=rd(s,h,SonyDsiReadData);
    // Qcom RDBK register is network order. A two-byte DCS response is 0x22,
    // parameter MSB, parameter LSB, ECC. Reject ACK/errors, one-byte and stale
    // appended responses rather than accepting ambiguous physical state.
    const uint8_t bytes[2]={(uint8_t)(reply >> 16),(uint8_t)(reply >> 8)};
    if (count != 4 || (reply >> 24) != 0x22 ||
        (uint8_t)reply != sony_dsi_header_ecc((uint8_t)(reply >> 24),bytes[0],bytes[1]) ||
        !sony_oled_decode_dbv(bytes,&s->observed[h]))
        return poison(s,SonyDsiResponse);
    if (!h) {
        if (now_us > UINT64_MAX - SonyDsiDeadlineUs) return poison(s,SonyDsiArgument);
        read_start(s,1,now_us); return SonyDsiPending;
    }
    if (s->observed[0] != s->observed[1] || (s->writing && s->observed[0] != s->requested)) {
        restore(s); s->last_error=SonyDsiMismatch; s->failures++; return SonyDsiMismatch;
    }
    restore(s); s->last_error=SonyDsiOK; s->completed++; return SonyDsiOK;
}

bool sony_dsi_busy(const SonyDsi *s) { return s && s->state != StateIdle; }
