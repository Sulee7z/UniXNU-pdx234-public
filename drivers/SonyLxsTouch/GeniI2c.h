/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef SONY_GENI_I2C_H
#define SONY_GENI_I2C_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    uint32_t (*read)(void *, uint32_t);
    void (*write)(void *, uint32_t, uint32_t);
    void *context;
} SonyGeniIo;
typedef struct {
    void *context;
    uint8_t *tx, *rx;
    uint64_t tx_physical, rx_physical;
    uint32_t capacity;
    void (*clean)(void *,void *,uint32_t);
    void (*prepare_rx)(void *,void *,uint32_t);
    void (*invalidate)(void *,void *,uint32_t);
} SonyGeniDma;
enum { SonyGeniIdle, SonyGeniTx, SonyGeniRx, SonyGeniCancel, SonyGeniAbort, SonyGeniOffline };
enum { SonyGeniPending, SonyGeniDone, SonyGeniFailed };
enum { SonyGeniOk, SonyGeniBusError, SonyGeniTimeout, SonyGeniShortRead,
       SonyGeniInvalidFifo, SonyGeniEarlyDone, SonyGeniUnstopped };
typedef struct {
    SonyGeniIo io;
    uint8_t address, phase, error, read_transfer;
    uint8_t command[8];
    const uint8_t *tx;
    uint8_t *rx;
    uint32_t tx_length, tx_done, rx_length, rx_done, tx_depth, rx_depth;
    uint32_t failure_status, done, failed, timeouts;
    SonyGeniDma dma;
    uint8_t dma_mode, dma_started, command_done, dma_done;
    uint32_t last_irq, last_dma_tx, last_dma_rx;
} SonyGeniI2c;
/* Inherited, already clocked I2C firmware only. Does not guess protocol/clock;
 * checks FIFO geometry and idle state before touching control registers. */
int sony_geni_prepare(SonyGeniI2c *, const SonyGeniIo *, uint8_t address, uint32_t qup_version);
/* For FIFO-disabled engines, use the host-visible SE DMA path. The owner must
 * mask the GIC line, map the actual Sony stream and pin buffers through errors. */
int sony_geni_prepare_dma(SonyGeniI2c *,const SonyGeniIo *,uint8_t,uint32_t,const SonyGeniDma *);
int sony_geni_read(SonyGeniI2c *, const uint8_t *command, uint32_t command_bytes,
                   uint8_t *bytes, uint32_t length);
int sony_geni_write(SonyGeniI2c *, const uint8_t *bytes, uint32_t length);
int sony_geni_poll(SonyGeniI2c *);
/* Caller supplies bounded deadlines; cancel, then abort, then permanently stop
 * if hardware has not acknowledged. Never reuse a live timed-out command. */
int sony_geni_timeout(SonyGeniI2c *);
#ifdef __cplusplus
}
#endif
#endif
