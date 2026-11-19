/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include "GeniI2c.h"
enum { STATUS=0x40, CLOCK=0x48, IF_DISABLE=0x64, REVISION=0x68,
       BYTE_GRAN=0x254, DMA_MODE=0x258, TX_PACK0=0x260, TX_PACK1=0x264,
       TX_LEN=0x26c, RX_LEN=0x270, SCL=0x278, RX_PACK0=0x284, RX_PACK1=0x288,
       CMD=0x600, CTRL=0x604, IRQ=0x610, IRQ_EN=0x614, CLEAR=0x618,
       TX_FIFO=0x700, RX_FIFO=0x780, TX_STATUS=0x800, RX_STATUS=0x804,
       TX_WM=0x80c, RX_WM=0x810, RX_RFR=0x814, SE_IRQ_EN=0xe1c,
       TX_PARAM=0xe24, RX_PARAM=0xe28, GSI_EN=0xe18,
       DMA_TX_PTR=0xc30,DMA_TX_PTR_H=0xc34,DMA_TX_ATTR=0xc38,DMA_TX_LEN=0xc3c,
       DMA_TX_STATUS=0xc40,DMA_TX_CLEAR=0xc44,DMA_TX_ENABLE=0xc4c,
       DMA_RX_PTR=0xd30,DMA_RX_PTR_H=0xd34,DMA_RX_ATTR=0xd38,DMA_RX_LEN=0xd3c,
       DMA_RX_STATUS=0xd40,DMA_RX_CLEAR=0xd44,DMA_RX_ENABLE=0xd4c };
#define DONE (1u<<0)
#define CANCEL (1u<<4)
#define ABORT (1u<<5)
#define ERRORS ((7u<<1) | (0x3fu<<9))
#define RX_EVENTS ((1u<<26) | (1u<<27))
#define TX_EVENT (1u<<30)
#define WANTED (DONE | CANCEL | ABORT | ERRORS | RX_EVENTS | TX_EVENT)
static uint32_t rd(SonyGeniI2c *g, uint32_t reg) {return g->io.read(g->io.context,reg);}
static void wr(SonyGeniI2c *g, uint32_t reg, uint32_t value) {g->io.write(g->io.context,reg,value);}

static int prepare(SonyGeniI2c *g,const SonyGeniIo *io,uint8_t address,uint32_t qup_version,const SonyGeniDma *dma) {
    if (!g || !io || !io->read || !io->write || address > 0x7f ||
        (qup_version>>28)!=3u || qup_version<0x30090000u) return -1;
    *g = (SonyGeniI2c){0};
    g->io = *io; g->address = address; g->phase = SonyGeniOffline;
    if (((rd(g,REVISION)>>8)&255u) != 3u || (!dma && rd(g,IF_DISABLE)&1u) ||
        !(rd(g,CLOCK)&1u) || !rd(g,SCL) || rd(g,STATUS)&1u) return -1;
    if(dma) {
        if(!dma->tx || !dma->rx || !dma->tx_physical || !dma->rx_physical ||
           dma->capacity<1024u || !dma->clean || !dma->prepare_rx || !dma->invalidate ||
           dma->tx_physical>=(1ull<<40) || dma->rx_physical>=(1ull<<40) ||
           dma->capacity>(1ull<<40)-dma->tx_physical || dma->capacity>(1ull<<40)-dma->rx_physical)return -1;
        g->dma=*dma;g->dma_mode=1;
    }
    const uint32_t tx_parameter=rd(g,TX_PARAM),rx_parameter=rd(g,RX_PARAM);
    const uint32_t depth_mask=qup_version>=0x300a0000u?255u:63u;
    if(((tx_parameter>>24)&63u)!=32u || ((rx_parameter>>24)&63u)!=32u)return -1;
    g->tx_depth = (tx_parameter>>16)&depth_mask;
    g->rx_depth = (rx_parameter>>16)&depth_mask;
    if (!g->tx_depth || !g->rx_depth || (!dma && (rd(g,TX_STATUS)&0xfffffffu ||
        rd(g,RX_STATUS)&0x1ffffffu))) return -1;
    wr(g,GSI_EN,0);wr(g,DMA_MODE,dma?1:0);
    wr(g,TX_PACK0,0x7f8fe); wr(g,TX_PACK1,0xffefe);
    wr(g,RX_PACK0,0x7f8fe); wr(g,RX_PACK1,0xffefe); wr(g,BYTE_GRAN,0);
    const uint32_t receive_mark=g->rx_depth>2 ? g->rx_depth-2 : 1;
    wr(g,TX_WM,0); wr(g,RX_WM,receive_mark);
    wr(g,RX_RFR,g->rx_depth>1 ? g->rx_depth-1 : 1);wr(g,CLEAR,UINT32_MAX);
     /* Sony Linux geni_se_select_dma_mode and QcomGeniSpi disable CMD_DONE
      * in SE DMA mode. The direction's DMA_DONE is the transfer completion. */
     wr(g,IRQ_EN,dma?(CANCEL|ABORT|ERRORS):WANTED);
    /* On these engines top-level gating also gates status visibility. The owner
     * masks the GIC SPI; SE_IRQ_EN=0 is not a valid polling mode on hardware. */
    wr(g,SE_IRQ_EN,dma?15u:4u);
    g->phase = SonyGeniIdle;
    return 0;
}
int sony_geni_prepare(SonyGeniI2c *g,const SonyGeniIo *io,uint8_t address,uint32_t version) {
    return prepare(g,io,address,version,0);
}
int sony_geni_prepare_dma(SonyGeniI2c *g,const SonyGeniIo *io,uint8_t address,uint32_t version,const SonyGeniDma *dma) {
    if(!dma)return -1;
    return prepare(g,io,address,version,dma);
}
static void dma_tx(SonyGeniI2c *g) {
    for(unsigned i=0;i<g->tx_length;++i)g->dma.tx[i]=g->tx[i];
    g->dma.clean(g->dma.context,g->dma.tx,g->tx_length);
    wr(g,DMA_TX_CLEAR,UINT32_MAX);wr(g,DMA_TX_ENABLE,7);
    wr(g,DMA_TX_PTR,(uint32_t)g->dma.tx_physical);wr(g,DMA_TX_PTR_H,(uint32_t)(g->dma.tx_physical>>32));
    wr(g,DMA_TX_ATTR,1);wr(g,DMA_TX_LEN,g->tx_length);
    g->dma_started=1;
}
static void read_command(SonyGeniI2c *g) {
    g->phase=SonyGeniRx;g->command_done=g->dma_done=0;wr(g,RX_LEN,g->rx_length);
    wr(g,CMD,(2u<<27)|(uint32_t)g->address<<9);
    if(g->dma_mode) {
        g->dma.prepare_rx(g->dma.context,g->dma.rx,g->rx_length);
        wr(g,DMA_RX_CLEAR,UINT32_MAX);wr(g,DMA_RX_ENABLE,7);
        wr(g,DMA_RX_PTR,(uint32_t)g->dma.rx_physical);wr(g,DMA_RX_PTR_H,(uint32_t)(g->dma.rx_physical>>32));
        wr(g,DMA_RX_ATTR,0);wr(g,DMA_RX_LEN,g->rx_length);g->dma_started=1;
    }
}

static int start(SonyGeniI2c *g) {
    if (rd(g,STATUS)&1u) {g->phase=SonyGeniOffline; return -1;}
    g->tx_done=g->rx_done=0;g->command_done=g->dma_done=0;g->error=SonyGeniOk;g->failure_status=0;
    wr(g,CLEAR,UINT32_MAX);
    if(g->dma_mode){wr(g,DMA_TX_CLEAR,UINT32_MAX);wr(g,DMA_RX_CLEAR,UINT32_MAX);}
    wr(g,TX_LEN,g->tx_length);
    g->phase=SonyGeniTx;
    wr(g,CMD,(1u<<27) | (uint32_t)g->address<<9 | (g->read_transfer ? 4u : 0u));
    if(g->dma_mode)dma_tx(g);else wr(g,TX_WM,1);
    return 0;
}

int sony_geni_read(SonyGeniI2c *g, const uint8_t *command, uint32_t command_bytes,
                   uint8_t *bytes, uint32_t length) {
    if (!g || g->phase!=SonyGeniIdle || !command || !command_bytes || command_bytes>8u ||
        !bytes || !length || length>1024u) return -1;
    for (unsigned i=0;i<command_bytes;++i) g->command[i]=command[i];
    g->tx=g->command; g->tx_length=command_bytes; g->rx=bytes; g->rx_length=length;
    g->read_transfer=1;
    return start(g);
}

int sony_geni_write(SonyGeniI2c *g, const uint8_t *bytes, uint32_t length) {
    if (!g || g->phase!=SonyGeniIdle || !bytes || !length || length>1024u) return -1;
    g->tx=bytes; g->tx_length=length; g->rx=0; g->rx_length=0; g->read_transfer=0;
    return start(g);
}

static int finish(SonyGeniI2c *g) {
    wr(g,TX_WM,0);
    if (g->error && !g->dma_mode) {
        const uint32_t words=rd(g,RX_STATUS)&0x1ffffffu;
        if (words>g->rx_depth || rd(g,STATUS)&1u) {
            g->phase=SonyGeniOffline; ++g->failed; g->tx=0; g->rx=0;
            wr(g,IRQ_EN,0); return SonyGeniFailed;
        }
        for (uint32_t i=0;i<words;++i) (void)rd(g,RX_FIFO);
        wr(g,CLEAR,UINT32_MAX);
    }
    g->tx=0; g->rx=0;
    /* Failed DMA stays pinned by the owner even after the command's cancel ACK:
     * that ACK alone does not prove the independent DMA FSM stopped. */
    g->phase=SonyGeniIdle;
    if (g->error) {++g->failed; return SonyGeniFailed;}
    ++g->done;
    return SonyGeniDone;
}

static int drain(SonyGeniI2c *g) {
    const uint32_t status=rd(g,RX_STATUS), words=status&0x1ffffffu;
    if (words>g->rx_depth) return -1;
    /* RX_LAST_BYTE_VALID [30:28] counts valid bytes in the final partial FIFO
     * word when RX_LAST [31] is set. Reading padding must not hide a short read. */
    const unsigned valid=(status>>28)&7u;
    if (valid>4u) return -1;
    for (uint32_t i=0;i<words;++i) {
        const uint32_t value=rd(g,RX_FIFO);
        const unsigned bytes=((status>>31) && i+1==words && valid) ? valid : 4u;
        for (unsigned k=0;k<bytes;++k) {
            if (g->rx_done>=g->rx_length) return -1;
            g->rx[g->rx_done++]=(uint8_t)(value>>(8*k));
        }
    }
    return 0;
}

static int cancel(SonyGeniI2c *g, unsigned error, uint32_t status) {
    g->error=(uint8_t)error; g->failure_status=status;
    wr(g,TX_WM,0); g->phase=SonyGeniCancel; wr(g,CTRL,4u);
    return SonyGeniPending;
}

int sony_geni_poll(SonyGeniI2c *g) {
    if (!g || g->phase==SonyGeniOffline) return SonyGeniFailed;
    if (g->phase==SonyGeniIdle) return SonyGeniPending;
    const uint32_t status=rd(g,IRQ);g->last_irq=status;
    uint32_t tx_status=0,rx_status=0;
    if(g->dma_mode) {
        tx_status=rd(g,DMA_TX_STATUS);rx_status=rd(g,DMA_RX_STATUS);
        g->last_dma_tx=tx_status;g->last_dma_rx=rx_status;
        if(tx_status)wr(g,DMA_TX_CLEAR,tx_status);
        if(rx_status)wr(g,DMA_RX_CLEAR,rx_status);
    }
    if (!status && !tx_status && !rx_status) return SonyGeniPending;
    /* Drain before acknowledging RX watermark/last. There are at most255 words
     * per observation, even if a broken engine returns an impossible counter. */
    if (g->phase==SonyGeniCancel || g->phase==SonyGeniAbort) {
        wr(g,CLEAR,status);
        if (status & (g->phase==SonyGeniCancel ? CANCEL : ABORT)) return finish(g);
        return SonyGeniPending;
    }
    if (status&ERRORS || (g->dma_mode && ((tx_status&4u) || (rx_status&(4u|(0x3fu<<5)|(3u<<12)))))) {
        wr(g,CLEAR,status);return cancel(g,SonyGeniBusError,status);
    }
    if(g->dma_mode) {
        wr(g,CLEAR,status);
        if(status&DONE)g->command_done=1;
        if((g->phase==SonyGeniTx?tx_status:rx_status)&1u)g->dma_done=1;
        if(!g->dma_done)return SonyGeniPending;
        if(g->phase==SonyGeniTx) {
            g->tx_done=g->tx_length;
            if(!g->read_transfer)return finish(g);
            read_command(g);return SonyGeniPending;
        }
        g->dma.invalidate(g->dma.context,g->dma.rx,g->rx_length);
        for(unsigned i=0;i<g->rx_length;++i)g->rx[i]=g->dma.rx[i];
        g->rx_done=g->rx_length;return finish(g);
    }
    if (g->phase==SonyGeniTx) {
        if (status&TX_EVENT) {
            const uint32_t used=rd(g,TX_STATUS)&0xfffffffu;
            if (used>g->tx_depth) {wr(g,CLEAR,status); return cancel(g,SonyGeniInvalidFifo,status);}
            for (uint32_t room=g->tx_depth-used; room && g->tx_done<g->tx_length; --room) {
                uint32_t word=0;
                for (unsigned k=0;k<4 && g->tx_done<g->tx_length;++k)
                    word|=(uint32_t)g->tx[g->tx_done++]<<(8*k);
                wr(g,TX_FIFO,word);
            }
            if (g->tx_done==g->tx_length) wr(g,TX_WM,0);
        }
        wr(g,CLEAR,status);
        if (!(status&DONE)) return SonyGeniPending;
        if (g->tx_done!=g->tx_length) return cancel(g,SonyGeniEarlyDone,status);
        if (!g->read_transfer) return finish(g);
        read_command(g);
        return SonyGeniPending;
    }
    if (g->phase==SonyGeniRx) {
        if (status&(RX_EVENTS|DONE)) {
            if (drain(g)) {wr(g,CLEAR,status); return cancel(g,SonyGeniInvalidFifo,status);}
        }
        wr(g,CLEAR,status);
        if (!(status&DONE)) return SonyGeniPending;
        if (g->rx_done!=g->rx_length) return cancel(g,SonyGeniShortRead,status);
        return finish(g);
    }
    wr(g,CLEAR,status);
    return cancel(g,SonyGeniEarlyDone,status);
}

int sony_geni_timeout(SonyGeniI2c *g) {
    if (!g || g->phase==SonyGeniOffline) return SonyGeniFailed;
    if (g->phase==SonyGeniIdle) return SonyGeniPending;
    if (g->phase==SonyGeniAbort) {
        g->error=SonyGeniUnstopped; g->phase=SonyGeniOffline; ++g->failed;
        g->tx=0; g->rx=0; wr(g,IRQ_EN,0);
        return SonyGeniFailed;
    }
    if (g->phase==SonyGeniCancel) {g->phase=SonyGeniAbort; wr(g,CTRL,2u); return SonyGeniPending;}
    ++g->timeouts;
    return cancel(g,SonyGeniTimeout,rd(g,IRQ));
}
