/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include "GeniInit.h"
static uint16_t le16(const uint8_t *p){return (uint16_t)(p[0]|(uint16_t)p[1]<<8);}
static uint32_t le32(const uint8_t *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static int span(size_t length,unsigned start,unsigned bytes){return start>=28u && start<=length && bytes<=length-start;}

int sony_geni_firmware_parse(const uint8_t *bytes,size_t length,SonyGeniFirmware *out) {
    if(!bytes || !out || length<28 || length>16384 || le32(bytes)!=0x57464553u ||
       le32(bytes+4)!=1 || le16(bytes+12)!=3)return SonyGeniInitHeader;
    SonyGeniFirmware fw={0};
    fw.core_version=le32(bytes+8);fw.revision=(uint8_t)le16(bytes+14);
    fw.config_revision=(uint8_t)le16(bytes+16);fw.words=le16(bytes+18);
    fw.word_offset=le16(bytes+20);fw.pairs=le16(bytes+22);
    fw.index_offset=le16(bytes+24);fw.value_offset=le16(bytes+26);
    if(!fw.words || fw.words>304 || !fw.pairs || fw.pairs>256 ||
       fw.word_offset%4 || fw.value_offset%4 ||
       !span(length,fw.word_offset,fw.words*4u) || !span(length,fw.value_offset,fw.pairs*4u) ||
       !span(length,fw.index_offset,fw.pairs))return SonyGeniInitHeader;
    const unsigned starts[3]={fw.word_offset,fw.value_offset,fw.index_offset};
    const unsigned sizes[3]={fw.words*4u,fw.pairs*4u,fw.pairs};
    for(unsigned i=0;i<3;++i)for(unsigned j=i+1;j<3;++j)
        if(starts[i]<starts[j]+sizes[j] && starts[j]<starts[i]+sizes[i])return SonyGeniInitHeader;
    uint8_t seen[256]={0};
    for(unsigned i=0;i<fw.pairs;++i) {
        const unsigned index=bytes[fw.index_offset+i];
        if(seen[index])return SonyGeniInitHeader;seen[index]=1;
    }
    for(unsigned i=0;i<fw.words;++i)
        /* Kailua's actual image uses bit23. The older Napali HAL's23-bit RAM
         * field mask must not truncate this24-bit instruction stream. */
        if(le32(bytes+fw.word_offset+4*i)&~0xffffffu)return SonyGeniInitHeader;
    *out=fw;return SonyGeniInitOk;
}

static uint32_t rd(const SonyGeniIo *io,unsigned at){return io->read(io->context,at);}
static void wr(const SonyGeniIo *io,unsigned at,uint32_t value){io->write(io->context,at,value);}
static void update(const SonyGeniIo *io,unsigned at,uint32_t mask,uint32_t value){wr(io,at,(rd(io,at)&~mask)|(value&mask));}
int sony_geni_firmware_init(const SonyGeniIo *se,const SonyGeniIo *wrapper,
                            const uint8_t *bytes,size_t length,unsigned *loaded) {
    SonyGeniFirmware fw={0};
    if(!se || !se->read || !se->write || !wrapper || !wrapper->read || !wrapper->write ||
       !loaded || sony_geni_firmware_parse(bytes,length,&fw))return SonyGeniInitHeader;
    *loaded=0;
    if(rd(se,0x40)&0x1001u)return SonyGeniInitBusy;
    const uint32_t proto=(rd(se,0x68)>>8)&255u;
    const uint32_t hardware=rd(wrapper,4);
    if((hardware>>28)!=3u || hardware<fw.core_version)return SonyGeniInitHardware;
    /* Do not replace a different live protocol, or fabricate a ROM/minicore image. */
    if(proto && proto!=3u)return SonyGeniInitProtocol;
    /* OEM fw_init belongs to boot firmware, not this non-secure XNU context.
     * Sheng hardware reports0x2008 data-aborts. Do not touch protected aliases
     * or replace secure-world firmware. FIFO-disabled engines use SE DMA. */
    if(!proto)return SonyGeniInitProtocol;
    wr(se,0xe18,0);
    update(se,0x28,0x7fu,0x7fu);update(se,0xe30,15u,15u);
    /* Restore all controller outputs, not just an all-zero inherited value.
     * The documented normal initialization sets these then forces idle IO. */
    update(se,0x24,0x7fu,0x7fu);
    wr(se,0x20,1);
    wr(se,0x618,UINT32_MAX);wr(se,0x648,UINT32_MAX);
    if(((rd(se,0x68)>>8)&255u)!=3u)return SonyGeniInitReadback;
    return SonyGeniInitOk;
}

int sony_geni_tcxo_config(uint32_t cfg) {
    return !(cfg&0x3700u) && (cfg&31u)<=1u;
}
int sony_geni_tcxo_level(const uint32_t *configs,unsigned count) {
    if(!configs || !count || count>8u)return -1;
    for(unsigned i=0;i<count;++i)if(sony_geni_tcxo_config(configs[i]))return (int)i;
    return -1;
}
