// SPDX-License-Identifier: BSD-2-Clause-Patent
// CPU-owned readonly block bytes. Every copied hit is reverified by the caller.
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>

struct D27VerifiedReadCache {
    static constexpr uint64_t blockBytes=4096,slots=8192;
    static constexpr size_t bytes=blockBytes*slots,tagBytes=slots*sizeof(uint64_t);
    unsigned char *data=nullptr;
    uint64_t *tags=nullptr;
    void initialize(void *storage,void *identities) {
        data=static_cast<unsigned char *>(storage);tags=static_cast<uint64_t *>(identities);
        if(tags)for(uint64_t i=0;i<slots;++i)tags[i]=UINT64_MAX;
    }
    bool copy(uint64_t first,uint32_t length,void *output) const {
        if(!data || !tags || !output || !length || length%blockBytes || first>UINT64_MAX-length/blockBytes)return false;
        for(uint64_t i=0;i<length/blockBytes;++i)
            if(tags[(first+i)%slots]!=first+i)return false;
        for(uint64_t i=0;i<length/blockBytes;++i)
            memcpy(static_cast<unsigned char *>(output)+i*blockBytes,data+((first+i)%slots)*blockBytes,blockBytes);
        return true;
    }
    void storeVerified(uint64_t first,uint32_t length,const void *input) {
        if(!data || !tags || !input || !length || length%blockBytes || first>UINT64_MAX-length/blockBytes)return;
        for(uint64_t i=0;i<length/blockBytes;++i) {
            const uint64_t slot=(first+i)%slots;
            memcpy(data+slot*blockBytes,static_cast<const unsigned char *>(input)+i*blockBytes,blockBytes);
            tags[slot]=first+i;
        }
    }
};
