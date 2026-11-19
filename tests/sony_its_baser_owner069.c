/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <inttypes.h>
#include <stdio.h>
#include "SonyIts.h"

static int check_owner(uint64_t value,int expected){
    const int actual=sony_its_baser_has_owner(value);
    if(actual==expected)return 0;
    fprintf(stderr,"BASER 0x%016" PRIx64 ": expected owner=%d, got %d\n",value,expected,actual);
    return 1;
}

int main(void){
    const uint64_t presets[]={
        0,
        (1ULL<<56)|(7ULL<<48),             /* Device, 8-byte entries, 4 KiB pages. */
        (4ULL<<56)|(15ULL<<48)|(2ULL<<8),   /* Collection, 16-byte entries, 64 KiB pages. */
    };
    unsigned failures=0;
    for(unsigned i=0;i<sizeof(presets)/sizeof(presets[0]);i++){
        failures+=check_owner(presets[i],0);
        for(unsigned bit=0;bit<64;bit++){
            const int expected=bit==63 || (bit>=12 && bit<=47);
            failures+=check_owner(presets[i]|(UINT64_C(1)<<bit),expected);
        }
    }
    const uint64_t legacy_mask=0x0000ffffffff0000ULL;
    for(unsigned bit=12;bit<=15;bit++){
        const uint64_t stale_address=UINT64_C(1)<<bit;
        if(stale_address&legacy_mask){
            fprintf(stderr,"legacy negative control unexpectedly sees bit%u\n",bit);
            ++failures;
        }
        failures+=check_owner(stale_address,1);
    }
    if(failures)return 1;
    puts("PASS Sony ITS BASER owner: valid/address bits over zero and typed presets; old bits12-15 leak reproduced");
    return 0;
}
