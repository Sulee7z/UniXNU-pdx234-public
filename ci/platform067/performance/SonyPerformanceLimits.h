// SPDX-License-Identifier: BSD-2-Clause-Patent
#ifndef PDX_PERFORMANCE_LIMITS_H
#define PDX_PERFORMANCE_LIMITS_H
static inline unsigned pdx_performance_samples(unsigned requested) {
    // Ten seconds per sample. Zero disables the observer, not the governors.
    return requested > 60 ? 60 : requested;
}
static inline bool pdx_performance_display_powered(const char *text,unsigned cap) {
    constexpr char wanted[]="powered=1 ";
    for(unsigned p=0;p+sizeof(wanted)<=cap && text[p];++p) {
        unsigned k=0;
        while(k+1<sizeof(wanted) && text[p+k]==wanted[k])++k;
        if(k+1==sizeof(wanted))return true;
    }
    return false;
}
#endif
