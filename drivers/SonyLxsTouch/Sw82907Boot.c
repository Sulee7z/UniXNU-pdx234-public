/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include "Sw82907Boot.h"
int sw82907_boot_result(uint32_t status) {
    if(!status || status==UINT32_MAX || (status&2u))return Sw82907BootSkip;
    return (status&8u)?Sw82907BootCrcError:Sw82907BootOk;
}
int sw82907_code_crc_result(uint32_t status) {
    if(!status || status==UINT32_MAX)return Sw82907BootSkip;
    return (status&0x40u)?Sw82907BootOk:Sw82907BootCrcError;
}
int sw82907_version_supported(uint32_t version) {
    return ((version>>16)&255u)==10u && ((version>>24)&15u)==4u;
}
