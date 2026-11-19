/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include "Sm8550AppsSmmu.h"

static uint32_t reg[0x100000 / 4];
static unsigned writes;
static uint32_t read_reg(void *ctx, uint32_t offset) {
    (void)ctx;
    assert(offset % 4 == 0 && offset / 4 < sizeof reg / sizeof *reg);
    return reg[offset / 4];
}
static void write_reg(void *ctx, uint32_t offset, uint32_t value) {
    read_reg(ctx, offset);
    ++writes;
    reg[offset / 4] = value;
}

int main(void) {
    const struct sm8550_apps_smmu_io io = {0, read_reg, write_reg};
    struct sm8550_apps_smmu_domain domain;
    const uint16_t sid = 0x1401;
    reg[0x20 / 4] = 1u << 30 | 1u << 27 | 1u << 8 | 16u;
    reg[0x24 / 4] = 1u << 16 | 8u;
    reg[0x28 / 4] = 1u << 12;
    reg[0] = 1u << 10;
#ifdef OLD_PICKER
    assert(sm8550_apps_smmu_pick(&io, &sid, 1, &domain) == -ENOTSUP && writes == 0);
#else
    assert(sm8550_apps_smmu_pick(&io, &sid, 1, &domain) == 0 && writes == 0);
    assert(domain.bank == 1 && domain.slots[0] == 0);
    assert(sm8550_apps_smmu_route(&io, &domain) == 0 && writes == 2);
    assert(reg[0] == (1u << 10) && reg[0x800 / 4] == (0x80000000u | sid));
    assert(sm8550_apps_smmu_pick(&io, &sid, 1, &domain) == -EBUSY && writes == 2);
    for (unsigned i = 0; i != 4; ++i) {
        const uint32_t rejected[] = {1u << 10 | 1u << 3, 0, 1u << 10 | 1u, UINT32_MAX};
        reg[0] = rejected[i];
        assert(sm8550_apps_smmu_pick(&io, &sid, 1, &domain) == -ENOTSUP && writes == 2);
    }
#endif
    return 0;
}
