// SPDX-License-Identifier: BSD-2-Clause-Patent
// Extend sheng's planner for an exact UFS SID already owned by boot firmware.
// Caller has stopped both request queues. Never disable the old context bank:
// it can still belong to another device. Only this exact stream is rerouted.
struct SonyUfsSmmuPlan {
    UfsSmmuPlan mapping;
    bool reroute = false;
    uint32_t originalSmr = 0, originalS2cr = 0;
};

template<class Read>
static SonyUfsSmmuPlan planSonyUfsSmmu(uint16_t stream, uint64_t dma, uint64_t bytes, Read read)
{
    SonyUfsSmmuPlan result;
    result.mapping = planUfsSmmu(stream, dma, bytes, read);
    if (!result.mapping.error ||
        (__builtin_strcmp(result.mapping.error, "conflicting UFS stream mapping") &&
         __builtin_strcmp(result.mapping.error, "reserved context bank already used") &&
         __builtin_strcmp(result.mapping.error, "reserved context bank not bypass")))
        return result;
    unsigned groups = read(0x20) & 255;
    if (groups > 128) groups = 128; // Same hardware-access bound as sheng.
    unsigned slot = 0xffffffffU, matches = 0;
    for (unsigned i = 0; i < groups; ++i) {
        const uint32_t smr = read(0x800 + 4 * i);
        if (!(smr & 0x80000000U)) continue;
        const uint32_t mask = (smr >> 16) & 0x7fff;
        if (((smr ^ stream) & 0xffff & ~mask) != 0) continue;
        ++matches;
        if (mask || (smr & 0xffff) != stream) return result;
        slot = i;
    }
    if (matches != 1) return result;
    const uint32_t smr = read(0x800 + 4 * slot), s2cr = read(0xc00 + 4 * slot);
    if (((s2cr >> 16) & 3) == 3) return result;
    // Hide only our exact stream during free-bank selection. All other streams
    // remain visible, including any sharing its former context bank.
    const unsigned oldBank = s2cr & 255;
    const unsigned pages = 1U << (((read(0x24) >> 28) & 7) + 1);
    const bool oldContext = ((s2cr >> 16) & 3) == 0;
    if (oldContext && oldBank >= (read(0x24) & 255)) return result;
    auto withoutOurStream = [&](unsigned offset) -> uint32_t {
        if (offset == 0x800 + 4 * slot) return 0;
        // Reserve the former bank regardless of SCTLR.M. Firmware may have
        // disabled translation but still rely on its other attributes.
        if (oldContext && offset == (pages + oldBank) * 4096) return read(offset) | 1U;
        return read(offset);
    };
    UfsSmmuPlan candidate = planUfsSmmu(stream, dma, bytes, withoutOurStream);
    if (candidate.error) {
        result.mapping = candidate;
        return result;
    }
    // An active old bank must never be selected, even when firmware left it
    // referenced by this stream alone. The upstream planner checks SCTLR.M.
    if (((s2cr >> 16) & 3) == 0 && candidate.bank == oldBank) {
        result.mapping.error = "firmware UFS context cannot be overwritten";
        return result;
    }
    candidate.slot = slot;
    candidate.reuse = false;
    result.mapping = candidate;
    result.reroute = true;
    result.originalSmr = smr;
    result.originalS2cr = s2cr;
    return result;
}

template<class Read, class Write>
static const char *configureSonyUfsSmmu(const SonyUfsSmmuPlan &plan, uint16_t stream, Read read, Write write)
{
    const UfsSmmuPlan &p = plan.mapping;
    if (p.error) return p.error;
    if (!plan.reroute) return configureUfsSmmu(p, stream, read, write);
    const unsigned smrOffset = 0x800 + 4 * p.slot, routeOffset = 0xc00 + 4 * p.slot;
    if (read(smrOffset) != plan.originalSmr || read(routeOffset) != plan.originalS2cr)
        return "firmware UFS mapping changed after planning";
    const unsigned cb = (p.pages + p.bank) * 4096;
    // Recheck exclusivity immediately before configuring the new bank.
    unsigned groups = read(0x20) & 255;
    if (groups > 128) groups = 128;
    for (unsigned i = 0; i < groups; ++i) {
        const uint32_t smr = read(0x800 + 4 * i);
        if (!(smr & 0x80000000U)) continue;
        const uint32_t mask = (smr >> 16) & 0x7fff;
        if (i != p.slot && ((smr ^ stream) & 0xffff & ~mask) == 0)
            return "another mapping acquired the UFS stream";
        const uint32_t route = read(0xc00 + 4 * i);
        if (((route >> 16) & 3) == 0 && (route & 255) == p.bank)
            return "new UFS context acquired by another stream";
    }
    if (read(cb) & 1) return "new UFS context translation enabled";
    write(cb, 0);
    if (read(cb) != 0) return "SMMU bypass disable readback";
    write(0x1800 + 4 * p.bank, 1);
    write(0x1000 + 4 * p.bank, 0x10000);
    if (read(0x1800 + 4 * p.bank) != 1 || read(0x1000 + 4 * p.bank) != 0x10000 || read(cb) != 0)
        return "SMMU VA64 bypass readback";
    if (read(smrOffset) != plan.originalSmr || read(routeOffset) != plan.originalS2cr)
        return "firmware UFS mapping changed before reroute";
    // Keep all non-routing attributes. Publish once, after CB configuration;
    // exact SMR and the old context registers are never written.
    const uint32_t route = (plan.originalS2cr & ~0x000300ffU) | p.bank;
    write(routeOffset, route);
    if (read(routeOffset) != route || read(smrOffset) != plan.originalSmr) {
        write(routeOffset, plan.originalS2cr);
        if (read(routeOffset) != plan.originalS2cr)
            return "SMMU UFS reroute and rollback refused";
        return "SMMU UFS reroute refused; original restored";
    }
    return nullptr;
}
