// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <utility>
#include <vector>
#include "SmmuTakeover.h"
#include "SonySmmuTakeover.h"
int main()
{
    std::array<uint32_t, 0xd0000 / 4> r{};
    std::vector<std::pair<unsigned,uint32_t>> writes;
    unsigned drop = ~0U;
    auto reset = [&] {
        r.fill(0); writes.clear(); drop = ~0U;
        r[0x20 / 4] = 0x40000080; r[0x24 / 4] = 0x60000046; r[0x28 / 4] = 0x5111;
    };
    auto read = [&](unsigned at) { return r.at(at / 4); };
    auto write = [&](unsigned at, uint32_t v) { writes.emplace_back(at,v); if (at != drop) r.at(at/4) = v; };
    auto plan = [&] { return planSonyUfsSmmu(0x60, 0x880100000ULL, 0x22000, read); };
    auto firmware = [&] {
        reset(); r[0x800/4] = 0x80000060; r[0xc00/4] = 0x04000001;
        r[(128+1)*4096/4] = 0x21; // Firmware's enabled old context.
        r[(0x1000+4)/4] = 0x12345678;
    };
    reset(); auto p = plan(); assert(!p.mapping.error && !p.reroute);
    assert(!configureSonyUfsSmmu(p, 0x60, read, write));
    firmware(); p = plan(); assert(!p.mapping.error && p.reroute && p.mapping.bank == 69 && p.mapping.slot == 0);
    assert(!configureSonyUfsSmmu(p, 0x60, read, write));
    assert(read(0x800) == 0x80000060 && read(0xc00) == 0x04000045);
    assert(read((128+1)*4096) == 0x21 && read(0x1000+4) == 0x12345678);
    for (auto entry : writes) assert(entry.first != 0x800 && entry.first != (128+1)*4096 && entry.first != 0x1000+4);
    assert(writes.back().first == 0xc00); // Route published after new CB.
    // Other devices retain their old/shared context and SMR.
    firmware(); r[0x804/4] = 0x80000061; r[0xc04/4] = 1; p=plan();
    assert(!p.mapping.error && !configureSonyUfsSmmu(p,0x60,read,write));
    assert(read(0x804)==0x80000061 && read(0xc04)==1 && read((128+1)*4096)==0x21);
    // Masked or duplicate matching streams are not rehomed.
    firmware(); r[0x800/4]=0x80010060; assert(plan().mapping.error && writes.empty());
    firmware(); r[0x804/4]=0x80000060; r[0xc04/4]=2; assert(plan().mapping.error && writes.empty());
    // Never choose a bank held by another stream or enabled translation.
    firmware(); r[0x804/4]=0x80000061; r[0xc04/4]=69;
    r[(128+68)*4096/4]=1; p=plan(); assert(!p.mapping.error && p.mapping.bank==67);
    // Firmware can already use a high bank; it must be preserved even with M=0.
    firmware(); r[0xc00/4]=69; r[(128+69)*4096/4]=0;
    p=plan(); assert(!p.mapping.error && p.reroute && p.mapping.bank==68);
    assert(!configureSonyUfsSmmu(p,0x60,read,write)); assert(read((128+69)*4096)==0);
    // Hardware width failures never become reroute successes.
    firmware(); r[0x28/4]=0x5000; assert(plan().mapping.error && writes.empty());
    firmware(); for(unsigned k=0;k<8;++k) r[(128+69-k)*4096/4]=1;
    assert(plan().mapping.error && writes.empty());
    // Changed mapping between plan/configure: no writes.
    firmware(); p=plan(); r[0xc00/4]=2;
    assert(configureSonyUfsSmmu(p,0x60,read,write) && writes.empty());
    firmware(); p=plan(); r[0x804/4]=0x80000062; r[0xc04/4]=p.mapping.bank;
    assert(configureSonyUfsSmmu(p,0x60,read,write) && writes.empty());
    firmware(); p=plan(); r[0x804/4]=0x80010060; r[0xc04/4]=2;
    assert(configureSonyUfsSmmu(p,0x60,read,write) && writes.empty());
    // A CB configuration refusal never publishes a new route.
    for(unsigned at : {0x1800+4*69, 0x1000+4*69}) {
        firmware(); p=plan(); drop=at;
        assert(configureSonyUfsSmmu(p,0x60,read,write)); assert(read(0xc00)==0x04000001);
    }
    firmware(); p=plan(); drop=0xc00;
    assert(configureSonyUfsSmmu(p,0x60,read,write)); assert(read(0xc00)==0x04000001);
    puts("PASS: exact firmware SID reroute, old/shared context preservation, duplicate/masked/racing mappings, widths, blocked writes and rollback");
}
