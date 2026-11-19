/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include "SonyWcnPower.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
struct Model {unsigned live, calls, clocks, pcie; int fail_on, fail_off;};
static int vote(void *context, unsigned rail, bool on) {
    struct Model *m = context;
    ++m->calls;
    if ((on && m->fail_on == (int)rail) || (!on && m->fail_off == (int)rail)) return EIO;
    if (on) m->live |= 1u << rail;
    else m->live &= ~(1u << rail);
    return 0;
}
static int pcie(void *context, bool on) {((struct Model *)context)->pcie = on; return 0;}
static int clock_on(void *context) {++((struct Model *)context)->clocks; return 0;}
static void both(unsigned first) {
    struct Model m = {.fail_on=-1,.fail_off=-1};
    struct sony_wcn_power s = {0};
    const struct sony_wcn_power_ops ops={&m,vote,pcie,clock_on};
    assert(!sony_wcn_power_acquire(&s,&ops,first));
    unsigned calls=m.calls;
    assert(!sony_wcn_power_acquire(&s,&ops,first) && m.calls==calls);
    assert(!sony_wcn_power_acquire(&s,&ops,first^1));
    assert(s.owners==3 && s.live==63 && m.live==63 && m.clocks==1 && m.pcie);
    assert(!sony_wcn_power_release(&s,&ops,0));
    assert(s.owners==2 && s.live==0x3a && m.live==0x3a && !m.pcie);
    assert(!sony_wcn_power_release(&s,&ops,1));
    assert(!s.owners && !s.live && !m.live);
}
int main(void) {
    both(0);both(1);
    assert(sony_wcn_rails[0].microvolts==1000000);
    assert(sony_wcn_rails[2].microvolts==980000);
    assert(sony_wcn_rails[3].microvolts==950000);
    for(int i=0;i<6;++i) {
        struct Model m={.fail_on=i,.fail_off=-1};struct sony_wcn_power s={0};
        const struct sony_wcn_power_ops ops={&m,vote,pcie,clock_on};
        assert(sony_wcn_power_acquire(&s,&ops,0)==EIO);
        assert(!s.owners && !s.live && !m.live);
    }
    struct Model m={.fail_on=-1,.fail_off=-1};struct sony_wcn_power s={0};
    const struct sony_wcn_power_ops ops={&m,vote,pcie,clock_on};
    assert(!sony_wcn_power_acquire(&s,&ops,0));
    m.fail_off=4;
    assert(sony_wcn_power_release(&s,&ops,0)==EIO && s.owners==1 && s.live==16);
    /* A held ownership after a partial release must not fake a powered radio. */
    assert(!sony_wcn_power_acquire(&s,&ops,0) && s.live==63 && m.pcie);
    assert(sony_wcn_power_release(&s,&ops,0)==EIO && s.owners==1 && s.live==16);
    m.fail_off=-1;
    assert(!sony_wcn_power_release(&s,&ops,0) && !s.live && !s.owners);
    m.fail_on=5;m.fail_off=2;
    assert(sony_wcn_power_acquire(&s,&ops,0)==EIO && !s.owners && s.live==4 && s.cleanup_error==EIO);
    assert(sony_wcn_power_acquire(&s,&ops,0)==EIO && s.live==4);
    m.fail_on=m.fail_off=-1;
    assert(!sony_wcn_power_acquire(&s,&ops,1) && s.live==0x3a);
    assert(!sony_wcn_power_release(&s,&ops,1));
    assert(sony_wcn_power_acquire(&s,&ops,2)==EINVAL);
    puts("PASS Sony WCN: Sony voltages, both acquire orders, idempotence, partial vote rollback, pinned cleanup, release retry");
    return 0;
}
