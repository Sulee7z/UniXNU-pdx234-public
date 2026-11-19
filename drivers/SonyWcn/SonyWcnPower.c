/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include "SonyWcnPower.h"
#ifdef KERNEL
#include <sys/errno.h>
#else
#include <errno.h>
#endif

/* live.dtb: chip_cfg@1 (1107), bt_kiwi. PMIC e/g/b identities resolved through
 * the actual supply phandle's parent qcom,resource-name, never from sheng.
 * bit 0 WLAN; bit 1 BT. BT has three names for the same smpe4 supply. */
const struct sony_wcn_rail sony_wcn_rails[SONY_WCN_RAILS] = {
    {"smpg5", 1000000, 0x2fc, 1},
    {"ldob15",1800000, 0x2eb, 3},
    {"smpg2",  980000, 0x2f9, 1},
    {"smpe4",  950000, 0x2f2, 3},
    {"smpg4", 1350000, 0x2fb, 3},
    {"smpg6", 1900000, 0x2fd, 3},
};

static unsigned required(unsigned owners) {
    unsigned mask = 0;
    for (unsigned i = 0; i < SONY_WCN_RAILS; ++i)
        if (sony_wcn_rails[i].radios & owners) mask |= 1u << i;
    return mask;
}
static int validate(struct sony_wcn_power *s, const struct sony_wcn_power_ops *p, unsigned radio) {
    return !s || !p || !p->vote || !p->pcie || !p->sleep_clock || radio > SONY_WCN_BLUETOOTH ? EINVAL : 0;
}
static int retire(struct sony_wcn_power *s, const struct sony_wcn_power_ops *p, unsigned keep) {
    int first = 0;
    for (unsigned step = 0; step < SONY_WCN_RAILS; ++step) {
        const unsigned i = SONY_WCN_RAILS - step - 1, bit = 1u << i;
        if (!(s->live & bit) || (keep & bit)) continue;
        int e = p->vote(p->context, i, false);
        if (!e) s->live &= ~bit;
        else if (!first) first = e;
    }
    s->cleanup_error = first;
    return first;
}
int sony_wcn_power_acquire(struct sony_wcn_power *s, const struct sony_wcn_power_ops *p, unsigned radio) {
    int e = validate(s, p, radio);
    if (e) return e;
    const unsigned bit = 1u << radio;
    if ((s->owners & bit) && !s->cleanup_error &&
        (s->live & required(s->owners)) == required(s->owners) &&
        (radio != SONY_WCN_WLAN || s->pcie)) return 0;
    /* A failed rollback pins live resources. Retire them before a fresh start. */
    if (s->cleanup_error) {
        e = retire(s, p, required(s->owners));
        if (e) return e;
    }
    if (!s->owners && (e = p->sleep_clock(p->context))) return e;
    const unsigned before = required(s->owners), need = required(s->owners | bit);
    for (unsigned i = 0; i < SONY_WCN_RAILS; ++i) {
        if (!(need & (1u << i)) || (s->live & (1u << i))) continue;
        e = p->vote(p->context, i, true);
        if (e) break;
        s->live |= 1u << i;
    }
    if (!e && radio == SONY_WCN_WLAN && !s->pcie) {
        e = p->pcie(p->context, true);
        if (!e) s->pcie = true;
    }
    if (e) {
        /* The first operational error survives a separate rollback error. */
        (void)retire(s, p, before);
        return e;
    }
    s->owners |= bit;
    return 0;
}
int sony_wcn_power_release(struct sony_wcn_power *s, const struct sony_wcn_power_ops *p, unsigned radio) {
    int e = validate(s, p, radio);
    if (e) return e;
    const unsigned bit = 1u << radio;
    if (!(s->owners & bit)) return retire(s, p, required(s->owners));
    if (radio == SONY_WCN_WLAN && s->pcie) {
        e = p->pcie(p->context, false);
        if (e) return e;
        s->pcie = false;
    }
    e = retire(s, p, required(s->owners & ~bit));
    /* Keep the ownership on failure so release can be retried. */
    if (!e) s->owners &= ~bit;
    return e;
}
