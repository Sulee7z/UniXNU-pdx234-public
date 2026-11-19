/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include "HidTouchReport.h"
static int contains(const SonyHidContact *contacts, unsigned count, unsigned id) {
    for (unsigned i=0;i<count;++i) if (contacts[i].id==id) return 1;
    return 0;
}
static void finger(uint8_t *bytes, const SonyHidContact *contact, unsigned tip) {
    bytes[0]=(uint8_t)(2u | tip); bytes[1]=contact->id;
    bytes[2]=(uint8_t)contact->x; bytes[3]=(uint8_t)(contact->x>>8);
    bytes[4]=(uint8_t)contact->y; bytes[5]=(uint8_t)(contact->y>>8);
}
static void make(const SonyHidTouchState *previous, const SonyHidContact *contacts,
                 unsigned count, uint8_t *bytes, SonyHidTouchState *after) {
    bytes[0]=3;
    unsigned slot=0;
    after->count=(uint8_t)count;
    for (unsigned i=0;i<count;++i) {
        finger(bytes+1+6*slot++,&contacts[i],1); after->contacts[i]=contacts[i];
    }
    for (unsigned i=0;i<previous->count;++i)
        if (!contains(contacts,count,previous->contacts[i].id))
            finger(bytes+1+6*slot++,&previous->contacts[i],0);
    bytes[61]=(uint8_t)slot;
}
int sony_hid_touch_plan(const SonyHidTouchState *previous, const SonyHidContact *contacts,
                         unsigned count, SonyHidTouchPlan *plan) {
    if (!previous || !plan || previous->count>SONY_HID_CONTACTS || count>SONY_HID_CONTACTS ||
        (!contacts && count)) return -1;
    for (unsigned i=0;i<count;++i) {
        if (contacts[i].x>32767 || contacts[i].y>32767 || contains(contacts,i,contacts[i].id)) return -1;
    }
    for (unsigned i=0;i<previous->count;++i)
        if (previous->contacts[i].x>32767 || previous->contacts[i].y>32767 ||
            contains(previous->contacts,i,previous->contacts[i].id)) return -1;
    *plan=(SonyHidTouchPlan){0};
    if (!count && !previous->count) return 0;
    unsigned missing=0;
    for (unsigned i=0;i<previous->count;++i)
        missing+=!contains(contacts,count,previous->contacts[i].id);
    if (count+missing>SONY_HID_CONTACTS) {
        SonyHidContact kept[SONY_HID_CONTACTS]; unsigned n=0;
        for (unsigned i=0;i<count;++i)
            if (contains(previous->contacts,previous->count,contacts[i].id)) kept[n++]=contacts[i];
        make(previous,kept,n,plan->reports[0],&plan->after[0]);
        make(&plan->after[0],contacts,count,plan->reports[1],&plan->after[1]);
        plan->count=2;
    } else {
        make(previous,contacts,count,plan->reports[0],&plan->after[0]); plan->count=1;
    }
    return 0;
}
