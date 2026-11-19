/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "HIDLib.h"
#include "HidTouchReport.h"
#include "descriptors.h"
static SInt32 value(HIDPreparsedDataRef parsed,uint32_t collection,uint32_t page,uint32_t usage,uint8_t *report) {
    SInt32 result=-1;
    assert(!HIDGetUsageValue(kHIDInputReport,page,collection,usage,&result,parsed,report,SONY_HID_REPORT_BYTES));
    return result;
}
int main(void) {
    uint8_t combined[sizeof(descriptor)+sizeof(touchDescriptor)];
    memcpy(combined,descriptor,sizeof(descriptor));memcpy(combined+sizeof(descriptor),touchDescriptor,sizeof(touchDescriptor));
    HIDPreparsedDataRef parsed=NULL;
    assert(!HIDOpenReportDescriptor(combined,sizeof(combined),&parsed,0));
    IOByteCount length=0;assert(!HIDGetReportLength(kHIDInputReport,3,&length,parsed) && length==62);
    HIDPreparsedDataPtr data=(HIDPreparsedDataPtr)parsed;
    unsigned fingers[10],count=0;
    for(unsigned i=0;i<(unsigned)data->collectionCount;++i) {
        HIDCollection *c=&data->collections[i];
        if(c->usagePage==13 && data->usageItems[c->firstUsageItem].usage==34){assert(count<10);fingers[count++]=i;}
    }
    assert(count==10);
    SonyHidTouchState prev={0};SonyHidTouchPlan plan;SonyHidContact contacts[10];
    for(unsigned i=0;i<10;++i)contacts[i]=(SonyHidContact){(uint8_t)i,(uint16_t)(i*3000),32767};
    assert(!sony_hid_touch_plan(&prev,contacts,10,&plan) && plan.count==1);
    for(unsigned i=0;i<10;++i) {
        assert(value(parsed,fingers[i],13,81,plan.reports[0])==(int)i);
        assert(value(parsed,fingers[i],1,48,plan.reports[0])==(int)i*3000);
        assert(value(parsed,fingers[i],1,49,plan.reports[0])==32767);
    }
    assert(value(parsed,0,13,84,plan.reports[0])==10);
    prev=plan.after[0];assert(!sony_hid_touch_plan(&prev,NULL,0,&plan) && plan.count==1);
    for(unsigned i=0;i<10;++i) {
        HIDUsage buttons[8];UInt32 n=8;
        assert(!HIDGetButtonsOnPage(kHIDInputReport,13,fingers[i],buttons,&n,parsed,plan.reports[0],62));
        int tip=0,valid=0;for(unsigned k=0;k<n;++k){tip|=buttons[k]==0x42;valid|=buttons[k]==0x47;}
        assert(!tip && valid);
    }
    assert(!HIDCloseReportDescriptor(parsed));
    puts("PASS selected Apple HID parser: actual combined descriptor, report3 length62, ten contacts/IDs/XY/count and tip-up retains confidence");
}
