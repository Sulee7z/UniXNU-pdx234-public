// SPDX-License-Identifier: MIT
#ifndef PDX_D27_DLOPEN_DIAGNOSTIC_H
#define PDX_D27_DLOPEN_DIAGNOSTIC_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

namespace d27dlopen {
// Bounded, owned observations. An overflow length is a lower bound, never the
// length of the original error. raw and path remain separate for the log.
struct Diagnostic {
    enum { ErrorCapacity=4096, PathCapacity=1024, RowCapacity=64 };
    char raw[ErrorCapacity] = {};
    char path[PathCapacity] = {};
    size_t rawLength=0, pathLength=0;
    bool rawOverflow=false, pathOverflow=false, missing=false;
    unsigned flags=0;

    explicit Diagnostic(const char *attemptedPath, unsigned openFlags): flags(openFlags) {
        copy(path, sizeof path, attemptedPath, pathLength, pathOverflow);
    }

    static void copy(char *out, size_t cap, const char *input, size_t &length, bool &overflow) {
        length=0;overflow=false;
        if(input) {
            while(length+1<cap && input[length]) {out[length]=input[length];++length;}
            overflow=input[length]!=0;
        }
        out[length]=0;
    }

    // Call as capture(dlerror()) immediately after the failed operation. This
    // copies before printf, NSLog, allocation, GPU reports or another loader call.
    void capture(const char *error) {
        copy(raw, sizeof raw, error, rawLength, rawOverflow);
        missing=!error || !rawLength;
    }

    size_t causeOffset() const {
        if(pathOverflow || !pathLength || rawLength<7+pathLength+6)return 0;
        const char prefix[]="dlopen(";
        for(size_t i=0;i<7;++i)if(raw[i]!=prefix[i])return 0;
        for(size_t i=0;i<pathLength;++i)if(raw[7+i]!=path[i])return 0;
        size_t at=7+pathLength;
        if(raw[at++]!=',' || raw[at++]!=' ')return 0;
        unsigned base=10;
        if(at+2<rawLength && raw[at]=='0' && raw[at+1]=='x'){base=16;at+=2;}
        size_t digits=0;unsigned value=0;
        for(;at<rawLength;++at) {
            unsigned char c=(unsigned char)raw[at];unsigned digit;
            if(c>='0' && c<='9')digit=c-'0';
            else if(base==16 && c>='a' && c<='f')digit=c-'a'+10;
            else if(base==16 && c>='A' && c<='F')digit=c-'A'+10;
            else break;
            if(digit>=base || value>(UINT32_MAX-digit)/base)return 0;
            value=value*base+digit;++digits;
        }
        if(!digits || value!=flags || at+3>rawLength || raw[at]!=')' || raw[at+1]!=':' || raw[at+2]!=' ')return 0;
        return at+3;
    }

    const char *cause() const {return missing?"dlerror unavailable":raw+causeOffset();}

    // L = captured cause length (+ means a lower bound); C = capture overflow;
    // W = bytes omitted by the two screen rows. CT is the captured-prefix tail,
    // not the actual error's tail when C=1. H/T offsets are byte positions.
    void rows(char (&out)[2][RowCapacity], bool symbolFailure) const {
        const char *text=cause();
        size_t length=missing?19:rawLength-causeOffset();
        const char *stage=symbolFailure?"D5":"D4";
        int hn=snprintf(out[0],RowCapacity,"%s L%zu%s C%u W0 H:",stage,length,rawOverflow?"+":"",rawOverflow?1:0);
        size_t headCap=63-(size_t)hn;
        // A fixed-width tail offset keeps capacity independent of its value.
        int tn=snprintf(out[1],RowCapacity,"%s %s%04zu:",stage,rawOverflow?"CT":"T",(size_t)0);
        size_t tailCap=63-(size_t)tn;
        bool wireOverflow=rawOverflow || length>headCap+tailCap;
        (void)snprintf(out[0],RowCapacity,"%s L%zu%s C%u W%u H:",stage,length,rawOverflow?"+":"",rawOverflow?1:0,wireOverflow?1:0);
        size_t head=length<headCap?length:headCap;
        size_t tail=length-head<tailCap?length-head:tailCap;
        size_t tailAt=length-tail;
        (void)snprintf(out[1],RowCapacity,"%s %s%04zu:",stage,rawOverflow?"CT":"T",tailAt);
        for(size_t i=0;i<head;++i)out[0][hn+i]=printable(text[i]);
        out[0][hn+head]=0;
        for(size_t i=0;i<tail;++i)out[1][tn+i]=printable(text[tailAt+i]);
        out[1][tn+tail]=0;
    }

    static char printable(char c) {return (unsigned char)c>=32 && (unsigned char)c<127?c:'?';}
};
}
#endif
