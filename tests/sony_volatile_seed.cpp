// SPDX-License-Identifier: MIT
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include "SparseDisk.h"

struct Operations {
    uint8_t buffer[512] = {};
    bool fail = false;
    uint8_t *allocate() { return fail ? nullptr : static_cast<uint8_t *>(calloc(1,4096)); }
    uint64_t read(uint64_t at, void *p, uint64_t n) {
        assert(at <= sizeof buffer && n <= sizeof buffer-at); memcpy(p,buffer+at,n); return n;
    }
    uint64_t copy(uint64_t at, const void *p, uint64_t n) {
        assert(at <= sizeof buffer && n <= sizeof buffer-at); memcpy(buffer+at,p,n); return n;
    }
};

int main(int argc, char **argv) {
    assert(argc==2);
    FILE *file=fopen(argv[1],"rb"); assert(file);
    assert(!fseek(file,0,SEEK_END)); long length=ftell(file); assert(length>0 && length<=0x10000000);
    assert(!fseek(file,0,SEEK_SET)); std::vector<uint8_t> packed((size_t)length);
    assert(fread(packed.data(),1,packed.size(),file)==packed.size()); assert(!fclose(file));
    uint64_t logical=0; assert(ramPackedLayout(packed.data(),packed.size(),&logical));
    assert(logical==0x80000000ULL); // Exact native volatile/large boundary, not above it.
    std::vector<uint8_t *> pages(logical/4096,nullptr);
    RamSparseDisk disk={pages.data(),logical,0}; Operations ops;
    assert(ramSparseImport(disk,packed.data(),packed.size(),ops));
    assert(disk.resident<8*1024*1024); const uint64_t initial=disk.resident;
    bool noMemory=false;
    assert(ramSparseIO(disk,false,logical-512,512,ops,noMemory)==512);
    for(uint8_t b:ops.buffer)assert(!b);
    memset(ops.buffer,0x5a,sizeof ops.buffer);
    assert(ramSparseIO(disk,true,logical-512,512,ops,noMemory)==512 && !noMemory);
    assert(disk.resident==initial+4096);
    memset(ops.buffer,0,sizeof ops.buffer);
    assert(ramSparseIO(disk,false,logical-512,512,ops,noMemory)==512);
    for(uint8_t b:ops.buffer)assert(b==0x5a);
    assert(!ramSparseIO(disk,false,logical,512,ops,noMemory));
    assert(!ramSparseIO(disk,true,logical-256,512,ops,noMemory));
    ops.fail=true;
    assert(!ramSparseIO(disk,true,logical-8192,512,ops,noMemory) && noMemory);
    assert(disk.resident==initial+4096);
    for(uint8_t *page:pages)free(page);
    puts("PASS actual2GiB packed layout/import, sparse memory footprint, last block read/write, capacity bounds and allocation failure; persistence not required");
}
