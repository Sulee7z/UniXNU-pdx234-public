// SPDX-License-Identifier: BSD-2-Clause-Patent
// Drives the exact selected libclosure/runtime.cpp and Block_private.h with a
// bounded allocator and actual QEMU PAC instructions. No fake authentication.
#include <libkern/Block_private.h>
#include <stddef.h>
#include <stdint.h>
#include <ptrauth.h>
extern "C" void block_test_fail(void) __attribute__((noreturn));
extern "C" {
void *_NSConcreteMallocBlock[32];
void *_NSConcreteStackBlock[32];
void *_NSConcreteGlobalBlock[32];
volatile uint64_t block_test_expect_failure,block_test_rejected;
}
static unsigned char arena[65536] __attribute__((aligned(16384)));
static size_t used;
static unsigned allocations,frees;
static void *volatile authentication_sink;
extern "C" void *test_alloc(size_t length) {
    used=(used+15)&~size_t(15);
    if(!length || length>sizeof(arena)-used)block_test_fail();
    void *result=arena+used;used+=length;++allocations;return result;
}
extern "C" void test_free(void *pointer,size_t length) {
    if(!pointer || !length || (uintptr_t)pointer<(uintptr_t)arena ||
       (uintptr_t)pointer+length>(uintptr_t)arena+used)block_test_fail();
    ++frees;
}
extern "C" void *memmove(void *destination,const void *source,size_t size) {
    auto *d=(unsigned char *)destination;auto *s=(const unsigned char *)source;
    if(d<s)for(size_t i=0;i<size;++i)d[i]=s[i];
    else for(size_t i=size;i;--i)d[i-1]=s[i-1];
    return destination;
}
extern "C" void *memcpy(void *destination,const void *source,size_t size) {return memmove(destination,source,size);}
extern "C" void *memset(void *destination,int value,size_t size) {
    for(size_t i=0;i<size;++i)((unsigned char *)destination)[i]=(unsigned char)value;
    return destination;
}
static void require(bool value){if(!value)block_test_fail();}
static void stage(unsigned value){*(volatile unsigned *)0x09000000=(unsigned)('A'+value);}
__attribute__((noinline)) static void *authenticate(void *pointer,void *slot) {
    return ptrauth_auth_data(pointer,ptrauth_key_asda,ptrauth_blend_discriminator(slot,0xc0bb));
}
struct NestedBlock {Block_layout layout;Block_layout *captured;};
extern "C" void nested_copy(void *destination,const void *source) {
    auto *d=(NestedBlock *)destination;auto *s=(const NestedBlock *)source;
    _Block_object_assign(&d->captured,s->captured,BLOCK_FIELD_IS_BLOCK);
}
extern "C" void nested_dispose(const void *source) {
    _Block_object_dispose(((const NestedBlock *)source)->captured,BLOCK_FIELD_IS_BLOCK);
}
extern "C" void nested_invoke(void *source,...) {
    auto *block=((NestedBlock *)source)->captured;
    _Block_get_invoke_fn(block)(block);
}
extern "C" int block_test_main(void) {
    stage(0);
    int count=1;int *counter=&count;
    void (^stack)(void)=^{*counter+=7;};
    auto *before=(Block_layout *)(void *)stack;
    auto *descriptor=(Block_descriptor_1 *)_Block_get_descriptor(before);
    require(descriptor->size==40);
    const uintptr_t signedBefore=(uintptr_t)before->descriptor;
    require(signedBefore!=(uintptr_t)descriptor);
    auto *heap=(Block_layout *)_Block_copy(before);
    stage(1);
    require(heap!=before && allocations==1);
    require(_Block_get_descriptor(heap)==descriptor);
    require((uintptr_t)heap->descriptor!=signedBefore);
    _Block_get_invoke_fn(heap)(heap);require(count==8);
    stage(2);
    require(_Block_copy(heap)==heap && allocations==1);
    _Block_release(heap);require(!frees);
    _Block_release(heap);require(frees==1);
    stage(3);
    // Hand-construct a global block in runtime memory so ELF relocation support
    // isn't confused with the runtime authentication contract under test.
    Block_layout global={};global.flags=BLOCK_IS_GLOBAL;
    global.descriptor=(Block_descriptor_1 *)ptrauth_sign_unauthenticated(
        descriptor,ptrauth_key_asda,ptrauth_blend_discriminator(&global.descriptor,0xc0bb));
    require(_Block_copy(&global)==&global);_Block_release(&global);require(frees==1);
    stage(4);
    void (^inner)(void)=^{*counter+=3;};
    struct {Block_descriptor_1 base;Block_descriptor_2 helpers;} desc;
    desc.base.reserved=0;desc.base.size=sizeof(NestedBlock);
    void *copyAddress,*disposeAddress,*invokeAddress;
    __asm__ volatile("adr %0,nested_copy":"=r"(copyAddress));
    __asm__ volatile("adr %0,nested_dispose":"=r"(disposeAddress));
    __asm__ volatile("adr %0,nested_invoke":"=r"(invokeAddress));
    // Emulate the original Apple's storage-signed helper entries. The ELF test
    // linker does not implement Mach-O authenticated constant relocations.
    *(uintptr_t *)&desc.helpers.copy=(uintptr_t)ptrauth_sign_unauthenticated(copyAddress,ptrauth_key_asia,&desc.helpers.copy);
    *(uintptr_t *)&desc.helpers.dispose=(uintptr_t)ptrauth_sign_unauthenticated(disposeAddress,ptrauth_key_asia,&desc.helpers.dispose);
    NestedBlock outer={};outer.layout.flags=BLOCK_HAS_COPY_DISPOSE;
    outer.layout.descriptor=(Block_descriptor_1 *)ptrauth_sign_unauthenticated(
        &desc,ptrauth_key_asda,ptrauth_blend_discriminator(&outer.layout.descriptor,0xc0bb));
    *(uintptr_t *)&outer.layout.invoke=(uintptr_t)ptrauth_sign_unauthenticated(invokeAddress,ptrauth_key_asia,&outer.layout.invoke);
    outer.captured=(Block_layout *)(void *)inner;
    auto *nested=(Block_layout *)_Block_copy(&outer);
    stage(5);
    require(allocations==3);
    _Block_get_invoke_fn(nested)(nested);require(count==11);
    _Block_release(nested);require(frees==3);
    stage(6);
    // Authentication itself must reject tampering and using the signature at a
    // different storage address. Compare its poisoned result before dereference.
    void *bad=(void *)((uintptr_t)before->descriptor^(uintptr_t(1)<<45));
    block_test_expect_failure=1;
    authentication_sink=authenticate(bad,&before->descriptor);
    require(block_test_rejected==1 && block_test_expect_failure==0);
    block_test_expect_failure=1;
    authentication_sink=authenticate(before->descriptor,&global.descriptor);
    require(block_test_rejected==2 && block_test_expect_failure==0);
    return 0;
}
