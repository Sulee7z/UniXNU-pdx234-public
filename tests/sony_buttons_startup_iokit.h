// SPDX-License-Identifier: BSD-2-Clause-Patent
#ifndef SONY_BUTTONS_STARTUP_TEST_IOKIT_H
#define SONY_BUTTONS_STARTUP_TEST_IOKIT_H
#include "sony_buttons_iokit.h"
#include <map>
#include <string>
namespace buttons_test {
inline std::map<std::string, unsigned> bootargs;
inline unsigned starts = 0, deallocates = 0;
inline IOService *dummyStartupDevice = nullptr;
inline unsigned allocations = 0;
inline int allocationQualification = 0;
inline uint8_t allocationMask = 255;
inline void *allocationContext = nullptr;
inline void (*scheduled)(void *, int) = nullptr;
}
using kern_return_t = int;
using wait_result_t = int;
using thread_t = void *;
constexpr int KERN_SUCCESS = 0;
struct kmod_info_t { const char *name; };
struct OSSymbol : OSObject {
    using OSObject::release;
    static OSSymbol *withCString(const char *) { return new OSSymbol; }
    void release() const { delete this; }
};
struct OSMetaClass {
    static const OSMetaClass *getMetaClassWithName(const OSSymbol *) { static OSMetaClass meta; return &meta; }
    unsigned getClassSize() const { return 208; }
    static void *preModLoad(const char *) { return reinterpret_cast<void *>(1); }
    static int postModLoad(void *) { return 0; }
};
inline int OSKextLoadKextWithIdentifier(const char *) { return 0; }
inline int PE_parse_boot_argn(const char *name, void *output, size_t bytes) {
    assert(bytes == sizeof(unsigned));
    auto it = buttons_test::bootargs.find(name);
    if (it == buttons_test::bootargs.end()) return 0;
    memcpy(output, &it->second, bytes); return 1;
}
inline kern_return_t kernel_thread_start(void (*worker)(void *, wait_result_t), void *, thread_t *out) {
    buttons_test::scheduled = worker;
    ++buttons_test::starts; *out = reinterpret_cast<void *>(1); return KERN_SUCCESS;
}
inline void thread_deallocate(thread_t) { ++buttons_test::deallocates; }
inline thread_t current_thread() { return reinterpret_cast<void *>(1); }
inline void thread_terminate(thread_t) {}
#endif
