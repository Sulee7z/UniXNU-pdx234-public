/* Executes the production Wi-Fi startup body after the independent overlay. */
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
using thread_t = void *;
constexpr int KERN_SUCCESS = 0;
static uint32_t native_wifi_stats[29];
static unsigned stage, threadCalls, publishCalls, publishedBeforeSchedule;
static int providerError, msiError, publishError, threadError;
static bool PE_parse_boot_argn(const char *key, void *data, size_t length) {
    assert(!strcmp(key, "wifi") && length == sizeof(stage));
    memcpy(data, &stage, length);
    return true;
}
static int sony_wcn_platform_ready() { return providerError; }
static int sony_wcn_platform_wifi_ready() { return msiError; }
static int native_sony_wifi_publish() { ++publishCalls; return publishError; }
static void wifiThread(void *, int) {}
static int kernel_thread_start(void (*worker)(void *, int), void *arg, thread_t *thread) {
    assert(worker == wifiThread && reinterpret_cast<uintptr_t>(arg) == stage);
    assert(!publishError && publishCalls > publishedBeforeSchedule);
    publishedBeforeSchedule = publishCalls;
    ++threadCalls;
    *thread = nullptr;
    return threadError;
}
static void thread_deallocate(thread_t) {}
#include "SonyWifiStart069.h"

int main() {
    stage = 0;
    native_sony_wifi_start();
    assert(!threadCalls && !publishCalls && native_wifi_stats[0] == 0);
    stage = 3;
    native_sony_wifi_start();
    assert(!threadCalls && !publishCalls && native_wifi_stats[0] == uint32_t(-EINVAL));
    stage = 5;
    providerError = ENXIO;
    native_sony_wifi_start();
    assert(!threadCalls && !publishCalls && native_wifi_stats[0] == uint32_t(-ENXIO));
    providerError = 0; msiError = ENXIO;
    native_sony_wifi_start();
    assert(!threadCalls && !publishCalls && native_wifi_stats[0] == uint32_t(-ENXIO));
    // Build007 intentionally leaves firmware validation to the bounded worker.
    // Entry still performs the address publication and schedules that worker.
    msiError = 0;
    publishError = EIO;
    native_sony_wifi_start();
    assert(!threadCalls && publishCalls == 1 && native_wifi_stats[0] == uint32_t(-EIO));
    publishError = 0; threadError = 1;
    native_sony_wifi_start();
    assert(threadCalls == 1 && publishCalls == 2 && native_wifi_stats[0] == uint32_t(-ENOMEM));
    threadError = 0;
    native_sony_wifi_start();
    assert(threadCalls == 2 && publishCalls == 3);
    native_sony_wifi_start();
    assert(threadCalls == 2 && publishCalls == 4); // worker once-only; publication remains idempotent.
}
