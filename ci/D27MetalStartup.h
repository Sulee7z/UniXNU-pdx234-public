// D27 Metal startup: test actual creation with the process's effective credentials.
#pragma once
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <mutex>
#include <sys/stat.h>
#include <unistd.h>

namespace d27startup {
// access(W_OK) uses real IDs and does not test directory search permission or
// the sandbox's create operation. The runtime needs an actual writable cache.
inline int prepareCache(const char *path) {
    if (!path || !*path) return ENOENT;
    if (mkdir(path, 0700) && errno != EEXIST) return errno;
    struct stat info = {};
    if (stat(path, &info)) return errno;
    if (!S_ISDIR(info.st_mode)) return ENOTDIR;
    std::string probe = std::string(path) + "/.d27-cache-XXXXXX";
    const int fd = mkstemp(probe.data());
    if (fd < 0) return errno;
    const int closeError = close(fd) ? errno : 0;
    const int removeError = unlink(probe.c_str()) ? errno : 0;
    return closeError ? closeError : removeError;
}

// The bridge/runtime already supports this option for ordinary Metal clients.
// Restore the caller's process environment after the synchronous open attempt.
class OptionalCache {
    static std::recursive_mutex &mutex() {
        static std::recursive_mutex value;
        return value;
    }
    std::unique_lock<std::recursive_mutex> lock;
    bool existed;
    std::string previous;
public:
    int error;
    OptionalCache() : lock(mutex()), existed(false), error(0) {
        // Snapshot once and own the bytes before any environment mutation.
        if (const char *value = getenv("METAL2VULKAN_SHADER_CACHE_OPTIONAL")) {
            existed = true;
            previous = value;
        }
        if (setenv("METAL2VULKAN_SHADER_CACHE_OPTIONAL", "1", 1)) error = errno;
    }
    ~OptionalCache() {
        if (error) return; // A failed setenv did not replace the original value.
        if (existed) setenv("METAL2VULKAN_SHADER_CACHE_OPTIONAL", previous.c_str(), 1);
        else unsetenv("METAL2VULKAN_SHADER_CACHE_OPTIONAL");
    }
    OptionalCache(const OptionalCache &) = delete;
    OptionalCache &operator=(const OptionalCache &) = delete;
};
}
