#include "D27MetalStartup.h"
#include <cassert>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <thread>
#include <vector>
#include <stdexcept>

int main() {
    char root[] = "/tmp/d27-metal-XXXXXX";
    assert(mkdtemp(root));
    const std::string cache = std::string(root) + "/cache";
    assert(d27startup::prepareCache(cache.c_str()) == 0);
    assert(d27startup::prepareCache(cache.c_str()) == 0);
    DIR *dir = opendir(cache.c_str());
    assert(dir);
    while (auto *entry = readdir(dir)) assert(!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."));
    closedir(dir);
    const std::string file = std::string(root) + "/file";
    const int fd = open(file.c_str(), O_CREAT | O_WRONLY, 0600);
    assert(fd >= 0); close(fd);
    assert(d27startup::prepareCache(file.c_str()) == ENOTDIR);
    assert(d27startup::prepareCache((file + "/child").c_str()) == ENOTDIR);
    assert(d27startup::prepareCache((std::string(root) + "/missing/child").c_str()) == ENOENT);
    assert(d27startup::prepareCache("") == ENOENT);
    assert(d27startup::prepareCache(nullptr) == ENOENT);
    if (geteuid() != 0) {
        assert(chmod(cache.c_str(), 0500) == 0);
        assert(d27startup::prepareCache(cache.c_str()) == EACCES);
        assert(chmod(cache.c_str(), 0700) == 0);
    }
    unsetenv("METAL2VULKAN_SHADER_CACHE_OPTIONAL");
    { d27startup::OptionalCache state; assert(!state.error); assert(!strcmp(getenv("METAL2VULKAN_SHADER_CACHE_OPTIONAL"), "1")); }
    assert(!getenv("METAL2VULKAN_SHADER_CACHE_OPTIONAL"));
    setenv("METAL2VULKAN_SHADER_CACHE_OPTIONAL", "old", 1);
    { d27startup::OptionalCache state; assert(!state.error); }
    assert(!strcmp(getenv("METAL2VULKAN_SHADER_CACHE_OPTIONAL"), "old"));
    try {
        d27startup::OptionalCache state;
        throw std::runtime_error("open failed");
    } catch (const std::runtime_error &) {}
    assert(!strcmp(getenv("METAL2VULKAN_SHADER_CACHE_OPTIONAL"), "old"));
    {
        d27startup::OptionalCache outer;
        {d27startup::OptionalCache inner; assert(!inner.error);}
        assert(!strcmp(getenv("METAL2VULKAN_SHADER_CACHE_OPTIONAL"), "1"));
    }
    assert(!strcmp(getenv("METAL2VULKAN_SHADER_CACHE_OPTIONAL"), "old"));
    std::vector<std::thread> threads;
    for (unsigned i=0;i<8;++i) threads.emplace_back([] {
        for (unsigned n=0;n<100;++n) {
            d27startup::OptionalCache state;
            assert(!state.error);
            std::this_thread::yield();
            assert(!strcmp(getenv("METAL2VULKAN_SHADER_CACHE_OPTIONAL"), "1"));
        }
    });
    for (auto &thread:threads) thread.join();
    assert(!strcmp(getenv("METAL2VULKAN_SHADER_CACHE_OPTIONAL"), "old"));
    unlink(file.c_str()); rmdir(cache.c_str()); rmdir(root);
}
