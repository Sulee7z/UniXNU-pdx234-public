#include "D27MetalStartup.h"
#include <cassert>
#include <cstring>
extern "C" Class objc_getClass(const char *name);
__attribute__((objc_root_class))
@interface D27StartupException
@end
@implementation D27StartupException
@end

int main() {
    for (bool present : {false, true}) {
        if (present) setenv("METAL2VULKAN_SHADER_CACHE_OPTIONAL", "saved", 1);
        else unsetenv("METAL2VULKAN_SHADER_CACHE_OPTIONAL");
        bool caught = false;
        {
            // Same lifetime as the plugin: exception caught before scope exits.
            d27startup::OptionalCache optional;
            assert(!optional.error);
            @try {
                @throw (id)objc_getClass("D27StartupException");
            } @catch (id exception) {
                (void)exception;
                caught = true;
            }
            assert(!strcmp(getenv("METAL2VULKAN_SHADER_CACHE_OPTIONAL"), "1"));
        }
        assert(caught);
        const char *value = getenv("METAL2VULKAN_SHADER_CACHE_OPTIONAL");
        if (present) assert(value && !strcmp(value, "saved"));
        else assert(!value);
    }
}
