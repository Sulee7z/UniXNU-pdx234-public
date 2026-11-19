"""Checked overlay for the already D27-qualified Metal plugin startup path."""


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f'Expected one startup anchor: {old[:100]!r}')
    return text.replace(old, new, 1)


def adapt(text):
    if 'D27MetalStartup.h' in text:
        raise ValueError('Startup adapter already applied')
    text = replace_once(text, '#include "SharedShaderCache.h"',
                        '#include "SharedShaderCache.h"\n#include "D27MetalStartup.h"\n'
                        'extern "C" const char *d27_metal_open_error();\n'
                        'extern "C" const char *d27_metal_open_stage();\n'
                        'extern "C" bool d27_metal_runtime_ready();')
    # Only edit the render-server branch. Client mode has its own existing fallback.
    start = text.index('static id deviceForPort(unsigned port)')
    prefix, server = text[:start], text[start:]
    server = replace_once(server, '        gpu->mark(0x6801);', '''        gpu->mark(0x6801);
        // Preserve dyld's actual refusal before the Rust loader reduces it to
        // LoaderNotFound. Keep this library resident just as a successful runtime
        // does; unloading/reloading a driver may repeat process-global init.
        dlerror();
        void *startupLoader = dlopen(turnip, RTLD_NOW | RTLD_LOCAL);
        const char *loaderError = startupLoader ? nullptr : dlerror();
        const char *loaderStage = "dlopen";
        bool loaderSymbol = false;
        if (startupLoader) {
            dlerror();
            loaderSymbol = dlsym(startupLoader, "vkGetInstanceProcAddr") != nullptr;
            if (!loaderSymbol) {
                loaderError = dlerror();
                loaderStage = "vkGetInstanceProcAddr";
            }
        }
        if (!startupLoader || !loaderSymbol) {
            if (!loaderError) loaderError = "missing loader symbol";
            NSLog(@"D27 Metal %s %s: %s", loaderStage, turnip, loaderError);
            char text[64];
            snprintf(text, sizeof text, "PUB %.20s %.37s", loaderStage, loaderError);
            streamText(*gpu, text);
            gpu->mark(startupLoader ? 0x68f5 : 0x68f4);
            return nil;
        }
        gpu->mark(0x6804);''')
    server = replace_once(server,
        '        static const unsigned order[] = {5, 4, 0, 1, 2, 3};',
        '''        // A compact final row retains every candidate's result concurrently:
        // '-' empty, 'c' cache refused, 'r' runtime refused, 'x' exception, '+' open.
        char cacheStages[7] = "------";
        int cacheErrors[6] = {};
        char optionalStage = '-';
        std::string startupError = "no cache candidate";
        static const unsigned order[] = {5, 4, 0, 1, 2, 3};''')
    server = replace_once(server,
        '''            mkdir(candidates[i], 0700);
            if (access(candidates[i], W_OK) != 0) continue;''',
        '''            const int cacheError = d27startup::prepareCache(candidates[i]);
            if (cacheError) {
                cacheStages[i] = 'c';
                cacheErrors[i] = cacheError;
                char detail[64];
                snprintf(detail, sizeof detail, "cache%u errno=%d", i, cacheError);
                startupError = detail;
                gpu->mark(0x6900 | (i << 5) | (unsigned(cacheError) & 31));
                NSLog(@"D27 Metal cache%u %s: errno=%d", i, candidates[i], cacheError);
                continue;
            }
            // Runtime probes v1/<build> too; a writable root alone is insufficient.
            // Disk caching is an optimization, never a prerequisite for the GPU.
            d27startup::OptionalCache optional;
            if (optional.error) {
                cacheStages[i] = 'e'; cacheErrors[i] = optional.error;
                startupError = "optional-cache setenv failed";
                continue;
            }''')
    server = replace_once(server,
        '''            @try {
                device = native_bridge_metal_open(turnip, candidates[i], registryID, nullptr);
            } @catch (NSException *exception) {
                device = nil;
            }
            if (device) {gpu->mark(0x6810 + i); gCacheDirectory = candidates[i];}''',
        '''            @try {
                device = native_bridge_metal_open(turnip, candidates[i], registryID, nullptr);
                cacheStages[i] = device ? '+' : 'r';
                if (!device) startupError = d27_metal_open_error();
            } @catch (NSException *exception) {
                device = nil;
                cacheStages[i] = 'x';
                const char *name = exception.name.UTF8String;
                const char *reason = exception.reason.UTF8String;
                startupError = std::string(d27_metal_open_stage()) + ": " + (name ? name : "NSException") + ": " + (reason ? reason : "no reason");
            }
            if (!device) NSLog(@"D27 Metal cache%u %s: %s", i, candidates[i], startupError.c_str());
            if (device) {gpu->mark(0x6810 + i); gCacheDirectory = candidates[i];}
            // Once a runtime device exists, a cache retry cannot repair frontend
            // class/ABI/init failure and must not overwrite the live handle.
            if (!device && d27_metal_runtime_ready()) {gpu->mark(0x68f6); break;}''')
    server = replace_once(server,
        '''        if (!device) {
            gpu->mark(0x68f2);
            char text[64];
            snprintf(text, sizeof text, "PUB no device: %.40s", nmb_last_error());''',
        '''        if (!device && !d27_metal_runtime_ready() && !strchr(cacheStages, 'r') && !strchr(cacheStages, 'x')) {
            // Apply the existing client's cache-optional policy to backboardd too.
            d27startup::OptionalCache optional;
            if (!optional.error) {
                const char *path = candidates[0][0] ? candidates[0] : candidates[1][0] ? candidates[1] : "/var/mobile/tmp/m2v";
                gpu->mark(0x68e0);
                optionalStage = 'r';
                @try {
                    device = native_bridge_metal_open(turnip, path, registryID, nullptr);
                    if (device) {gCacheDirectory = path; optionalStage = '+'; gpu->mark(0x68e1);}
                    else startupError = d27_metal_open_error();
                } @catch (NSException *exception) {
                    optionalStage = 'x';
                    const char *name = exception.name.UTF8String;
                    const char *reason = exception.reason.UTF8String;
                    startupError = std::string(d27_metal_open_stage()) + ": " + (name ? name : "NSException") + ": " + (reason ? reason : "no reason");
                }
                if (!device && d27_metal_runtime_ready()) gpu->mark(0x68f6);
            } else {optionalStage = 'e'; startupError = "optional-cache setenv failed";}
        }
        if (!device) {
            gpu->mark(0x68f2);
            NSLog(@"D27 Metal PUB C%s: %s", cacheStages, startupError.c_str());
            char text[64];
            snprintf(text, sizeof text, "PUB C%s O%c E%d,%d,%d,%d,%d,%d", cacheStages, optionalStage,
                     cacheErrors[0], cacheErrors[1], cacheErrors[2], cacheErrors[3], cacheErrors[4], cacheErrors[5]);
            streamText7(*gpu, text);
            snprintf(text, sizeof text, "%.63s", startupError.c_str());''')
    return prefix + server


def adapt_frontend(text):
    """Capture the exact failing stage immediately, before later bridge calls clear it."""
    anchor = 'extern "C" id native_bridge_metal_open(const char *loader,const char *cache,uint64_t registryID,void (*missing)(const char *,const char *)) {'
    text = replace_once(text, anchor, '''static thread_local std::string d27OpenError;
static thread_local const char *d27OpenStage = "not-entered";
extern "C" const char *d27_metal_open_error() {return d27OpenError.empty() ? d27OpenStage : d27OpenError.c_str();}
extern "C" const char *d27_metal_open_stage() {return d27OpenStage;}
extern "C" bool d27_metal_runtime_ready() {return gDevice != nullptr;}
''' + anchor + '''
 if(gDeviceObject)return gDeviceObject;
 // A live runtime plus no frontend object is a terminal frontend failure.
 // Preserve its error/stage, including one interrupted by an ObjC exception.
 if(gDevice)return nil;
 d27OpenError.clear(); d27OpenStage="frontend-entry";''')
    text = replace_once(text, ' gDevice=nmb_device_open(loader,cache);', ''' d27OpenStage="runtime-device-open";
 gDevice=nmb_device_open(loader,cache);
 if(!gDevice) {const char *error=nmb_last_error();d27OpenError=std::string(d27OpenStage)+": "+(error&&*error?error:"nil without error");}
 d27OpenStage="runtime-diagnostic-hooks";''')
    text = replace_once(text, ' watchImportPressure();\n if(cache && logGpuOn())',
                        ' d27OpenStage="frontend-properties";\n watchImportPressure();\n if(cache && logGpuOn())')
    text = replace_once(text, ' if(!base){NBLOG(@"native-metal: no _MTLDevice");return nil;}',
                        ' if(!base){d27OpenError="frontend: missing _MTLDevice";NBLOG(@"native-metal: no _MTLDevice");return nil;}')
    text = replace_once(text, ' Class cls=objc_allocateClassPair(base,"NativeBridgeMetalDevice",0);if(!cls)return nil;',
                        ''' d27OpenStage="frontend-allocate-class";
 Class cls=objc_allocateClassPair(base,"NativeBridgeMetalDevice",0);if(!cls){d27OpenError="frontend: objc_allocateClassPair returned nil";return nil;}
 d27OpenStage="frontend-install-methods";''')
    text = replace_once(text, ' objc_registerClassPair(cls);\n gDeviceObject=[cls new];',
                        ''' d27OpenStage="frontend-register-class";
 objc_registerClassPair(cls);
 d27OpenStage="frontend-new-device";
 gDeviceObject=[cls new];
 if(!gDeviceObject)d27OpenError="frontend: device allocation/init returned nil";
 else d27OpenStage="device-ready";''')
    return text
