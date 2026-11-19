// SPDX-License-Identifier: MIT
// Adreno Metal plugin, reached through the original discovery (IOAcceleratorES -> MetalPluginName -> NSBundle -> principal class ->
// initWithAcceleratorPort:). Default (stage 1): it runs the shared userspace GPU test (NativeAdrenoUserTest.h) from inside a real system
// process, under that process's sandbox, and then returns nil. No device is registered, so the original software rendering keeps running unchanged.
// Published (the image carries the file NativeAdrenoMetal.publish beside the bundle): backboardd, the one process that owns the GPU, returns the native
// Metal frontend's device (the metal2vulkan runtime on Turnip, on the Adreno 740), which the original discovery registers; the CARenderServer then
// renders the system UI through it, and the display driver's frames are written to the scanout by the GPU (GpuScanoutClient.h). Another process
// gets its own native device too (its own driver connection, GPU address space and shader cache), as every process does with Apple's
// own GPU plugin.
#import <Foundation/Foundation.h>
#include "SharedShaderCache.h"
#include "D27MetalStartup.h"
#include "D27DlopenDiagnostic.h"
extern "C" const char *d27_metal_open_error();
extern "C" const char *d27_metal_open_stage();
extern "C" bool d27_metal_runtime_ready();
#include <pthread.h>
#include <thread>
#include <dlfcn.h>
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif
#include <unistd.h>
#include <pwd.h>
#include <fts.h>
#include <mach/mach.h>
#include <sys/sysctl.h>
#include <libkern/OSCacheControl.h>
#include <objc/message.h>
#include "NativeAdrenoUserTest.h"
#include "NativeTurnipSwapTest.h"
#include "NativeGpuTrace.h"
#include "NativeMetalBridgePhase.h"
#include "CacheExport.h"
#include "PrimeShaders.h"
#include "ExceptionDiag.h"

@interface _MTLDevice : NSObject
@end
@interface NativeAdrenoMetalDeviceBase : NSObject   // only a lock object for the published mode's one-time setup
@end
@implementation NativeAdrenoMetalDeviceBase
@end
@interface NativeAdrenoMetalDevice : _MTLDevice
- (id)initWithAcceleratorPort:(unsigned)port;
@end

// ---- published mode ----
namespace publish {
// The image's marker: a file beside the bundle in the union view of /System/Library/Extensions (the bundle's own seal stays untouched).
// A file beside the bundle: its path in path, true when it is readable.
static bool requestedPath(const char *name, char *path, size_t size) {
    Dl_info info = {};
    if (!dladdr(reinterpret_cast<const void *>(&requestedPath), &info) || !info.dli_fname) return false;
    snprintf(path, size, "%s", info.dli_fname);
    char *slash = strrchr(path, '/');          // the bundle's executable: <dir>/NativeAdrenoMetal.bundle/NativeAdrenoMetal
    if (!slash) return false;
    *slash = 0;
    slash = strrchr(path, '/');
    if (!slash) return false;
    snprintf(slash + 1, size - size_t(slash + 1 - path), "%s", name);
    return access(path, R_OK) == 0;
}
static bool requested() {
    char path[1024];
    return requestedPath("NativeAdrenoMetal.publish", path, sizeof path);
}
static Gpu *makeGpu(unsigned port) {
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW | RTLD_LOCAL);
    if (!iokit) return nullptr;
    Gpu *gpu = new Gpu;
    gpu->call = (CallFn)dlsym(iokit, "IOConnectCallStructMethod");
    gpu->map = (MapFn)dlsym(iokit, "IOConnectMapMemory64");
    gpu->unmap = (UnmapFn)dlsym(iokit, "IOConnectUnmapMemory64");
    gpu->openFn = (IOServiceOpenFn)dlsym(iokit, "IOServiceOpen");
    gpu->closeFn = (IOServiceCloseFn)dlsym(iokit, "IOServiceClose");
    gpu->port = port;
    return gpu;
}
static std::string gCacheDirectory;   // the runtime's cache directory (the one that opened the device), exported by CacheExport.h
// Progress markers 0x68xx (GPU6): 6800 entered, 6801 Turnip found, 6802 device made, 6803 returned to the discovery, 68f1 no Turnip, 68f2 no device.
static unsigned gDiagBits;
// Reads of the render server's own state for the framebuffer-format question (diagnostic only, for the exact QuartzCore of the target image; a read
// that fails or a build that differs reports zeros). Each value is one marker, 0x7Kvv: K picks the item, vv the value.
static bool bootArgSet(const char *key) {
    char args[1100] = {};
    size_t size = sizeof args - 1;
    return sysctlbyname("kern.bootargs", args, &size, nullptr, 0) == 0 && strstr(args, key);
}
// Every process other than the render server: the same runtime on its own connection, with none of the render server's threads (no
// display hand-off, telemetry, benchmark or cache export). Its shader cache lives in its own cache or temp directory.
// The reason a client's device failed, as a text line the driver keeps per process (the render server's report row is rewritten every ten seconds):
// "<step> <detail>", through the marker stream (a connection is not needed). The Gpu object is made only on this path.
// Deletes every "*.import" file under `root`: the copying import of an earlier image wrote each file beside its place and renamed it only
// once the whole pack was read; a boot that ended first left them all there.
static void removeHalfImported(const char *root) {
    char *paths[] = {const_cast<char *>(root), nullptr};
    FTS *fts = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR | FTS_XDEV, nullptr);
    if (!fts) return;
    while (FTSENT *e = fts_read(fts))
        if (e->fts_info == FTS_F && e->fts_namelen > 7 && !strcmp(e->fts_name + e->fts_namelen - 7, ".import")) unlink(e->fts_path);
    fts_close(fts);
}
static unsigned gClientPort;
static void clientFailure(unsigned port, const char *step, const char *detail) {
    if (Gpu *gpu = makeGpu(port)) {
        // The row holds 63 characters: the common prefix goes, and a long reason keeps its start (what was refused) and its end (why).
        if (!detail) detail = "";
        if (!strncmp(detail, "native-metal: ", 14)) detail += 14;
        char shown[48];
        const size_t length = strlen(detail);
        if (length <= 46) strlcpy(shown, detail, sizeof shown);
        else snprintf(shown, sizeof shown, "%.18s~%s", detail, detail + length - 27);
        char text[64];
        snprintf(text, sizeof text, "%.14s %s", step, shown);
        streamText(*gpu, text);
        // A refusal's text is what says why a client ends (iconservicesagent's pipeline refusal showed 18 characters of it): the rest of it
        // follows in rows of its own, up to six, each 46 characters.
        if (!strcmp(step, "problem") && length > 46)
            for (unsigned part = 1, at = 46; part <= 6 && at < length; ++part, at += 46) {
                // The log keeps the latest text row only: each part follows the one before it by 4 s so a sample catches every one.
                std::string row = "problem" + std::to_string(part) + " " + std::string(detail + at).substr(0, 46);
                auto *target = gpu;
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, int64_t(part) * 4 * NSEC_PER_SEC),
                               dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{streamText(*target, row.c_str());});
            }
    }
}
static id clientDevice(unsigned port) {
    char turnip[1024];
    if (!turnip::libraryPath(turnip, sizeof turnip) || access(turnip, R_OK) != 0) {clientFailure(port, "no-turnip", ""); return nil;}
    uint64_t registryID = 0;
    if (void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW | RTLD_LOCAL)) {
        if (auto retain = (int (*)(unsigned))dlsym(iokit, "IOObjectRetain")) retain(port);
        if (auto entryID = (int (*)(unsigned, uint64_t *))dlsym(iokit, "IORegistryEntryGetRegistryEntryID")) entryID(port, &registryID);
    }
    // IOSurfaces this GPU reads or writes must be plain rows, as in the render server.
    CFPreferencesSetAppValue(CFSTR("CAEnableIOSurfaceCompression"), kCFBooleanFalse, kCFPreferencesCurrentApplication);
    char candidates[3][512] = {};
    if (!confstr(_CS_DARWIN_USER_CACHE_DIR, candidates[0], sizeof candidates[0] - 16)) candidates[0][0] = 0;
    if (!confstr(_CS_DARWIN_USER_TEMP_DIR, candidates[1], sizeof candidates[1] - 16)) candidates[1][0] = 0;
    strlcpy(candidates[2], sharedShaderCacheDirectory().c_str(), sizeof candidates[2]);
    id device = nil;
    const char *lastError = "";
    unsigned usable = 0;
    for (unsigned i : {2u, 0u, 1u}) {
        if (device) break;
        if (!candidates[i][0]) continue;
        if (i != 2) strlcat(candidates[i], "m2v", sizeof candidates[i]);
        mkdir(candidates[i], 0700);
        if (access(candidates[i], W_OK) != 0) continue;
        ++usable;
        @try {
            device = native_bridge_metal_open(turnip, candidates[i], registryID, nullptr);
        } @catch (NSException *exception) {
            device = nil;
            lastError = "exception";
        }
        if (!device && !lastError[0]) lastError = nmb_last_error();
    }
    if (!device && !usable) {
        setenv("METAL2VULKAN_SHADER_CACHE_OPTIONAL", "1", 1);
        const char *path = candidates[0][0] ? candidates[0] : candidates[1][0] ? candidates[1] : "/var/mobile/tmp/m2v";
        @try {
            device = native_bridge_metal_open(turnip, path, registryID, nullptr);
        } @catch (NSException *exception) {
            device = nil;
            lastError = "exception";
        }
        if (!device && !lastError[0]) lastError = nmb_last_error();
    }
    if (!device) clientFailure(port, usable ? "no-device" : "no-cachedir", lastError);
    // The client's first problem, once, on the same text line, sent from the thread that hit it: WidgetRenderer crashed on a nil render
    // encoder with no reason anywhere readable (its own log lines need the plugin's format strings, which the device does not keep), and a
    // once-a-second reader never ran before the crash (i568).
    if (device) {
        gClientPort = port;
        native_bridge_metal_problem_hook = [](const char *problem) {clientFailure(gClientPort, "problem", problem);};
        char problem[200] = {};
        if (native_bridge_metal_first_problem(problem, sizeof problem) && problem[0]) clientFailure(port, "problem", problem);
    }
    return device;
}
static id deviceForPort(unsigned port) {
    static id device;
    static bool tried;
    @synchronized([NativeAdrenoMetalDeviceBase class]) {
        if (tried) return device;
        tried = true;
        exceptiondiag::start(); // the throw site of an uncaught exception, for the kernel's THROW row (ExceptionDiag.h)
        // No concurrent binning in any Metal process: with it BV ran ahead of BR and the two stopped waiting on each other inside a pass
        // (int-261p, int-262, and in system memory int-265). Without it Turnip's autotune picks tile memory (GMEM) or system memory per
        // pass: i553 forced system memory for every pass, the GPU busy 19 % at 680 MHz. A tile store writes whole 16x4 blocks, which the
        // runtime keeps within a texture's rows (bridge patch 0016).
        if (FILE *flags = fopen("/private/var/ngpu/tu_debug", "r")) {
            char line[128] = {};
            if (fgets(line, sizeof line, flags)) {line[strcspn(line, "\n")] = 0; setenv("TU_DEBUG", line, 1);}
            fclose(flags);
        }
        // sheng-tu-debug=<flags>: TU_DEBUG for every Metal process (an experiment: sysmem renders without GMEM load and store, gmem always with them).
        {
            char args[1100] = {};
            size_t size = sizeof args - 1;
            if (sysctlbyname("kern.bootargs", args, &size, nullptr, 0) == 0)
                if (const char *at = strstr(args, "sheng-tu-debug=")) {
                    char value[64] = {};
                    strlcpy(value, at + 15, sizeof value);
                    value[strcspn(value, " ")] = 0;
                    setenv("TU_DEBUG", value, 1);
                }
        }
        // Every pass renders in system memory with the 8-bit BGRA framebuffer (sheng-fb-bgra=1): measured against tile memory with the swap of
        // GMEM loads and stores fixed (patches/mesa/turnip-gmem-mutable-swap.patch, lock screen 99.5 % equal to the RGhA picture), the GPU time per
        // command buffer was no better (17.8 ms mean and 56.1 ms at p95 in tile memory, 17.1 and 52.1 in system memory), and one home screen frame
        // still came out with red and blue exchanged. sheng-tu-debug= overrides this for experiments.
        setenv("TU_DEBUG", bootArgSet("sheng-fb-bgra=1") ? "sysmem,nocb" : "nocb", 0);
        // sheng-diag=1 turns on every diagnostic of the GPU stack in this process: the frontend's frame trace, Turnip's pass stamps and
        // submission ring, the runtime's stage ring, and in the render server the status and telemetry lines. Without it none of them runs.
        if (bootArgSet("sheng-diag=1") || bootArgSet("sheng-gpu-trace=1")) setenv("SHENG_DIAG", "1", 1);
        else unsetenv("SHENG_DIAG");
        if (bootArgSet("sheng-gpu-trace=1")) setenv("SHENG_GPU_TRACE", "1", 1);
        else unsetenv("SHENG_GPU_TRACE");
        if (bootArgSet("sheng-wallpaper-freeze=1")) setenv("NATIVE_METAL_FREEZE_WALLPAPER", "1", 1);
        // log-gpu=1: the GPU stack's log lines (NSLog, the pipeline journal); off without it.
        if (bootArgSet("log-gpu=1")) setenv("SHENG_LOG_GPU", "1", 1);
        else unsetenv("SHENG_LOG_GPU");
        if (strcmp(getprogname(), "backboardd") != 0) return device = clientDevice(port);
        // The discovery releases the accelerator port when it is done; the monitor and the scanout client keep using it.
        if (void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW | RTLD_LOCAL)) {
            if (auto retain = (int (*)(unsigned))dlsym(iokit, "IOObjectRetain")) retain(port);
        }
        Gpu *gpu = makeGpu(port);
        if (!gpu) return nil;
        gpu->mark(0x6800);
        char turnip[1024];
        if (!turnip::libraryPath(turnip, sizeof turnip) || access(turnip, R_OK) != 0) {gpu->mark(0x68f1); return nil;}
        gpu->mark(0x6801);
        // Preserve dyld's actual refusal before the Rust loader reduces it to
        // LoaderNotFound. Keep this library resident just as a successful runtime
        // does; unloading/reloading a driver may repeat process-global init.
        d27dlopen::Diagnostic loaderDiagnostic(turnip, RTLD_NOW | RTLD_LOCAL);
        dlerror();
        void *startupLoader = dlopen(turnip, RTLD_NOW | RTLD_LOCAL);
        if (!startupLoader) loaderDiagnostic.capture(dlerror());
        const char *loaderStage = "dlopen";
        bool loaderSymbol = false;
        if (startupLoader) {
            dlerror();
            loaderSymbol = dlsym(startupLoader, "vkGetInstanceProcAddr") != nullptr;
            if (!loaderSymbol) {
                loaderDiagnostic.capture(dlerror());
                loaderStage = "vkGetInstanceProcAddr";
            }
        }
        if (!startupLoader || !loaderSymbol) {
            char loaderRows[2][64];
            loaderDiagnostic.rows(loaderRows, startupLoader != nullptr);
            // Own both strings before any external call. Logs retain the raw
            // prefix and path separately; C/W in the screen rows disclose loss.
            NSLog(@"D27 Metal %s path[%zu%s]=%s raw[%zu%s]=%s", loaderStage,
                  loaderDiagnostic.pathLength, loaderDiagnostic.pathOverflow ? "+" : "", loaderDiagnostic.path,
                  loaderDiagnostic.rawLength, loaderDiagnostic.rawOverflow ? "+" : "", loaderDiagnostic.raw);
            // Existing two report slots, one local stream lock for the pair.
            // Neither slot can retain more than 63 bytes; this is a summary.
            pthread_mutex_lock(&gStreamLock);
            for (unsigned slot=0; slot<2; ++slot) {
                gpu->mark(slot ? 0x7fff : 0x7ffe);
                for (unsigned i=0; i<63 && loaderRows[slot][i]; ++i)
                    gpu->mark(0x7000 | (uint8_t)loaderRows[slot][i]);
            }
            pthread_mutex_unlock(&gStreamLock);
            gpu->mark(startupLoader ? 0x68f5 : 0x68f4);
            return nil;
        }
        gpu->mark(0x6804);
        // The runtime refuses to open without a writable shader-cache directory, and which directories backboardd's sandbox lets it write is not
        // known from here: try the user cache and temp directories, then /tmp and /var/tmp, and use the first that opens a device.
        uint64_t registryID = 0;
        if (void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW | RTLD_LOCAL)) {
            if (auto entryID = (int (*)(unsigned, uint64_t *))dlsym(iokit, "IORegistryEntryGetRegistryEntryID")) entryID(port, &registryID);
        }
        // What the render server sees for its framebuffer choice (marker 0x6Axx): bit0 the deep-framebuffer preference is set, bit1 it is false,
        // bit2 MobileGestalt's answer behind the render server's deep flag is true, bit3 it exists, bit4 the compression capability dictionary exists,
        // bit5 the process is not root.
        {
            unsigned bits = 0;
            if (CFTypeRef value = CFPreferencesCopyAppValue(CFSTR("CAEnableDeepFramebuffer"), kCFPreferencesCurrentApplication)) {
                bits |= 1;
                if (CFGetTypeID(value) == CFBooleanGetTypeID() && !CFBooleanGetValue((CFBooleanRef) value)) bits |= 2;
                CFRelease(value);
            }
            if (auto copyAnswer = (CFTypeRef (*)(CFStringRef)) dlsym(RTLD_DEFAULT, "MGCopyAnswer")) {
                if (CFTypeRef deep = copyAnswer(CFSTR("Aixt/MEN2O2B7f+8m4TxUA"))) {
                    bits |= 8;
                    if (CFGetTypeID(deep) == CFBooleanGetTypeID() && CFBooleanGetValue((CFBooleanRef) deep)) bits |= 4;
                    CFRelease(deep);
                }
                if (CFTypeRef caps = copyAnswer(CFSTR("AoKnINTLPoKML3ctoP0AZg"))) {bits |= 16; CFRelease(caps);}
            }
            if (getuid() != 0) bits |= 32;
            gDiagBits = bits;
            gpu->mark(0x6A00 | bits);
        }
        // The render server compresses its framebuffer (an Apple/AGX layout this GPU does not write) unless told not to; the display driver takes plain rows.
        setenv("CA_DISABLE_FRAMEBUFFER_COMPRESSION", "1", 1);
#if defined(__arm64e__)
        // iPadOS 27 picks a 64-bit half-float framebuffer ('RGhA') whenever the display's EDR headroom is above 1 (this panel reports XDR
        // headroom), which the display path can only show converted, slowly and greyed. As on iPadOS 17, where the render server drew plain
        // 8-bit BGRA, the headroom is held at 1. IOMFBDisplay::framebuffer_pixel_format (24A446 0x184461838, asked on every update) takes
        // RGhA when the headroom (Display::edr_headroom, CA_DISPLAY_EDR_HEADROOM first when nonzero) is above CA_FP16_MIN_HEADROOM and
        // the panel's own above 8, or when CA_FORCE_FP16_FRAMEBUFFER, CA_ALLOW_EDR_MIRRORING or the display's own flag says so. Both
        // options are QuartzCore's float options: init_debug reads them from the environment into debug_values (index 21 at
        // __DATA_DIRTY 0x1e7021014, index 81 at 0x1e7021104), so they are set in the environment for a read after this and written for
        // one before it. i84edf75a1 wrote only the stored values (marks 6E01, 6E02) and the framebuffer stayed RGhA: an option read after
        // the plugin loaded put the threshold back to 0. CADefaultsGetFloat takes the environment first (getenv, atof), then the defaults:
        // a threshold of 1e30 is above any headroom.
        // id02fe1633 read back 0x6E19 in one process: CA_ALLOW_EDR_MIRRORING set and the threshold not raised (a process whose options
        // were read after the write). The mirroring option is held off the same two ways (bool option 156 at _ca_debug_options
        // 0x1e702116c + 156; init_debug stores value != 0).
        setenv("CA_DISPLAY_EDR_HEADROOM", "1", 1);
        setenv("CA_FP16_MIN_HEADROOM", "1e30", 1);
        setenv("CA_ALLOW_EDR_MIRRORING", "0", 1);
        // D27 has its own QuartzCore image. Keep the upstream named options
        // above, but no J820 absolute-address writes or diagnostic dereferences.
        gpu->mark(0x6EF0); // Named options only; cached private settings unmodified.

#endif
        // The runtime's creation log reports each VkPipeline making's time to the device's sink, which the telemetry's V row sums
        // (sheng-diag=1).
        unsetenv("METAL2VULKAN_LOG_PIPELINES");
        CFPreferencesSetAppValue(CFSTR("CAEnableFramebufferCompression"), kCFBooleanFalse, kCFPreferencesCurrentApplication);
        CFPreferencesSetAppValue(CFSTR("CAEnableIOSurfaceCompression"), kCFBooleanFalse, kCFPreferencesCurrentApplication);
        char candidates[6][512] = {};
        if (!confstr(_CS_DARWIN_USER_CACHE_DIR, candidates[0], sizeof candidates[0] - 16)) candidates[0][0] = 0;
        if (!confstr(_CS_DARWIN_USER_TEMP_DIR, candidates[1], sizeof candidates[1] - 16)) candidates[1][0] = 0;
        strlcpy(candidates[2], "/tmp/", sizeof candidates[2]);
        strlcpy(candidates[3], "/private/var/tmp/", sizeof candidates[3]);
        // The user temp directory of the mobile user is under /var/mobile/tmp, which launchd's boot task dirs_cleaner empties at every boot,
        // so with a persistent Data store the pipelines were still compiled again each boot (V row hit0). Try the user's Library/Caches first
        // (marker 0x6814); the earlier candidates keep their markers.
        if (const passwd *user = getpwuid(getuid()); user && user->pw_dir && user->pw_dir[0]) {
            snprintf(candidates[4], sizeof candidates[4] - 16, "%s/Library/Caches/com.apple.backboardd", user->pw_dir);
            mkdir(candidates[4], 0700);
            strlcat(candidates[4], "/", sizeof candidates[4]);
        }
        strlcpy(candidates[5], sharedShaderCacheDirectory().c_str(), sizeof candidates[5]);
        // A compact final row retains every candidate's result concurrently:
        // '-' empty, 'c' cache refused, 'r' runtime refused, 'x' exception, '+' open.
        char cacheStages[7] = "------";
        int cacheErrors[6] = {};
        char optionalStage = '-';
        std::string startupError = "no cache candidate";
        static const unsigned order[] = {5, 4, 0, 1, 2, 3};
        for (unsigned i : order) {
            if (device) break;
            if (!candidates[i][0]) continue;
            if (i != 5) strlcat(candidates[i], "m2v", sizeof candidates[i]);
            const int cacheError = d27startup::prepareCache(candidates[i]);
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
            }
            // Files an earlier image's copying import left half written here (int 590aaee2), which hold memory of the Data disk.
            {
                static bool once;
                if (!once && i != 5) {once = true; removeHalfImported(candidates[i]);}
            }
            // The image's pipeline pack (an earlier boot's export), into this directory before the runtime reads it. Marker 0x6Cnn: files written
            // (saturated at 0xfe), 0x6Cff the pack was refused.
            if (char pack[1024]; requestedPath("NativeAdrenoMetal.m2vpack", pack, sizeof pack)) {
                const int imported = cacheexport::importPack(pack, candidates[i]);
                if (imported) gpu->mark(0x6C00 | (imported < 0 ? 0xff : imported > 0xfe ? 0xfe : imported));
            }
            @try {
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
            if (!device && d27_metal_runtime_ready()) {gpu->mark(0x68f6); break;}   // which directory served
        }
        if (!device && !d27_metal_runtime_ready() && !strchr(cacheStages, 'r') && !strchr(cacheStages, 'x')) {
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
            snprintf(text, sizeof text, "%.63s", startupError.c_str());
            streamText(*gpu, text);
            return nil;
        }
        gpu->mark(0x6802);
        // The display hand-off client on its own thread: it only serves, not the discovery.
        pthread_t scanout;
        pthread_attr_t attributes;
        pthread_attr_init(&attributes);
        pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
        pthread_attr_setstacksize(&attributes, 1u << 20);
        pthread_create(&scanout, &attributes, [](void *arg) -> void * {
            Gpu *g = static_cast<Gpu *>(arg);
            sleep(3);
            @try {
                bridgephase::serveScanout(*g, device);
            } @catch (NSException *exception) {
                g->mark(0x68f3);
            }
            return nullptr;
        }, gpu);
        // The cache directory's export to the UFS log only when NativeAdrenoMetal.cacheexport sits beside the bundle: Data persists across
        // boots now, so the caches no longer need the trip through the host, and once priming has filled the directory, every rescan and
        // export competed with the render server (int-245: the scanning thread at 45% CPU, the sending one at 48%, frames twice as slow).
        char exportPath[1024];
        if (requestedPath("NativeAdrenoMetal.cacheexport", exportPath, sizeof exportPath)) {
            pthread_t exporter;
            pthread_create(&exporter, &attributes, [](void *arg) -> void * {
                cacheexport::run(*static_cast<Gpu *>(arg), gCacheDirectory);
                return nullptr;
            }, gpu);
        }
        // Every Metal library of the OS through the runtime, 90 s after the render server opened the device (PrimeShaders.h); the boots that froze
        // or crashed before three minutes never primed anything. Progress is kept in the Data cache directory, so later boots resume.
        // The translator recurses deeply on large functions: give it the stack of a main thread.
        pthread_attr_setstacksize(&attributes, 8u << 20);
        pthread_t primer;
        pthread_create(&primer, &attributes, [](void *) -> void * {
                char list[1024];
                prime::run((id<MTLDevice>)device, gCacheDirectory, 90,
                           requestedPath("NativeAdrenoMetal.primelist", list, sizeof list) ? std::string(list) : std::string());
                return nullptr;
            }, nullptr);
        pthread_attr_destroy(&attributes);
        // The GMEM colour order test (NativeTurnipSwapTest.h), once, 20 s after the device is published: each result line goes to the
        // kernel's GPU trace as a problem record (event 65).
        if (bootArgSet("sheng-swaptest=1") && !strcmp(getprogname(), "backboardd")) {
            pthread_t tester;
            pthread_create(&tester, nullptr, [](void *) -> void * {
                    sleep(20);
                    char path[1024];
                    if (!turnip::libraryPath(path, sizeof path)) return nullptr;
                    void *lib = dlopen(path, RTLD_NOW | RTLD_LOCAL);
                    auto send = lib ? reinterpret_cast<bool (*)(uint32_t, const void *, uint32_t)>(dlsym(lib, "tu_darwin_frame_diagnostic"))
                                    : nullptr;
                    turnip::swaptest::run(path, [&](const char *text) {
                        if (!send) return;
                        NativeGpuTraceRecord record = {};
                        record.event = GpuTraceProblem;
                        strlcpy(reinterpret_cast<char *>(&record.value[1]), text, 11 * sizeof(uint64_t));
                        send(NativeGpuTraceMethod, &record, sizeof record);
                    });
                    return nullptr;
                }, nullptr);
            pthread_detach(tester);
        }
        gpu->mark(0x6803);
        return device;
    }
}
}  // namespace publish

@implementation NativeAdrenoMetalDevice
- (id)initWithAcceleratorPort:(unsigned)port {
    self = [super init];
    if (!self || !port) return nil;
    if (publish::requested()) return publish::deviceForPort(port);
    static bool attempted;
    if (attempted) return nil;
    attempted = true;
    // The test runs on its own thread: a kernel call that never returns (int-042: BoFree) then stalls that thread only, not SpringBoard's
    // main thread (the UI froze with the test running inline).
    // The discovery code releases the accelerator port as soon as this returns nil, which is before the test thread has started: the first
    // marker (and every later open) then went to a dead name and never reached the kernel (K0 in int-043..052, with the plugin file opened by
    // SpringBoard). Keep one extra user reference on the port, and let the thread look the service up itself as well.
    if (void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW | RTLD_LOCAL)) {
        if (auto retain = (int (*)(unsigned))dlsym(iokit, "IOObjectRetain")) retain(port);
    }
    struct Job {unsigned port; char name[32];};
    Job *job = new Job{port, {}};
    strlcpy(job->name, getprogname(), sizeof job->name);
    pthread_t thread;
    pthread_attr_t attributes;
    pthread_attr_init(&attributes);
    pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&thread, &attributes, [](void *arg) -> void * {
            Job *j = static_cast<Job *>(arg);
            unsigned port = j->port;
            if (void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW | RTLD_LOCAL)) {
                auto matching = (void *(*)(const char *))dlsym(iokit, "IOServiceMatching");
                auto getService = (unsigned (*)(unsigned, void *))dlsym(iokit, "IOServiceGetMatchingService");
                if (matching && getService) {
                    const unsigned own = getService(0, matching("IOAcceleratorES"));
                    if (own) port = own;
                }
            }
            gAfterTurnip = bridgephase::run;
            adrenoUserTest(port, j->name);
            delete j;
            return nullptr;
        }, job) != 0) delete job;
    pthread_attr_destroy(&attributes);
    return nil;
}
@end
