"""Opt-in extension applied AFTER d27_metal_startup.adapt; no kernel ABI changes."""
from pathlib import Path


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f'Unreviewed dlopen diagnostic anchor: {old[:100]!r}')
    return text.replace(old, new, 1)


def adapt(text):
    if 'D27DlopenDiagnostic.h' in text:
        raise ValueError('Dlopen diagnostic extension already applied')
    text = replace_once(text, '#include "D27MetalStartup.h"',
                        '#include "D27MetalStartup.h"\n#include "D27DlopenDiagnostic.h"')
    text = replace_once(text, '''        dlerror();
        void *startupLoader = dlopen(turnip, RTLD_NOW | RTLD_LOCAL);
        const char *loaderError = startupLoader ? nullptr : dlerror();''', '''        d27dlopen::Diagnostic loaderDiagnostic(turnip, RTLD_NOW | RTLD_LOCAL);
        dlerror();
        void *startupLoader = dlopen(turnip, RTLD_NOW | RTLD_LOCAL);
        if (!startupLoader) loaderDiagnostic.capture(dlerror());''')
    text = replace_once(text, '                loaderError = dlerror();',
                        '                loaderDiagnostic.capture(dlerror());')
    text = replace_once(text, '''            if (!loaderError) loaderError = "missing loader symbol";
            NSLog(@"D27 Metal %s %s: %s", loaderStage, turnip, loaderError);
            char text[64];
            snprintf(text, sizeof text, "PUB %.20s %.37s", loaderStage, loaderError);
            streamText(*gpu, text);''', '''            char loaderRows[2][64];
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
            pthread_mutex_unlock(&gStreamLock);''')
    return text


def stage_header(directory):
    """Builder calls this explicitly when selecting the diagnostic extension."""
    source = Path(__file__).with_name('D27DlopenDiagnostic.h')
    (Path(directory)/source.name).write_bytes(source.read_bytes())
