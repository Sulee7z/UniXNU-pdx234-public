"""Remove unqualified J820 QuartzCore accesses from the D27 runtime build."""
def adapt(text):
    before=text
    start=text.index('static bool readTask(uintptr_t address,')
    stop=text.index('static bool bootArgSet(',start)
    text=text[:start]+text[stop:]
    start=text.index('static unsigned patchFramebufferBranch(uintptr_t slide)')
    stop=text.index('// Every process other than the render server:',start)
    text=text[:start]+text[stop:]
    start=text.index('        if (void *start = dlsym(RTLD_DEFAULT, "CARenderServerStart")) {')
    stop=text.index('\n#endif',start)
    text=text[:start]+'''        // D27 has its own QuartzCore image. Keep the upstream named options
        // above, but no J820 absolute-address writes or diagnostic dereferences.
        gpu->mark(0x6EF0); // Named options only; cached private settings unmodified.
'''+text[stop:]
    for forbidden in ('writeTask(', 'readTask(', 'patchFramebufferBranch(', '0x1846dce88', '0x1e7021014 +', '0x1e7021104 +', '0x1e701bdd9 +'):
        if forbidden in text:raise ValueError('Unqualified access remains: '+forbidden)
    if before==text:raise ValueError('No adaptation performed')
    return text
