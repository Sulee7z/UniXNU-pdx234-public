"""Compose the brightness-only D27 runtime over the exact 068 exec overlay."""

from platform067.arm64e.logging067.qualify import composed_exec

PATCH_NAME = 'audit-d27-addon-reference'
PREPARE = 'static void\nnative_gpu_addon_prepare(proc_t p, user_addr_t scratch)\n'
TAIL = '\tnative_cryptex_os_view(p, scratch);\n'

BODY = r'''static int
native_display069_file(const char *path)
{
	vnode_t vp = NULLVP;
	int error = vnode_lookup(path, 0, &vp, vfs_context_current());
	if (!error) {
		error = vnode_vtype(vp) == VREG ? 0 : EINVAL;
		vnode_put(vp);
	}
	return error;
}

/* This only rolls back a newly installed top mount (stage >= 3). Use the
 * existing syscall path, including its normal authorization and VROOT checks. */
static int
native_display069_rollback(proc_t p, user_addr_t scratch, const char *point, size_t size)
{
	struct unmount_args request = {.path = scratch + 0x620, .flags = MNT_NOFOLLOW};
	int32_t result = 0;
	int error = copyout(point, request.path, size);
	return error ? error : unmount(p, &request, &result);
}

static __attribute__((noinline)) void
native_display069_runtime(proc_t p, user_addr_t scratch, int wifi_visible)
{
	uint32_t enabled = 0, control = 1;
	if (!PE_parse_boot_argn("backlight", &enabled, sizeof(enabled)) || enabled != 1) {
		return;
	}
	PE_parse_boot_argn("backlight-control", &control, sizeof(control));
	if (control != 1 || native_gpu_addon_files <= 0 || native_gpu_addon_failed || native_gpu_addon_error) {
		return;
	}
	static const char lib_source[] = "/private/var/ngpu/display-lib", lib_point[] = "/usr/lib";
	static const char bin_source[] = "/private/var/ngpu/display-bin", bin_point[] = "/usr/libexec";
	static const char wifi_path[] = "/usr/libexec/unixnu-wpa_supplicant";
	static const char loader_path[] = "/usr/libexec/launchd_cache_loader";
	static volatile int lib_stage, lib_status, bin_stage, bin_status;
	int error = native_display069_file("/private/var/ngpu/display-bin/backboardd");
	if (!error) error = native_display069_file("/private/var/ngpu/display-bin/SonyBacklight069.runtime");
	if (!error) error = native_display069_file("/private/var/ngpu/display-lib/UniXNUBacklight.dylib");
	if (!error) error = native_display069_file(loader_path);
	if (!error && wifi_visible) error = native_display069_file(wifi_path);
	if (error) {
		printf("[sony069-brightness-runtime] missing input: %d\n", error);
		return;
	}
	native_gpu_addon_mount(p, scratch, 0x600, lib_source, sizeof(lib_source),
	    lib_point, sizeof(lib_point), "/usr/lib/dyld", "/usr/lib/UniXNUBacklight.dylib", &lib_stage, &lib_status);
	int rollback = 0;
	if (lib_stage == 5 && !lib_status) {
		native_gpu_addon_mount(p, scratch, 0x600, bin_source, sizeof(bin_source),
		    bin_point, sizeof(bin_point), loader_path, "/usr/libexec/SonyBacklight069.runtime", &bin_stage, &bin_status);
		if (!bin_status && wifi_visible) bin_status = native_display069_file(wifi_path);
		if (!bin_status) bin_status = native_display069_file("/usr/libexec/backboardd");
		if (bin_stage >= 3 && (bin_stage != 5 || bin_status)) {
			rollback = native_display069_rollback(p, scratch, bin_point, sizeof(bin_point));
			if (!rollback) bin_stage = -1;
		}
	} else if (lib_stage >= 3) {
		rollback = native_display069_rollback(p, scratch, lib_point, sizeof(lib_point));
		if (!rollback) lib_stage = -1;
	}
	printf("[sony069-brightness-runtime] library=%d/%d executables=%d/%d rollback=%d\n",
	    lib_stage, lib_status, bin_stage, bin_status, rollback);
}

'''


def adapt_exec(original: str) -> str:
    base = composed_exec(original)
    if base.count(PREPARE) != 1 or base.count(TAIL) != 1 or base.count('wifi_bin_stage, &wifi_bin_status') != 1:
        raise ValueError('068 exec overlay anchors changed')
    return base.replace(PREPARE, BODY + PREPARE).replace(TAIL,
        '\tnative_display069_runtime(p, scratch, wifi_bin_stage == 5 && !wifi_bin_status);\n' + TAIL)


ADAPTERS = {PATCH_NAME: adapt_exec}
