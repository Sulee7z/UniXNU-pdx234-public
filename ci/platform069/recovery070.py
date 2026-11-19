"""Follow-up to the measured PDX069 run; never change the frozen 069 adapter."""
from platform069.display_runtime import PATCH_NAME, adapt_exec as exec069
from platform069.crashes.qualify import adapt_boot_log as bootlog069


def once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('PDX070 source anchor changed: ' + before[:120])
    return text.replace(before, after, 1)


def adapt_exec(text):
    text = exec069(text)
    text = once(text, 'volatile int native_gpu_addon_error = 0;', '''volatile int native_gpu_addon_error = 0;
/* Written only by the boot addon installer, consumed in the same prepare call. */
static uint32_t native_display070_files;
volatile int native_display070_runtime_status[5];''')
    text = once(text, '\tnative_gpu_addon_files = (int)count;',
        '\tnative_display070_files = 0;\n\tnative_gpu_addon_files = (int)count;')
    text = once(text, '\t\tif (error < 0) {\n\t\t\tnative_gpu_addon_same++;', '''		/* -1 from the writer means exact existing bytes and mode. Do not
		 * accept a merely present file or hide an error in a required member. */
		if (!strcmp(name, "display-lib/UniXNUBacklight.dylib")) {
			native_display070_files = (native_display070_files & ~1u) | (error <= 0 ? 1u : 0u);
		} else if (!strcmp(name, "display-bin/backboardd")) {
			native_display070_files = (native_display070_files & ~2u) | (error <= 0 ? 2u : 0u);
		} else if (!strcmp(name, "display-bin/SonyBacklight069.runtime")) {
			native_display070_files = (native_display070_files & ~4u) | (error <= 0 ? 4u : 0u);
		}
		if (error < 0) {
			native_gpu_addon_same++;''')
    text = once(text, 'if (control != 1 || native_gpu_addon_files <= 0 || native_gpu_addon_failed || native_gpu_addon_error) {', '''if (control != 1) {
		return;
	}
	if (native_display070_files != 7u) {
		native_display070_runtime_status[1] = ENOENT;
		printf("[sony070-brightness] incomplete staging mask=%u addon-error=%d\\n",
		    native_display070_files, native_gpu_addon_error);''')
    text = once(text, '\t\tprintf("[sony069-brightness-runtime] missing input: %d\\n", error);',
        '\t\tnative_display070_runtime_status[1] = error;\n\t\tprintf("[sony069-brightness-runtime] missing input: %d\\n", error);')
    return once(text, '\tprintf("[sony069-brightness-runtime] library=', '''	native_display070_runtime_status[0] = lib_stage;
	native_display070_runtime_status[1] = lib_status;
	native_display070_runtime_status[2] = bin_stage;
	native_display070_runtime_status[3] = bin_status;
	native_display070_runtime_status[4] = rollback;
	printf("[sony069-brightness-runtime] library=''')


def adapt_boot_log(text):
    text = bootlog069(text)
    anchor = 'static int log_crash_evidence_on;'
    if text.count(anchor) != 1:
        raise ValueError('PDX070 BootLog selector anchor changed')
    return once(text, '    if (diag == 1 || log_crash_evidence_on) text = diag_msg_lines', '''    if (log_crash_evidence_on) {
      extern volatile int native_display070_runtime_status[5] __attribute__((weak_import));
      extern volatile int32_t native_sony_display069_stats[32] __attribute__((weak_import));
      char peripheral[256];
      if (&native_wifi_stats && &native_wifi_mhi && &native_bluetooth_stats) {
        snprintf(peripheral, sizeof peripheral, "[sony070-radio] wifi=%d stack=%d ready=%08x bt=%llu errno=%lld step=%llu",
            (int)native_wifi_stats[0], (int)native_wifi_mhi[0], native_wifi_mhi[1],
            (unsigned long long)native_bluetooth_stats[0], (long long)(int64_t)native_bluetooth_stats[1],
            (unsigned long long)native_bluetooth_stats[14]);
        text = put((char *)boot_log_buffer, text, LogSlotBlocks * LogBlock, peripheral, sizeof peripheral);
      }
      if (&native_display070_runtime_status && &native_sony_display069_stats) {
        const volatile int *m = native_display070_runtime_status;
        const volatile int32_t *s = native_sony_display069_stats;
        snprintf(peripheral, sizeof peripheral, "[sony070-display] lib=%d/%d exec=%d/%d rollback=%d owner=%d err=%d rss=%d request=%d sent=%d packets=%d",
            m[0], m[1], m[2], m[3], m[4], s[0], s[1], s[10], s[2], s[3], s[7]);
        text = put((char *)boot_log_buffer, text, LogSlotBlocks * LogBlock, peripheral, sizeof peripheral);
      }
    }
    if (diag == 1 || log_crash_evidence_on) text = diag_msg_lines''')


ADAPTERS = {PATCH_NAME: adapt_exec, 'crashes069-persistent-lines': adapt_boot_log}


def adapt_supplicant(text):
    return once(text, '''  driver->client = nw_control_client_open();
  if (!driver->client) { wpa_printf(MSG_ERROR, "sheng: native control open failed: %s", strerror(errno)); os_free(driver); return NULL; }
  u8 bytes[64]; struct nw_control_builder b; struct nw_control_view reply;
  if (sheng_begin(driver, &b, bytes, sizeof(bytes), NW_CONTROL_INFO) ||
      sheng_rpc(driver, &b, &reply)) {
    wpa_printf(MSG_ERROR, "sheng: native INFO failed: %s", strerror(errno)); goto fail;
  }''', '''  u8 bytes[64]; struct nw_control_builder b; struct nw_control_view reply;
  /* launchd starts before firmware and cfg80211 necessarily register en0.
   * Retry only not-ready errors; no retry of authentication or protocol errors.
   * INFO is bounded independently so an unresponsive control port is not polled. */
  for (unsigned attempt = 0; ; attempt++) {
    int error;
    driver->client = nw_control_client_open();
    if (!driver->client) {
      error = errno;
      if (error != ENOENT && error != ENXIO && error != ENODEV) {
        wpa_printf(MSG_ERROR, "sheng: native control open failed: %s", strerror(error)); goto fail;
      }
    } else {
      if (sheng_begin(driver, &b, bytes, sizeof(bytes), NW_CONTROL_INFO)) goto fail;
      int result = nw_control_client_exchange(driver->client, &b, &reply, 1000);
      if (result == NW_CONTROL_OK) {
        if (nw_control_client_has_events(driver->client)) sheng_schedule(driver);
        break;
      }
      if (result != NW_CONTROL_NOT_READY) {
        wpa_printf(MSG_ERROR, "sheng: native INFO failed: status=%d errno=%d", result, result < 0 ? errno : 0); goto fail;
      }
      nw_control_client_close(driver->client); driver->client = NULL;
    }
    if (attempt == 29) { wpa_printf(MSG_ERROR, "sheng: native Wi-Fi still not ready"); goto fail; }
    os_sleep(1, 0);
  }''')
