/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <sys/errno.h>
#include <sys/systm.h>
#include <IOKit/IOLib.h>
#include <libkern/crypto/sha2.h>
#include "WifiFirmware.h"
#include "BluetoothFirmware.h"

struct SonyFirmwareFile {
    const char *name;
    size_t bytes;
    uint8_t sha256[SHA256_DIGEST_LENGTH];
};
#include "SonyFirmware.generated.h"

static int check(const struct SonyFirmwareFile *files, size_t count,
                 const char *name, const uint8_t *data, size_t size)
{
    if (!name || !data) return EINVAL;
    for (size_t i = 0; i < count; ++i) {
        const struct SonyFirmwareFile *file = &files[i];
        if (strcmp(name, file->name)) continue;
        if (size != file->bytes) return EINVAL;
        SHA256_CTX hash;
        uint8_t digest[SHA256_DIGEST_LENGTH];
        SHA256_Init(&hash);
        SHA256_Update(&hash, data, size);
        SHA256_Final(digest, &hash);
        return memcmp(digest, file->sha256, sizeof(digest)) ? EAUTH : 0;
    }
    return ENOENT;
}

#define ELEMENTS(array) (sizeof(array) / sizeof((array)[0]))

int sony069_wifi_verify_firmware(const char *name, const uint8_t *data, size_t size)
{
    return check(wifi_files, ELEMENTS(wifi_files), name, data, size);
}

int sony069_bt_verify_firmware(const char *name, const uint8_t *data, size_t size)
{
    return check(bt_files, ELEMENTS(bt_files), name, data, size);
}

int sony_wcn_wifi_inputs_ready(void)
{
    // Reuse the same checked reads that supply bytes to the driver. This gate
    // runs on the Wi-Fi worker after addon install and before WLAN_EN changes.
    for (size_t i = 0; i < ELEMENTS(wifi_files); ++i) {
        uint8_t *data = NULL;
        size_t size = 0;
        int error = sony_wifi_firmware_read(wifi_files[i].name, &data, &size);
        if (error) return error;
        IOFreeData(data, size);
    }
    return 0;
}

int sony_wcn_bluetooth_inputs_ready(void)
{
    static const char *const base[] = {"qca/hmtbtfw20.tlv", "qca/hmtnv20.bin"};
    for (size_t i = 0; i < ELEMENTS(base); ++i) {
        uint8_t *data = NULL;
        size_t size = 0;
        int error = sheng_bt_firmware_read(base[i], &data, &size);
        if (error) return error;
        sheng_bt_firmware_release(data, size);
    }
    // The actual ROM/BID query still selects the NVM. Each requested variant
    // is independently checked by BluetoothFirmware before it reaches QCA.
    return 0;
}
