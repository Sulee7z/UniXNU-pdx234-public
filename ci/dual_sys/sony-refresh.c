/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Refresh only the two reviewed Sony kernel partition views, not disk bytes.
 * The caller must compare both on-disk GPT copies with the reviewed plan first.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/blkpg.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

static void fail(const char *message) { perror(message); exit(1); }
static uint64_t le64(const unsigned char *p) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= (uint64_t)p[i] << (i * 8);
    return value;
}
static uint64_t number(const char *path) {
    FILE *file = fopen(path, "r");
    unsigned long long value = 0;
    if (!file || fscanf(file, "%llu", &value) != 1) fail(path);
    if (fclose(file)) fail("fclose");
    return (uint64_t)value;
}
static void geometry(int part, uint64_t start, uint64_t size) {
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/block/sda%d/start", part);
    if (number(path) != start / 512) { errno = EINVAL; fail("kernel start differs"); }
    snprintf(path, sizeof(path), "/sys/class/block/sda%d/size", part);
    if (number(path) != size / 512) { errno = EINVAL; fail("kernel size differs"); }
}
int main(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[1], "refresh-reviewed-sony64")) {
        fprintf(stderr, "usage: sony-refresh refresh-reviewed-sony64\n");
        return 2;
    }
    int fd = open("/dev/block/sda", O_RDONLY | O_CLOEXEC);
    if (fd < 0) fail("open disk");
    uint64_t bytes = 0;
    int sector = 0;
    if (ioctl(fd, BLKGETSIZE64, &bytes) || ioctl(fd, BLKSSZGET, &sector)) fail("geometry");
    if (bytes != 255844155392ULL || sector != 4096) { errno = EINVAL; fail("wrong disk"); }
    unsigned char entries[128 * 3];
    if (pread(fd, entries, sizeof(entries), 8192 + 95 * 128) != sizeof(entries)) fail("GPT read");
    const uint64_t starts[] = {5933398ULL, 62456827ULL, 45679360ULL};
    const uint64_t ends[] = {45679359ULL, 62461946ULL, 62456575ULL};
    const char *names[] = {"userdata", "rddata", "unixnu"};
    for (int i = 0; i < 3; ++i) {
        const unsigned char *p = entries + i * 128;
        if (le64(p + 32) != starts[i] || le64(p + 40) != ends[i]) {
            errno = EINVAL; fail("reviewed GPT bounds differ");
        }
        for (size_t c = 0; c <= strlen(names[i]); ++c) {
            if (p[56 + c * 2] != (unsigned char)names[i][c] || p[57 + c * 2]) {
                errno = EINVAL; fail("GPT labels differ");
            }
        }
    }
    geometry(96, 5933398ULL * 4096, 231519965184ULL);
    geometry(97, 62456827ULL * 4096, 5120ULL * 4096);
    if (access("/sys/class/block/sda98", F_OK) == 0) {
        errno = EEXIST; fail("partition98 already exists; no retry");
    }
    struct blkpg_partition part = {0};
    part.pno = 96;
    part.start = 5933398LL * 4096;
    part.length = 162799460352LL;
    struct blkpg_ioctl_arg arg = { .op = BLKPG_RESIZE_PARTITION, .flags = 0,
                                  .datalen = sizeof(part), .data = &part };
    if (ioctl(fd, BLKPG, &arg)) fail("BLKPG resize96; disk GPT already updated");
    geometry(96, 5933398ULL * 4096, 162799460352ULL);
    memset(&part, 0, sizeof(part));
    part.pno = 98;
    part.start = 45679360LL * 4096;
    part.length = 68719476736LL;
    arg.op = BLKPG_ADD_PARTITION;
    if (ioctl(fd, BLKPG, &arg)) fail("BLKPG add98; do not retry automatically");
    geometry(98, 45679360ULL * 4096, 68719476736ULL);
    geometry(97, 62456827ULL * 4096, 5120ULL * 4096);
    if (close(fd)) fail("close");
    puts("Kernel partition96 resized; partition98 added. No disk writes by this helper.");
    return 0;
}
