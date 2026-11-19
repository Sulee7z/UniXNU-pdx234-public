// SPDX-License-Identifier: MIT
// Verify copied seed nodes, bytes and extended attributes without following links.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

static unsigned nodes, files, links, attributes;
static void die(const char *format, ...) {
    va_list args; va_start(args, format); vfprintf(stderr, format, args); va_end(args);
    fputc('\n', stderr); exit(1);
}
static void *allocate(size_t bytes) {
    void *p = malloc(bytes ? bytes : 1);
    if (!p) die("allocation failed");
    return p;
}
static char *join(const char *base, const char *name) {
    char *p = NULL;
    if (asprintf(&p, "%s/%s", base, name) < 0) die("path allocation failed");
    return p;
}
static void compare_attributes(const char *a, const char *b) {
    ssize_t na = llistxattr(a, NULL, 0), nb = llistxattr(b, NULL, 0);
    if (na < 0 || nb < 0 || na != nb) die("xattr list differs: %s (%zd/%zd)", a, na, nb);
    char *names = allocate((size_t)na);
    if (llistxattr(a, names, (size_t)na) != na) die("xattr list changed: %s", a);
    for (ssize_t i = 0; i < na;) {
        size_t len = strnlen(names + i, (size_t)(na - i));
        if (!len || len >= (size_t)(na - i)) die("invalid xattr name: %s", a);
        const char *name = names + i;
        ssize_t va = lgetxattr(a, name, NULL, 0), vb = lgetxattr(b, name, NULL, 0);
        if (va < 0 || vb != va) die("xattr length differs: %s:%s", a, name);
        void *ba = allocate((size_t)va), *bb = allocate((size_t)vb);
        if (lgetxattr(a, name, ba, (size_t)va) != va ||
            lgetxattr(b, name, bb, (size_t)vb) != vb || memcmp(ba, bb, (size_t)va))
            die("xattr bytes differ: %s:%s", a, name);
        free(ba); free(bb); ++attributes; i += (ssize_t)len + 1;
    }
    free(names);
}
static void compare_file(const char *a, const char *b) {
    int fa = open(a, O_RDONLY | O_NOFOLLOW), fb = open(b, O_RDONLY | O_NOFOLLOW);
    if (fa < 0 || fb < 0) die("file open failed: %s", a);
    unsigned long aa = 0, ab = 0;
    if (ioctl(fa, FS_IOC_GETFLAGS, &aa) || ioctl(fb, FS_IOC_GETFLAGS, &ab) || aa != ab)
        die("inode flags differ: %s", a);
    uint8_t ba[65536], bb[65536];
    for (;;) {
        ssize_t na = read(fa, ba, sizeof ba), nb = read(fb, bb, sizeof bb);
        if (na < 0 || nb < 0 || na != nb || memcmp(ba, bb, (size_t)na))
            die("file bytes differ: %s", a);
        if (!na) break;
    }
    if (close(fa) || close(fb)) die("file close failed: %s", a);
    ++files;
}
static unsigned directory_count(const char *path) {
    DIR *dir = opendir(path); if (!dir) die("directory open failed: %s", path);
    unsigned count = 0;
    for (;;) {
        errno = 0; struct dirent *entry = readdir(dir);
        if (!entry) { if (errno) die("readdir failed: %s", path); break; }
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) ++count;
    }
    if (closedir(dir)) die("directory close failed: %s", path);
    return count;
}
static void verify(const char *a, const char *b, unsigned depth) {
    struct stat sa, sb;
    if (depth > 128 || lstat(a, &sa) || lstat(b, &sb)) die("node inaccessible: %s", a);
    if (sa.st_mode != sb.st_mode || sa.st_uid != sb.st_uid || sa.st_gid != sb.st_gid ||
        (!S_ISDIR(sa.st_mode) && sa.st_nlink != sb.st_nlink) ||
        sa.st_mtim.tv_sec != sb.st_mtim.tv_sec || sa.st_mtim.tv_nsec != sb.st_mtim.tv_nsec ||
        (!S_ISDIR(sa.st_mode) && sa.st_size != sb.st_size) || sa.st_rdev != sb.st_rdev)
        die("node metadata differs: %s", a);
    ++nodes; compare_attributes(a, b);
    if (S_ISREG(sa.st_mode)) compare_file(a, b);
    else if (S_ISLNK(sa.st_mode)) {
        size_t cap = (size_t)sa.st_size + 2;
        char *ba = allocate(cap), *bb = allocate(cap);
        ssize_t na = readlink(a, ba, cap), nb = readlink(b, bb, cap);
        if (na < 0 || na != nb || (size_t)na >= cap || memcmp(ba, bb, (size_t)na))
            die("symlink differs: %s", a);
        free(ba); free(bb); ++links;
    } else if (S_ISDIR(sa.st_mode)) {
        if (directory_count(a) != directory_count(b)) die("directory entries differ: %s", a);
        DIR *dir = opendir(a); if (!dir) die("directory open failed: %s", a);
        for (;;) {
            errno = 0; struct dirent *entry = readdir(dir);
            if (!entry) { if (errno) die("readdir failed: %s", a); break; }
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
            char *pa = join(a, entry->d_name), *pb = join(b, entry->d_name);
            verify(pa, pb, depth + 1); free(pa); free(pb);
        }
        if (closedir(dir)) die("directory close failed: %s", a);
    } else if (!S_ISFIFO(sa.st_mode) && !S_ISCHR(sa.st_mode) && !S_ISBLK(sa.st_mode))
        die("unsupported seed node type: %s", a);
}
int main(int argc, char **argv) {
    if (argc != 3) die("usage: verify-tree SOURCE DESTINATION");
    verify(argv[1], argv[2], 0);
    printf("SEED_TREE_PASS nodes=%u files=%u symlinks=%u xattrs=%u\n", nodes, files, links, attributes);
    return 0;
}
