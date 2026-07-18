#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/sendfile.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>

#ifndef __NR_openat2
#define __NR_openat2       437
#endif
#ifndef __NR_copy_file_range
#define __NR_copy_file_range 326
#endif
#ifndef __NR_preadv2
#define __NR_preadv2       327
#endif
#ifndef __NR_pwritev2
#define __NR_pwritev2      328
#endif
#ifndef __NR_statx
#define __NR_statx         332
#endif
#ifndef __NR_close_range
#define __NR_close_range   436
#endif

#ifndef RESOLVE_NO_XDEV
struct open_how_local {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};
#define RESOLVE_NO_SYMLINKS (1 << 2)
#define RESOLVE_BENEATH     (1 << 3)
typedef struct open_how_local open_how_t;
#else
typedef struct open_how open_how_t;
#endif

static int do_openat2(const char *path, int flags, mode_t mode, uint64_t resolve)
{
    open_how_t how = {};
    how.flags   = (uint64_t)flags;
    how.mode    = (uint64_t)mode;
    how.resolve = resolve;
    return (int)syscall(__NR_openat2, AT_FDCWD, path, &how, sizeof(how));
}

static ssize_t do_preadv2(int fd, void *buf, size_t len, int64_t offset)
{
    struct iovec iov = { .iov_base = buf, .iov_len = len };

    return syscall(__NR_preadv2, fd, &iov, 1, (long)offset, (long)0, 0);
}

static ssize_t do_pwritev2(int fd, const void *buf, size_t len, int64_t offset)
{
    struct iovec iov = { .iov_base = (void *)buf, .iov_len = len };
    return syscall(__NR_pwritev2, fd, &iov, 1, (long)offset, (long)0, 0);
}

static ssize_t do_copy_file_range(int fd_in, int fd_out, size_t len)
{
    return syscall(__NR_copy_file_range,
                   fd_in, NULL, fd_out, NULL, len, 0);
}

static void cmd_cat(const char *path)
{

    int fd = do_openat2(path, O_RDONLY | O_CLOEXEC, 0, 0);
    if (fd < 0) {
        fprintf(stderr, "[!] openat2 '%s': %s\n", path, strerror(errno));
        return;
    }

    char buf[8192];
    ssize_t n;

    while ((n = do_preadv2(fd, buf, sizeof(buf), -1)) > 0)
        do_pwritev2(STDOUT_FILENO, buf, (size_t)n, -1);
    close(fd);
}

static void cmd_copy(const char *src, const char *dst)
{
    int rfd = do_openat2(src, O_RDONLY, 0, 0);
    if (rfd < 0) {
        fprintf(stderr, "[!] openat2 src: %s\n", strerror(errno)); return;
    }
    int wfd = do_openat2(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644, 0);
    if (wfd < 0) {
        fprintf(stderr, "[!] openat2 dst: %s\n", strerror(errno));
        close(rfd); return;
    }

    size_t total = 0;
    ssize_t n;
    while ((n = do_copy_file_range(rfd, wfd, 1 << 20)) > 0)
        total += (size_t)n;

    close(rfd); close(wfd);
    fprintf(stderr, "[+] copy_file_range: %zu bytes '%s' → '%s'\n", total, src, dst);
}

static void cmd_write(const char *path, const char *data)
{
    int fd = do_openat2(path, O_WRONLY | O_CREAT | O_APPEND, 0644, 0);
    if (fd < 0) {
        fprintf(stderr, "[!] openat2: %s\n", strerror(errno)); return;
    }
    size_t len = strlen(data);
    ssize_t n = do_pwritev2(fd, data, len, 0);
    do_pwritev2(fd, "\n", 1, (uint64_t)len);
    close(fd);
    fprintf(stderr, "[+] pwritev2: %zd bytes → '%s'\n", n, path);
}

static void cmd_stat(const char *path)
{

    struct {
        uint32_t stx_mask, stx_blksize; uint64_t stx_attributes;
        uint32_t stx_nlink; uint32_t stx_uid, stx_gid;
        uint16_t stx_mode; uint16_t pad1;
        uint64_t stx_ino, stx_size, stx_blocks;
        uint64_t stx_attributes_mask;
        struct { int64_t tv_sec; uint32_t tv_nsec; uint32_t pad; } stx_atime, stx_btime, stx_ctime, stx_mtime;
        uint32_t stx_rdev_major, stx_rdev_minor, stx_dev_major, stx_dev_minor;
        uint64_t stx_mnt_id; uint64_t spare[9];
    } sx = {};

    long r = syscall(__NR_statx, AT_FDCWD, path,
                     AT_STATX_SYNC_AS_STAT, 0xfffU, &sx);
    if (r < 0) {
        fprintf(stderr, "[!] statx: %s\n", strerror(errno)); return;
    }
    printf("  inode=%-12lu  size=%-12lu  mode=%04o  uid=%u gid=%u\n",
           (unsigned long)sx.stx_ino,
           (unsigned long)sx.stx_size,
           (unsigned)sx.stx_mode & 07777,
           sx.stx_uid, sx.stx_gid);
}

static void cmd_probe(void)
{
    printf("[*] probing alternative syscall availability on this kernel:\n");

    struct { const char *name; long nr; } sc[] = {
        { "openat2",        __NR_openat2        },
        { "copy_file_range",__NR_copy_file_range},
        { "preadv2",        __NR_preadv2        },
        { "pwritev2",       __NR_pwritev2       },
        { "statx",          __NR_statx          },
        { "close_range",    __NR_close_range    },
        { "io_uring_setup", __NR_io_uring_setup },
        { NULL, 0 }
    };

    for (int i = 0; sc[i].name; i++) {

        syscall(sc[i].nr, -1, NULL, NULL, NULL, NULL, NULL);
        int avail = (errno != ENOSYS);
        printf("  %-20s  nr=%-4ld  %s\n",
               sc[i].name, sc[i].nr,
               avail ? "available" : "ENOSYS (not on this kernel)");
    }

    printf("\n[*] if openat kprobes are present, 'openat2' likely not hooked.\n");
    printf("    check with: edr_recon kprobes | grep openat\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <probe|cat|write|copy|stat>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "probe") == 0) {
        cmd_probe();
    } else if (strcmp(argv[1], "cat") == 0 && argc >= 3) {
        cmd_cat(argv[2]);
    } else if (strcmp(argv[1], "write") == 0 && argc >= 4) {
        cmd_write(argv[2], argv[3]);
    } else if (strcmp(argv[1], "copy") == 0 && argc >= 4) {
        cmd_copy(argv[2], argv[3]);
    } else if (strcmp(argv[1], "stat") == 0 && argc >= 3) {
        cmd_stat(argv[2]);
    } else {
        fprintf(stderr, "unknown: %s\n", argv[1]);
        return 1;
    }
    return 0;
}
