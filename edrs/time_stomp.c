#define _GNU_SOURCE
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

static void show_times(const char *path)
{
    struct stat st;
    if (stat(path, &st) < 0) { perror(path); return; }

    char abuf[64], mbuf[64], cbuf[64];
    struct tm tm;

    gmtime_r(&st.st_atim.tv_sec, &tm);
    strftime(abuf, sizeof(abuf), "%Y-%m-%d %H:%M:%S UTC", &tm);
    gmtime_r(&st.st_mtim.tv_sec, &tm);
    strftime(mbuf, sizeof(mbuf), "%Y-%m-%d %H:%M:%S UTC", &tm);
    gmtime_r(&st.st_ctim.tv_sec, &tm);
    strftime(cbuf, sizeof(cbuf), "%Y-%m-%d %H:%M:%S UTC", &tm);

    printf("  atime (access):   %s\n", abuf);
    printf("  mtime (modify):   %s\n", mbuf);
    printf("  ctime (change):   %s (kernel-set, read-only)\n", cbuf);
}

static void cmd_show(const char *path)
{
    printf("[*] %s:\n", path);
    show_times(path);
}

static void cmd_clone(const char *src, const char *dst)
{
    struct stat st;
    if (stat(src, &st) < 0) { perror(src); return; }

    struct timespec ts[2];
    ts[0] = st.st_atim;
    ts[1] = st.st_mtim;

    if (utimensat(AT_FDCWD, dst, ts, 0) < 0) {
        perror(dst); return;
    }
    printf("[+] cloned atime+mtime from '%s' to '%s'\n", src, dst);
    printf("[*] after:\n");
    show_times(dst);
}

static void cmd_set(const char *path, time_t epoch)
{
    struct timespec ts[2];
    ts[0].tv_sec  = epoch; ts[0].tv_nsec = 0;
    ts[1].tv_sec  = epoch; ts[1].tv_nsec = 0;

    if (utimensat(AT_FDCWD, path, ts, 0) < 0) {
        perror(path); return;
    }
    char buf[64];
    struct tm tm;
    gmtime_r(&epoch, &tm);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm);
    printf("[+] set atime+mtime of '%s' to %s\n", path, buf);
}

static void cmd_zero(const char *path)
{
    cmd_set(path, 0);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <show|clone|set|zero|match>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "show") == 0 && argc >= 3) {
        cmd_show(argv[2]);
    } else if (strcmp(argv[1], "clone") == 0 && argc >= 4) {
        cmd_clone(argv[2], argv[3]);
    } else if (strcmp(argv[1], "set") == 0 && argc >= 4) {
        cmd_set(argv[2], (time_t)atol(argv[3]));
    } else if (strcmp(argv[1], "zero") == 0 && argc >= 3) {
        cmd_zero(argv[2]);
    } else if (strcmp(argv[1], "match") == 0 && argc >= 4) {
        cmd_clone(argv[3], argv[2]);
        return 0;
    } else {
        fprintf(stderr, "unknown: %s\n", argv[1]); return 1;
    }
    return 0;
}
