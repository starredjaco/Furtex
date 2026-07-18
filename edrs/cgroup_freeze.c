#define _GNU_SOURCE
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static int write_file(const char *path, const char *str)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) { perror(path); return -1; }
    ssize_t n = write(fd, str, strlen(str));
    close(fd);
    return n < 0 ? -1 : 0;
}

static int detect_v2(void)
{
    struct stat st;
    if (stat("/sys/fs/cgroup/cgroup.controllers", &st) == 0) return 1;
    return 0;
}

static void freeze_v2(pid_t pid)
{
    char dir[256];
    snprintf(dir, sizeof(dir), "/sys/fs/cgroup/furtex-freeze-%d", (int)pid);
    mkdir(dir, 0755);

    char path[320];

    snprintf(path, sizeof(path), "%s/cgroup.procs", dir);
    char pidbuf[32];
    snprintf(pidbuf, sizeof(pidbuf), "%d\n", (int)pid);
    if (write_file(path, pidbuf) < 0) {
        fprintf(stderr, "[!] could not move PID %d to cgroup\n", (int)pid); goto out;
    }

    snprintf(path, sizeof(path), "%s/cgroup.freeze", dir);
    if (write_file(path, "1\n") == 0)
        printf("[+] PID %d frozen via cgroup v2 (%s)\n", (int)pid, dir);
    else goto out;

    return;
out:
    rmdir(dir);
}

static void thaw_v2(pid_t pid)
{
    char dir[256];
    snprintf(dir, sizeof(dir), "/sys/fs/cgroup/furtex-freeze-%d", (int)pid);

    char path[320];
    snprintf(path, sizeof(path), "%s/cgroup.freeze", dir);
    write_file(path, "0\n");

    snprintf(path, sizeof(path), "%s/cgroup.procs", dir);
    char pidbuf[32];
    snprintf(pidbuf, sizeof(pidbuf), "%d\n", (int)pid);
    write_file(path, pidbuf);

    printf("[+] PID %d thawed\n", (int)pid);
    rmdir(dir);
}

static void freeze_v1(pid_t pid)
{
    const char *base = "/sys/fs/cgroup/freezer";
    char dir[256];
    snprintf(dir, sizeof(dir), "%s/furtex-%d", base, (int)pid);
    mkdir(dir, 0755);

    char path[320];
    snprintf(path, sizeof(path), "%s/tasks", dir);
    char pidbuf[32];
    snprintf(pidbuf, sizeof(pidbuf), "%d\n", (int)pid);
    if (write_file(path, pidbuf) < 0) {
        fprintf(stderr, "[!] write tasks failed - is freezer cgroup mounted?\n");
        rmdir(dir);
        return;
    }

    snprintf(path, sizeof(path), "%s/freezer.state", dir);
    if (write_file(path, "FROZEN\n") == 0)
        printf("[+] PID %d frozen via cgroup v1 freezer (%s)\n", (int)pid, dir);
}

static void thaw_v1(pid_t pid)
{
    char dir[256];
    snprintf(dir, sizeof(dir), "/sys/fs/cgroup/freezer/furtex-%d", (int)pid);

    char path[320];
    snprintf(path, sizeof(path), "%s/freezer.state", dir);
    write_file(path, "THAWED\n");

    snprintf(path, sizeof(path), "%s/tasks", dir);
    char pidbuf[32];
    snprintf(pidbuf, sizeof(pidbuf), "%d\n", (int)pid);
    write_file(path, pidbuf);

    printf("[+] PID %d thawed (v1)\n", (int)pid);
    rmdir(dir);
}

static void find_pids(const char *name)
{
    DIR *d = opendir("/proc");
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        char *end;
        pid_t pid = (pid_t)strtol(ent->d_name, &end, 10);
        if (*end) continue;

        char comm_path[64], comm[256];
        snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", (int)pid);
        FILE *f = fopen(comm_path, "r");
        if (!f) continue;
        if (!fgets(comm, sizeof(comm), f)) { fclose(f); continue; }
        fclose(f);
        comm[strcspn(comm, "\n")] = '\0';

        if (strstr(comm, name)) printf("  PID %-6d  %s\n", (int)pid, comm);
    }
    closedir(d);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <find|freeze|thaw>\n", argv[0]);
        return 1;
    }

    int v2 = detect_v2();
    printf("[*] cgroup %s detected\n", v2 ? "v2" : "v1");

    if (strcmp(argv[1], "find") == 0 && argc >= 3) {
        find_pids(argv[2]);
        return 0;
    }

    if (argc < 3) { fprintf(stderr, "[!] need PID\n"); return 1; }
    pid_t pid = (pid_t)atoi(argv[2]);

    if (strcmp(argv[1], "freeze") == 0) {
        if (v2) freeze_v2(pid); else freeze_v1(pid);
    } else if (strcmp(argv[1], "thaw") == 0) {
        if (v2) thaw_v2(pid); else thaw_v1(pid);
    } else {
        fprintf(stderr, "unknown: %s\n", argv[1]); return 1;
    }
    return 0;
}
