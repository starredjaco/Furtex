#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static int write_oom(pid_t pid, int score)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/oom_score_adj", (int)pid);
    FILE *f = fopen(path, "w");
    if (!f) { fprintf(stderr, "[!] %s: %s\n", path, strerror(errno)); return -1; }
    fprintf(f, "%d\n", score);
    fclose(f);
    return 0;
}

static int read_oom(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/oom_score_adj", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) return -9999;
    int v;
    fscanf(f, "%d", &v);
    fclose(f);
    return v;
}

static char *read_comm(pid_t pid)
{
    static char comm[256];
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) { comm[0] = '?'; comm[1] = '\0'; return comm; }
    if (!fgets(comm, sizeof(comm), f)) { comm[0] = '?'; comm[1] = '\0'; }
    comm[strcspn(comm, "\n")] = '\0';
    fclose(f);
    return comm;
}

static void cmd_protect(void)
{
    if (write_oom(getpid(), -1000) == 0)
        printf("[+] self (PID %d) oom_score_adj=-1000  - OOM killer will skip us\n",
               (int)getpid());
}

static void cmd_punish(pid_t pid, int score)
{
    char *comm = read_comm(pid);
    if (write_oom(pid, score) == 0)
        printf("[+] PID %d (%s) oom_score_adj=%d  - OOM killer priority elevated\n",
               (int)pid, comm, score);
}

static void cmd_find_punish(const char *name, int score)
{
    DIR *d = opendir("/proc");
    if (!d) { perror("/proc"); return; }

    struct dirent *ent;
    int found = 0;
    while ((ent = readdir(d)) != NULL) {
        char *end;
        pid_t pid = (pid_t)strtol(ent->d_name, &end, 10);
        if (*end != '\0' || pid <= 1) continue;
        char *comm = read_comm(pid);
        if (strstr(comm, name)) {
            cmd_punish(pid, score);
            found++;
        }
    }
    closedir(d);
    if (!found) fprintf(stderr, "[!] no process matching '%s' found\n", name);
}

static void cmd_list(void)
{
    DIR *d = opendir("/proc");
    if (!d) return;

    printf("  %-8s  %-5s  %s\n", "PID", "OOM", "comm");
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        char *end;
        pid_t pid = (pid_t)strtol(ent->d_name, &end, 10);
        if (*end != '\0' || pid <= 0) continue;
        int oom = read_oom(pid);
        if (oom == -9999) continue;
        printf("  %-8d  %-5d  %s\n", (int)pid, oom, read_comm(pid));
    }
    closedir(d);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <protect|punish|hunt|list>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "protect") == 0) {
        cmd_protect();
    } else if (strcmp(argv[1], "punish") == 0 && argc >= 3) {
        int score = argc >= 4 ? atoi(argv[3]) : 900;
        cmd_punish((pid_t)atoi(argv[2]), score);
    } else if (strcmp(argv[1], "hunt") == 0 && argc >= 3) {
        int score = argc >= 4 ? atoi(argv[3]) : 900;
        cmd_find_punish(argv[2], score);
    } else if (strcmp(argv[1], "list") == 0) {
        cmd_list();
    } else {
        fprintf(stderr, "unknown: %s\n", argv[1]); return 1;
    }
    return 0;
}
