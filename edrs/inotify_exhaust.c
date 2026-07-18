#define _GNU_SOURCE
#include <sys/inotify.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static int read_int_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int v;
    fscanf(f, "%d", &v);
    fclose(f);
    return v;
}

static void write_int_file(const char *path, int v)
{
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); return; }
    fprintf(f, "%d\n", v);
    fclose(f);
}

static void cmd_info(void)
{
    int max_w  = read_int_file("/proc/sys/fs/inotify/max_user_watches");
    int max_i  = read_int_file("/proc/sys/fs/inotify/max_user_instances");
    int max_q  = read_int_file("/proc/sys/fs/inotify/max_queued_events");
    printf("[*] inotify limits (current user):\n");
    printf("    max_user_watches   = %d\n", max_w);
    printf("    max_user_instances = %d\n", max_i);
    printf("    max_queued_events  = %d\n", max_q);
}

static void cmd_cap(int new_max)
{
    int cur = read_int_file("/proc/sys/fs/inotify/max_user_watches");
    printf("[*] current max_user_watches = %d\n", cur);
    write_int_file("/proc/sys/fs/inotify/max_user_watches", new_max);
    printf("[+] set max_user_watches = %d\n", new_max);
    printf("[*] new inotify_add_watch() calls by any user will fail with ENOSPC\n");
}

static void cmd_fill(int percent)
{
    int max = read_int_file("/proc/sys/fs/inotify/max_user_watches");
    if (max < 0) { perror("max_user_watches"); return; }

    int target = (max * percent) / 100;
    printf("[*] filling %d%% of max_user_watches (%d/%d)\n", percent, target, max);

    int ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (ifd < 0) { perror("inotify_init1"); return; }

    int *wds = calloc((size_t)target, sizeof(int));
    if (!wds) { close(ifd); return; }

    int added = 0;
    const char *scan_dirs[] = { "/usr/lib", "/usr/bin", "/lib", "/bin", "/etc", NULL };
    char path[512];

    for (int si = 0; scan_dirs[si] && added < target; si++) {
        DIR *d = opendir(scan_dirs[si]);
        if (!d) continue;
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL && added < target) {
            if (ent->d_name[0] == '.') continue;
            snprintf(path, sizeof(path), "%s/%s", scan_dirs[si], ent->d_name);
            int wd = inotify_add_watch(ifd, path, IN_ALL_EVENTS);
            if (wd >= 0) wds[added++] = wd;
        }
        closedir(d);
    }

    printf("[+] consumed %d inotify watches\n", added);
    printf("[*] holding - press Enter to release\n");
    getchar();

    free(wds);
    close(ifd);
    printf("[+] released\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <info|cap|fill>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "info") == 0) cmd_info();
    else if (strcmp(argv[1], "cap") == 0 && argc >= 3) cmd_cap(atoi(argv[2]));
    else if (strcmp(argv[1], "fill") == 0) {
        int pct = argc >= 3 ? atoi(argv[2]) : 90;
        cmd_fill(pct);
    } else { fprintf(stderr, "unknown: %s\n", argv[1]); return 1; }

    return 0;
}
