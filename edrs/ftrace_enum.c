#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

static const char *TRACEFS[] = {
    "/sys/kernel/tracing",
    "/sys/kernel/debug/tracing",
    NULL
};

static const char *tracefs_root(void)
{
    for (int i = 0; TRACEFS[i]; i++) {
        struct stat st;
        if (stat(TRACEFS[i], &st) == 0) return TRACEFS[i];
    }
    return NULL;
}

static void print_file(const char *path, const char *label)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[!] %s: %s\n", path, strerror(errno));
        return;
    }
    printf("=== %s (%s) ===\n", label, path);
    char line[512];
    int count = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strcmp(line, "\n") == 0) continue;
        printf("  %s", line);
        count++;
    }
    if (count == 0) printf("  (empty)\n");
    fclose(f);
    printf("\n");
}

static int count_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[512];
    int n = 0;
    while (fgets(line, sizeof(line), f))
        if (strcmp(line, "\n") != 0 && line[0] != '#') n++;
    fclose(f);
    return n;
}

static void cmd_list(void)
{
    const char *root = tracefs_root();
    if (!root) { fprintf(stderr, "[!] tracefs not found\n"); return; }

    char path[512];

    snprintf(path, sizeof(path), "%s/kprobe_events", root);
    print_file(path, "kprobe events");

    snprintf(path, sizeof(path), "%s/uprobe_events", root);
    print_file(path, "uprobe events");

    snprintf(path, sizeof(path), "%s/set_ftrace_filter", root);
    int ftrace_n = count_file(path);
    if (ftrace_n > 0) print_file(path, "ftrace filter");
    else printf("=== ftrace filter ===\n  (not set)\n\n");

    snprintf(path, sizeof(path), "%s/enabled_functions", root);
    {
        struct stat st;
        if (stat(path, &st) == 0) print_file(path, "enabled functions");
    }

    const char *kprobes_list = "/sys/kernel/debug/kprobes/list";
    {
        struct stat st;
        if (stat(kprobes_list, &st) == 0) print_file(kprobes_list, "kprobes/list");
    }

    snprintf(path, sizeof(path), "%s/tracing_on", root);
    print_file(path, "tracing_on");
}

static int write_str(const char *path, const char *str)
{
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0) { perror(path); return -1; }
    ssize_t n = write(fd, str, strlen(str));
    close(fd);
    return (n < 0) ? -1 : 0;
}

static void cmd_clear_kprobes(int dry_run)
{
    const char *root = tracefs_root();
    if (!root) { fprintf(stderr, "[!] tracefs not found\n"); return; }

    char path[512];
    snprintf(path, sizeof(path), "%s/kprobe_events", root);

    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return; }

    char lines[256][768];
    int n = 0;
    char line[768];
    while (n < 256 && fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = '\0';
        if (strlen(line) == 0) continue;
        memcpy(lines[n], line, 767);
        lines[n][767] = '\0';
        n++;
    }
    fclose(f);

    printf("[*] %d kprobe events to remove\n", n);

    for (int i = 0; i < n; i++) {
        char *space = strchr(lines[i], ' ');
        if (!space) continue;
        *space = '\0';
        char *slash = strchr(lines[i], '/');
        char del[1024];

        if (slash) {
            char *type = lines[i];
            char *name = slash + 1;
            *slash = '\0';
            snprintf(del, sizeof(del), "-%.*s/%.*s", 383, type, 383, name);
            *slash = '/';
        } else {
            snprintf(del, sizeof(del), "-%.*s", 767, lines[i]);
        }

        printf("  [%s] %s -> del: %s\n",
               dry_run ? "dry-run" : "remove",
               lines[i], del);

        if (!dry_run) {
            int fd = open(path, O_WRONLY | O_APPEND);
            if (fd >= 0) {
                write(fd, del, strlen(del));
                write(fd, "\n", 1);
                close(fd);
            }
        }
    }
    if (!dry_run) printf("[+] cleared %d kprobe events\n", n);
}

static void cmd_clear_uprobes(int dry_run)
{
    const char *root = tracefs_root();
    if (!root) { fprintf(stderr, "[!] tracefs not found\n"); return; }

    char path[512];
    snprintf(path, sizeof(path), "%s/uprobe_events", root);

    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return; }

    char line[768];
    int n = 0, removed = 0;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = '\0';
        if (strlen(line) == 0) continue;
        n++;
        char del[1024];
        char *sp = strchr(line, ' ');
        if (sp) *sp = '\0';
        snprintf(del, sizeof(del), "-%.*s\n", 767, line);
        printf("  [%s] %s\n", dry_run ? "dry-run" : "remove", line);
        if (!dry_run) {
            int fd = open(path, O_WRONLY | O_APPEND);
            if (fd >= 0) { write(fd, del, strlen(del)); close(fd); removed++; }
        }
    }
    fclose(f);

    if (!dry_run) printf("[+] cleared %d/%d uprobe events\n", removed, n);
    else printf("[*] would remove %d uprobe events\n", n);
}

static void cmd_tracing_off(void)
{
    const char *root = tracefs_root();
    if (!root) { fprintf(stderr, "[!] tracefs not found\n"); return; }

    char path[512];
    snprintf(path, sizeof(path), "%s/tracing_on", root);
    if (write_str(path, "0\n") == 0)
        printf("[+] tracing disabled (tracing_on=0)\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <list|clear-kprobes|clear-uprobes|tracing-off>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "list") == 0) {
        cmd_list();
    } else if (strcmp(argv[1], "clear-kprobes") == 0) {
        int dry = (argc >= 3 && strcmp(argv[2], "--dry-run") == 0);
        cmd_clear_kprobes(dry);
    } else if (strcmp(argv[1], "clear-uprobes") == 0) {
        int dry = (argc >= 3 && strcmp(argv[2], "--dry-run") == 0);
        cmd_clear_uprobes(dry);
    } else if (strcmp(argv[1], "tracing-off") == 0) {
        cmd_tracing_off();
    } else {
        fprintf(stderr, "unknown command: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
