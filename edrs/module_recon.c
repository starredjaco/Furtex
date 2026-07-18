#define _GNU_SOURCE
#include <dirent.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static const char *edr_patterns[] = {
    "edr_kmod", "edr_alpha",   "edra_",
    "edr_delta", "edr_d_",     "edr_agd",
    "edr_agentd", "edr_epsilon", "edr_e_",
    "edr_theta", "edr_endpoint_t",
    "tetragon", "cilium",
    "falco",
    "wazuh",
    "edr_iota", "edr_khook_i", "edr_i_",
    "edr_xdr",  "edr_beta",    "edr_lsm",
    "edr_cylnc", "edr_optic",
    "osquery",
    NULL
};

static int is_edr(const char *name)
{
    char lower[256];
    size_t i;
    for (i = 0; i < sizeof(lower)-1 && name[i]; i++)
        lower[i] = (name[i] >= 'A' && name[i] <= 'Z') ? name[i] + 32 : name[i];
    lower[i] = '\0';

    for (int j = 0; edr_patterns[j]; j++)
        if (strstr(lower, edr_patterns[j])) return 1;
    return 0;
}

static void read_module_info(const char *modname)
{
    char path[256];
    snprintf(path, sizeof(path), "/sys/module/%s/version", modname);
    FILE *f = fopen(path, "r");
    if (f) {
        char ver[64]; fgets(ver, sizeof(ver), f); fclose(f);
        ver[strcspn(ver, "\n")] = '\0';
        printf("    version:    %s\n", ver);
    }

    snprintf(path, sizeof(path), "/sys/module/%s/refcnt", modname);
    f = fopen(path, "r");
    if (f) {
        int rc; fscanf(f, "%d", &rc); fclose(f);
        printf("    refcount:   %d\n", rc);
    }

    snprintf(path, sizeof(path), "/sys/module/%s/holders", modname);
    DIR *d = opendir(path);
    if (d) {
        struct dirent *ent;
        int first = 1;
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            if (first) { printf("    holders:    "); first = 0; }
            else printf(", ");
            printf("%s", ent->d_name);
        }
        if (!first) printf("\n");
        closedir(d);
    }

    snprintf(path, sizeof(path), "/sys/module/%s/srcversion", modname);
    f = fopen(path, "r");
    if (f) {
        char sv[64]; fgets(sv, sizeof(sv), f); fclose(f);
        sv[strcspn(sv, "\n")] = '\0';
        printf("    srcversion: %s\n", sv);
    }
}

static void cmd_list(int edr_only)
{
    FILE *f = fopen("/proc/modules", "r");
    if (!f) { perror("/proc/modules"); return; }

    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char name[128];
        unsigned long size;
        int refcnt;
        char deps[256], state[32];
        unsigned long long addr;

        if (sscanf(line, "%127s %lu %d %255s %31s %llx",
                   name, &size, &refcnt, deps, state, &addr) < 5) continue;

        if (edr_only && !is_edr(name)) continue;

        printf("[%s] 0x%llx  size=%-8lu  refs=%-3d  state=%s\n",
               name, addr, size, refcnt, state);

        if (is_edr(name)) {
            printf("  [!] matches EDR pattern\n");
            read_module_info(name);
            found++;
        } else if (!edr_only) {
            read_module_info(name);
        }
    }
    fclose(f);

    if (edr_only && !found) printf("[*] no EDR modules detected\n");
}

static void cmd_hooks(void)
{
    const char *hook_files[] = {
        "/proc/modules",
        "/sys/kernel/debug/kprobes/list",
        NULL
    };

    for (int i = 0; hook_files[i]; i++) {
        FILE *f = fopen(hook_files[i], "r");
        if (!f) continue;
        printf("\n=== %s ===\n", hook_files[i]);
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            int suspicious = 0;
            for (int j = 0; edr_patterns[j]; j++)
                if (strstr(line, edr_patterns[j])) { suspicious = 1; break; }
            if (suspicious) printf("[!] %s", line);
            else printf("    %s", line);
        }
        fclose(f);
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <list|edr|hooks>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "list") == 0) cmd_list(0);
    else if (strcmp(argv[1], "edr") == 0) cmd_list(1);
    else if (strcmp(argv[1], "hooks") == 0) cmd_hooks();
    else { fprintf(stderr, "unknown: %s\n", argv[1]); return 1; }

    return 0;
}
