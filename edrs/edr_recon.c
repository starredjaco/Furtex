#define _GNU_SOURCE
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>

#ifndef BPF_LINK_TYPE_KPROBE_MULTI
#define BPF_LINK_TYPE_KPROBE_MULTI 8
#endif
#ifndef BPF_LINK_TYPE_UPROBE_MULTI
#define BPF_LINK_TYPE_UPROBE_MULTI 12
#endif

#define BPF_ATTR_SZ(field) \
    (unsigned int)(offsetof(union bpf_attr, field) + sizeof(((union bpf_attr *)0)->field))

static int bpf_call(int cmd, union bpf_attr *a, unsigned int sz)
{
    return (int)syscall(__NR_bpf, cmd, a, sz);
}

struct edr_profile {
    const char *vendor;
    const char *procs[8];
    const char *modules[6];
    const char *files[10];
    const char *devs[4];
    const char *bpf_pats[6];
    int score;
};

static struct edr_profile edrs[] = {
    {
        .vendor = "CrowdStrike Falcon",
        .procs   = { "falcon-sensor", "falcond", "cs-agent", NULL },
        .modules = { "falcon_lsm_sensor", "falcon_nf_netcontain", "falcon_kal", NULL },
        .files   = { "/opt/CrowdStrike/falcond", "/opt/CrowdStrike/falcon-sensor",
                     "/var/run/falcon-agent.socket", "/opt/CrowdStrike/", NULL },
        .devs    = { "falcon-query0", "csagent", NULL },
        .bpf_pats = { "falcon", "crowdstrike", "cs_", NULL },
    },
    {
        .vendor = "Palo Alto Cortex XDR (Traps)",
        .procs   = { "traps_pmd", "traps", "cytool", "cyserver", NULL },
        .modules = { "traps", NULL },
        .files   = { "/opt/traps/bin/cytool", "/opt/traps/bin/traps_pmd",
                     "/opt/traps/running_mode", "/opt/traps/", NULL },
        .devs    = { "traps", NULL },
        .bpf_pats = { "traps", "cortex", NULL },
    },
    {
        .vendor = "Trend Micro (DS Agent / Apex One)",
        .procs   = { "ds_agent", "dsa_query", "cgtool", "ds_am", NULL },
        .modules = { "tmhook", "bmhook", "dsa_filter", "dsa_filter_hook", NULL },
        .files   = { "/opt/ds_agent/ds_agent", "/opt/ds_agent/",
                     "/opt/TrendMicro/SProtectLinux/", NULL },
        .devs    = { NULL },
        .bpf_pats = { "tmhook", "bmhook", "trendmicro", NULL },
    },
    {
        .vendor = "SentinelOne",
        .procs   = { "sentinelctl", "sentinel-agent", "s1agent", "sentineld", NULL },
        .modules = { "s1_sensor", "sentinel", NULL },
        .files   = { "/opt/sentinelone/bin/sentinelctl", "/opt/sentinelone/bin/sentineld",
                     "/opt/sentinelone/", NULL },
        .devs    = { "s1_sensor", NULL },
        .bpf_pats = { "s1_", "sentinel", NULL },
    },
    {
        .vendor = "VMware Carbon Black",
        .procs   = { "cbsensor", "cbdaemon", "cbagentd", "cbosxsensor", NULL },
        .modules = { "cbr_sensord", "carbonblack", NULL },
        .files   = { "/usr/share/cb/cbdaemon", "/var/lib/cb/",
                     "/opt/carbonblack/", NULL },
        .devs    = { NULL },
        .bpf_pats = { "carbonblack", "cbr_", NULL },
    },
    {
        .vendor = "Microsoft Defender (MDATP)",
        .procs   = { "mdatp", "wdavdaemon", "mdatp_audisp_plugin", NULL },
        .modules = { NULL },
        .files   = { "/opt/microsoft/mdatp/sbin/wdavdaemon",
                     "/var/opt/microsoft/mdatp/",
                     "/opt/microsoft/mdatp/", NULL },
        .devs    = { NULL },
        .bpf_pats = { "mdatp", "defender", "microsoft", NULL },
    },
    {
        .vendor = "Sophos",
        .procs   = { "sophoslinuxsensor", "sophos-spl", "ssm-service", NULL },
        .modules = { NULL },
        .files   = { "/opt/sophos-spl/bin/", "/opt/SophosLinux/",
                     "/opt/sophos-spl/", NULL },
        .devs    = { NULL },
        .bpf_pats = { "sophos", NULL },
    },
    {
        .vendor = "Elastic Endpoint",
        .procs   = { "elastic-endpoint", "elastic-agent", "fleet-server", NULL },
        .modules = { NULL },
        .files   = { "/opt/Elastic/Endpoint/elastic-endpoint",
                     "/opt/Elastic/Agent/elastic-agent",
                     "/opt/Elastic/", NULL },
        .devs    = { NULL },
        .bpf_pats = { "elastic", "endgame", NULL },
    },
    {
        .vendor = "Kaspersky (KESL)",
        .procs   = { "kesl", "kavstart", "klnagent", "kav", NULL },
        .modules = { "gsch", "klhk", "klrg", "klif", NULL },
        .files   = { "/opt/kaspersky/kesl/bin/kesl",
                     "/var/opt/kaspersky/",
                     "/opt/kaspersky/", NULL },
        .devs    = { "klbg", "kl_vtd", "kl_protect", NULL },
        .bpf_pats = { "kaspersky", "kesl", NULL },
    },
    {
        .vendor = "Wazuh / OSSEC",
        .procs   = { "wazuh-agent", "wazuh-modulesd", "wazuh-syscheckd",
                     "wazuh-logcollectord", "ossec-agentd", NULL },
        .modules = { NULL },
        .files   = { "/var/ossec/bin/wazuh-agent", "/etc/wazuh-agent/",
                     "/var/ossec/", NULL },
        .devs    = { NULL },
        .bpf_pats = { "wazuh", "ossec", NULL },
    },
    {
        .vendor = "Falco",
        .procs   = { "falco", "falco-bpf", NULL },
        .modules = { "scap", "falco_kmod", NULL },
        .files   = { "/usr/bin/falco", "/etc/falco/falco.yaml",
                     "/etc/falco/", NULL },
        .devs    = { "scap0", "falco", NULL },
        .bpf_pats = { "falco", "scap", "sysdig", NULL },
    },
    {
        .vendor = "Tetragon / Cilium",
        .procs   = { "tetragon", "tetra", "cilium-agent", NULL },
        .modules = { NULL },
        .files   = { "/usr/local/bin/tetragon", "/etc/tetragon/",
                     "/usr/local/bin/tetra", NULL },
        .devs    = { NULL },
        .bpf_pats = { "tg_", "tetragon", "cilium", NULL },
    },
    { .vendor = NULL },
};

static void score_add(const char *vendor, int delta)
{
    for (int i = 0; edrs[i].vendor; i++) {
        if (strcmp(edrs[i].vendor, vendor) == 0) {
            edrs[i].score += delta;
            return;
        }
    }
}

static const char *prog_type_str(uint32_t t)
{
    switch (t) {
    case BPF_PROG_TYPE_KPROBE:               return "kprobe";
    case BPF_PROG_TYPE_TRACEPOINT:           return "tracepoint";
    case BPF_PROG_TYPE_RAW_TRACEPOINT:       return "raw_tracepoint";
    case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE: return "raw_tp_writable";
    case BPF_PROG_TYPE_PERF_EVENT:           return "perf_event";
    case BPF_PROG_TYPE_LSM:                  return "lsm";
    case BPF_PROG_TYPE_TRACING:              return "tracing(fentry/fexit)";
    case BPF_PROG_TYPE_SOCKET_FILTER:        return "socket_filter";
    case BPF_PROG_TYPE_CGROUP_SKB:           return "cgroup_skb";
    case BPF_PROG_TYPE_XDP:                  return "xdp";
    default:                                 return "other";
    }
}

static int is_monitoring_prog(uint32_t t)
{
    return t == BPF_PROG_TYPE_KPROBE
        || t == BPF_PROG_TYPE_TRACEPOINT
        || t == BPF_PROG_TYPE_RAW_TRACEPOINT
        || t == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE
        || t == BPF_PROG_TYPE_PERF_EVENT
        || t == BPF_PROG_TYPE_LSM
        || t == BPF_PROG_TYPE_TRACING;
}

static const char *match_edr_bpf(const char *name)
{
    for (int i = 0; edrs[i].vendor; i++) {
        for (int j = 0; edrs[i].bpf_pats[j]; j++) {
            if (strcasestr(name, edrs[i].bpf_pats[j]))
                return edrs[i].vendor;
        }
    }
    return NULL;
}

static const char *match_edr_module(const char *name)
{
    for (int i = 0; edrs[i].vendor; i++) {
        for (int j = 0; edrs[i].modules[j]; j++) {
            if (strcasestr(name, edrs[i].modules[j]))
                return edrs[i].vendor;
        }
    }
    return NULL;
}

static void recon_processes(void)
{
    printf("\n=== Processes ===\n");

    DIR *proc = opendir("/proc");
    if (!proc) { perror("/proc"); return; }

    int found = 0;
    struct dirent *de;
    while ((de = readdir(proc))) {
        if (!de->d_name[0] || de->d_name[0] < '1' || de->d_name[0] > '9') continue;

        char path[64];
        snprintf(path, sizeof(path), "/proc/%.20s/comm", de->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;

        char comm[64] = {};
        if (!fgets(comm, sizeof(comm), f)) { fclose(f); continue; }
        fclose(f);

        size_t len = strlen(comm);
        if (len > 0 && comm[len-1] == '\n') comm[len-1] = '\0';

        for (int i = 0; edrs[i].vendor; i++) {
            for (int j = 0; edrs[i].procs[j]; j++) {
                if (strcasestr(comm, edrs[i].procs[j])) {
                    printf("  [!] pid=%-6s comm=%-24s vendor=%s\n",
                           de->d_name, comm, edrs[i].vendor);
                    score_add(edrs[i].vendor, 10);
                    found++;
                    goto next_pid;
                }
            }
        }
    next_pid:;
    }
    closedir(proc);

    if (!found) printf("  [*] no known EDR processes found\n");
}

static void recon_artifacts(void)
{
    printf("\n=== Filesystem Artifacts ===\n");
    int found = 0;

    for (int i = 0; edrs[i].vendor; i++) {
        for (int j = 0; edrs[i].files[j]; j++) {
            struct stat st;
            if (stat(edrs[i].files[j], &st) == 0) {
                printf("  [!] %-40s  vendor=%s\n", edrs[i].files[j], edrs[i].vendor);
                score_add(edrs[i].vendor, 5);
                found++;
            }
        }
    }

    printf("\n=== Device Files ===\n");
    for (int i = 0; edrs[i].vendor; i++) {
        for (int j = 0; edrs[i].devs[j]; j++) {
            char devpath[64];
            snprintf(devpath, sizeof(devpath), "/dev/%.50s", edrs[i].devs[j]);
            struct stat st;
            if (stat(devpath, &st) == 0) {
                printf("  [!] %-32s  vendor=%s\n", devpath, edrs[i].vendor);
                score_add(edrs[i].vendor, 8);
                found++;
            }
        }
    }

    if (!found) printf("  [*] no known EDR artifacts found\n");
}

static void recon_modules(void)
{
    printf("\n=== Kernel Modules ===\n");

    FILE *f = fopen("/proc/modules", "r");
    if (!f) { perror("/proc/modules"); return; }

    char line[512], name[256], state[32];
    int refcnt, found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%255s %*u %d %*s %31s", name, &refcnt, state) < 3) continue;
        const char *vendor = match_edr_module(name);
        if (vendor) {
            printf("  [!] %-32s refcnt=%-4d state=%-12s vendor=%s\n",
                   name, refcnt, state, vendor);
            score_add(vendor, 10);
            found++;
        }
    }
    fclose(f);
    if (!found) printf("  [*] no known EDR modules loaded\n");
}

static void recon_available_funcs(void)
{
    printf("\n=== Available Filter Functions (EDR module symbols) ===\n");

    static const char *paths[] = {
        "/sys/kernel/tracing/available_filter_functions",
        "/sys/kernel/debug/tracing/available_filter_functions",
        NULL
    };

    FILE *f = NULL;
    for (int i = 0; paths[i]; i++) {
        f = fopen(paths[i], "r");
        if (f) { printf("  [source: %s]\n", paths[i]); break; }
    }
    if (!f) { printf("  [!] available_filter_functions not accessible (need root)\n"); return; }

    char line[256];
    int vendor_hits[32] = {};
    int total_hits = 0;

    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[--len] = '\0';

        char *ob = strrchr(line, '[');
        char *cb = strrchr(line, ']');
        if (!ob || !cb || cb <= ob + 1) continue;

        char modname[64];
        size_t mlen = (size_t)(cb - ob - 1);
        if (mlen >= sizeof(modname)) mlen = sizeof(modname) - 1;
        memcpy(modname, ob + 1, mlen);
        modname[mlen] = '\0';

        for (int i = 0; edrs[i].vendor; i++) {
            int matched = 0;
            for (int j = 0; edrs[i].modules[j] && !matched; j++) {
                if (strcasecmp(modname, edrs[i].modules[j]) == 0) matched = 1;
            }
            if (!matched) continue;

            if (vendor_hits[i] < 5)
                printf("  [!] %-56s [%s]  vendor=%s\n", line, modname, edrs[i].vendor);
            else if (vendor_hits[i] == 5)
                printf("  [!] ... (more %s symbols from [%s])\n", edrs[i].vendor, modname);

            vendor_hits[i]++;
            total_hits++;
            score_add(edrs[i].vendor, 1);
            break;
        }
    }
    fclose(f);

    if (total_hits == 0) {
        printf("  [*] no known EDR module symbols found\n");
        printf("  [*] note: built-in EDRs (BPF-only) won't appear here - use 'progs' section\n");
    } else {
        printf("\n  summary:\n");
        for (int i = 0; edrs[i].vendor; i++) {
            if (vendor_hits[i] > 0)
                printf("    %-44s %d exported symbols\n", edrs[i].vendor, vendor_hits[i]);
        }
    }
}

static void recon_bpf_progs(void)
{
    printf("\n=== BPF Programs ===\n");
    printf("  %-6s %-36s %-22s %s\n", "id", "name", "type", "jited_len");
    printf("  %s\n", "----------------------------------------------------------------------");

    uint32_t id = 0;
    int total = 0, monitoring = 0, edr_match = 0;
    for (;;) {
        union bpf_attr nx = {}; nx.start_id = id;
        if (bpf_call(BPF_PROG_GET_NEXT_ID, &nx, BPF_ATTR_SZ(next_id)) < 0) break;
        id = nx.next_id;

        union bpf_attr gfd = {}; gfd.prog_id = id;
        int fd = bpf_call(BPF_PROG_GET_FD_BY_ID, &gfd, BPF_ATTR_SZ(prog_id));
        if (fd < 0) continue;

        struct bpf_prog_info info = {};
        union bpf_attr gi = {};
        gi.info.bpf_fd   = (uint32_t)fd;
        gi.info.info_len = sizeof(info);
        gi.info.info     = (uint64_t)(uintptr_t)&info;
        bpf_call(BPF_OBJ_GET_INFO_BY_FD, &gi, BPF_ATTR_SZ(info));
        close(fd);

        char name[BPF_OBJ_NAME_LEN + 1];
        memcpy(name, info.name, BPF_OBJ_NAME_LEN);
        name[BPF_OBJ_NAME_LEN] = '\0';

        int mon = is_monitoring_prog(info.type);
        const char *vendor = match_edr_bpf(name);
        total++;
        if (mon) monitoring++;
        if (vendor) {
            edr_match++;
            score_add(vendor, 3);
        }

        printf("  %-6u %-36s %-22s jit=%-8u%s%s\n",
               id, name, prog_type_str(info.type), info.jited_prog_len,
               mon ? "  [monitoring]" : "",
               vendor ? "  [!EDR!]" : "");
    }
    printf("  total=%d  monitoring_type=%d  edr_pattern=%d\n",
           total, monitoring, edr_match);
}

static void recon_bpf_links(void)
{
    printf("\n=== BPF Links ===\n");
    printf("  %-6s %-8s %-26s\n", "link_id", "prog_id", "link_type");
    printf("  %s\n", "--------------------------------------");

    uint32_t id = 0;
    int total = 0;
    for (;;) {
        union bpf_attr nx = {}; nx.start_id = id;
        if (bpf_call(BPF_LINK_GET_NEXT_ID, &nx, BPF_ATTR_SZ(next_id)) < 0) break;
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
        close(fd);

        static const char *ltype[] = {
            [BPF_LINK_TYPE_RAW_TRACEPOINT] = "raw_tracepoint",
            [BPF_LINK_TYPE_TRACING]        = "tracing(kp/tp/lsm/fentry)",
            [BPF_LINK_TYPE_CGROUP]         = "cgroup",
            [BPF_LINK_TYPE_ITER]           = "iter",
            [BPF_LINK_TYPE_NETNS]          = "netns",
            [BPF_LINK_TYPE_XDP]            = "xdp",
            [BPF_LINK_TYPE_PERF_EVENT]     = "perf_event",
            [BPF_LINK_TYPE_KPROBE_MULTI]   = "kprobe_multi",
            [BPF_LINK_TYPE_UPROBE_MULTI]   = "uprobe_multi",
        };
        const char *lt = (linfo.type < 16 && ltype[linfo.type]) ? ltype[linfo.type] : "?";
        printf("  %-6u %-8u %s\n", id, linfo.prog_id, lt);
        total++;
    }
    printf("  total=%d\n", total);
}

static void recon_bpf_maps(void)
{
    printf("\n=== BPF Maps (monitoring-relevant) ===\n");
    printf("  %-6s %-36s %-20s %s\n", "id", "name", "type", "max_entries");
    printf("  %s\n", "----------------------------------------------------------------------");

    uint32_t id = 0;
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

        char name[BPF_OBJ_NAME_LEN + 1];
        memcpy(name, info.name, BPF_OBJ_NAME_LEN);
        name[BPF_OBJ_NAME_LEN] = '\0';
        close(fd);

        int interesting = (info.type == BPF_MAP_TYPE_PERF_EVENT_ARRAY
                        || info.type == BPF_MAP_TYPE_RINGBUF
                        || info.type == BPF_MAP_TYPE_HASH
                        || info.type == BPF_MAP_TYPE_PERCPU_ARRAY)
                       && info.max_entries >= 16;
        if (!interesting) continue;

        static const char *mt[] = {
            [BPF_MAP_TYPE_HASH]             = "hash",
            [BPF_MAP_TYPE_ARRAY]            = "array",
            [BPF_MAP_TYPE_PERF_EVENT_ARRAY] = "perf_event_array",
            [BPF_MAP_TYPE_PERCPU_HASH]      = "percpu_hash",
            [BPF_MAP_TYPE_PERCPU_ARRAY]     = "percpu_array",
            [BPF_MAP_TYPE_RINGBUF]          = "ringbuf",
            [BPF_MAP_TYPE_LRU_HASH]         = "lru_hash",
        };
        const char *ts = (info.type < 32 && mt[info.type]) ? mt[info.type] : "other";
        const char *vendor = match_edr_bpf(name);
        if (vendor) score_add(vendor, 2);
        printf("  %-6u %-36s %-20s %u%s\n",
               id, name, ts, info.max_entries,
               vendor ? "  [!EDR!]" : "");
    }
}

static void recon_kprobes(void)
{
    printf("\n=== Active kprobes (tracefs) ===\n");

    static const char *paths[] = {
        "/sys/kernel/tracing/kprobe_events",
        "/sys/kernel/debug/tracing/kprobe_events",
        NULL
    };

    FILE *f = NULL;
    for (int i = 0; paths[i]; i++) {
        f = fopen(paths[i], "r");
        if (f) { printf("  [source: %s]\n", paths[i]); break; }
    }
    if (!f) { printf("  [!] tracefs not accessible\n"); return; }

    char line[512];
    int total = 0, edr_count = 0;
    while (fgets(line, sizeof(line), f)) {
        const char *vendor = NULL;
        for (int i = 0; edrs[i].vendor && !vendor; i++) {
            for (int j = 0; edrs[i].bpf_pats[j] && !vendor; j++) {
                if (strcasestr(line, edrs[i].bpf_pats[j])) {
                    vendor = edrs[i].vendor;
                    score_add(vendor, 2);
                }
            }
            for (int j = 0; edrs[i].modules[j] && !vendor; j++) {
                if (strcasestr(line, edrs[i].modules[j])) {
                    vendor = edrs[i].vendor;
                    score_add(vendor, 2);
                }
            }
        }
        printf("  %s%s", vendor ? "[!EDR!] " : "", line);
        total++;
        if (vendor) edr_count++;
    }
    fclose(f);
    printf("  total=%d  edr_pattern=%d\n", total, edr_count);
}

static void recon_ftrace(void)
{
    printf("\n=== ftrace function hooks (enabled_functions) ===\n");

    static const char *paths[] = {
        "/sys/kernel/tracing/enabled_functions",
        "/sys/kernel/debug/tracing/enabled_functions",
        NULL
    };

    FILE *f = NULL;
    for (int i = 0; paths[i]; i++) {
        f = fopen(paths[i], "r");
        if (f) { printf("  [source: %s]\n", paths[i]); break; }
    }
    if (!f) {
        printf("  [!] enabled_functions not accessible\n"
               "  [*] LKM ftrace hooks (register_ftrace_function) appear here\n"
               "      and cannot be removed via tracefs - must unload the module\n");
        return;
    }

    char line[256];
    int total = 0;
    while (fgets(line, sizeof(line), f)) {
        printf("  %s", line);
        total++;
    }
    fclose(f);
    printf("  total=%d\n", total);
}

static void recon_lsm(void)
{
    printf("\n=== Active LSM Stack ===\n");

    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    if (f) {
        char buf[256] = {};
        if (fgets(buf, sizeof(buf), f)) printf("  lsm stack: %s\n", buf);
        fclose(f);
    } else {
        printf("  [!] /sys/kernel/security/lsm not readable\n");
    }
    printf("  [*] BPF LSM progs visible in 'BPF Programs' section above\n"
           "      to remove: bpf_detach_all detach-all\n");
}

static void recon_perf_bpf(void)
{
    printf("\n=== Perf-attached BPF programs (not via BPF_LINK) ===\n");
    printf("  [scanning /proc/*/fdinfo for prog_id entries...]\n");

    DIR *proc = opendir("/proc");
    if (!proc) { perror("/proc"); return; }

    struct dirent *de;
    int total = 0;
    while ((de = readdir(proc))) {
        if (!de->d_name[0] || de->d_name[0] < '1' || de->d_name[0] > '9') continue;

        char fdinfo_path[320];
        snprintf(fdinfo_path, sizeof(fdinfo_path), "/proc/%.255s/fdinfo", de->d_name);
        DIR *fdinfo = opendir(fdinfo_path);
        if (!fdinfo) continue;

        struct dirent *fde;
        while ((fde = readdir(fdinfo))) {
            if (fde->d_name[0] == '.') continue;
            char ep[640];
            snprintf(ep, sizeof(ep), "%.*s/%.255s", 320, fdinfo_path, fde->d_name);
            FILE *f = fopen(ep, "r");
            if (!f) continue;

            char line[128];
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "prog_id:", 8) == 0) {
                    printf("  pid=%-6s fd=%-6s %s", de->d_name, fde->d_name, line);
                    total++;
                    break;
                }
            }
            fclose(f);
        }
        closedir(fdinfo);
    }
    closedir(proc);

    if (total == 0)
        printf("  [*] none found (all BPF progs use modern BPF_LINK attachment)\n");
    else
        printf("  [!] %d perf-attached BPF progs - bpf_link_detach cannot remove these\n"
               "      to remove: kill owner process or use cgroup_freeze + kmod_unload\n",
               total);
}

static void print_summary(void)
{
    printf("\n=== Detection Summary ===\n");
    printf("  %-40s %s\n", "vendor", "confidence");
    printf("  %s\n", "--------------------------------------------------------------");

    int any = 0;
    for (int i = 0; edrs[i].vendor; i++) {
        if (edrs[i].score == 0) continue;
        const char *level = edrs[i].score >= 20 ? "HIGH"
                          : edrs[i].score >= 10 ? "MEDIUM"
                          : "LOW";
        printf("  [!] %-40s score=%-4d  %s\n", edrs[i].vendor, edrs[i].score, level);
        any++;
    }

    if (!any) printf("  [*] no EDR indicators found\n");

    printf("\n=== Remediation map ===\n");
    printf("  kprobes (tracefs)        -> ftrace_enum clear-kprobes\n");
    printf("  BPF links (any type)     -> bpf_detach_all\n");
    printf("  BPF maps (event buffers) -> bpf_map_wipe run\n");
    printf("  LKM ftrace hooks         -> lkm_unload unload <module> [--force]\n");
    printf("  perf-attached BPF progs  -> kill owner process or lkm_unload\n");
    printf("  auditd                   -> audit_kill disable\n");
    printf("  EDR process              -> cgroup_freeze freeze <pid>\n");
    printf("  EDR kernel module        -> lkm_unload unload <module>\n");
}

int main(int argc, char *argv[])
{
    int do_procs   = 1, do_arts   = 1, do_avail  = 1;
    int do_mods    = 1, do_progs  = 1, do_links  = 1, do_maps  = 1;
    int do_kprobe  = 1, do_ftrace = 1, do_lsm    = 1, do_perf  = 1;

    if (argc >= 2 && strcmp(argv[1], "--help") != 0 && strcmp(argv[1], "help") != 0) {
        do_procs = do_arts = do_avail = do_mods = do_progs = do_links = 0;
        do_maps = do_kprobe = do_ftrace = do_lsm = do_perf = 0;
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "procs")   == 0) do_procs  = 1;
            if (strcmp(argv[i], "arts")    == 0) do_arts   = 1;
            if (strcmp(argv[i], "avail")   == 0) do_avail  = 1;
            if (strcmp(argv[i], "mods")    == 0) do_mods   = 1;
            if (strcmp(argv[i], "progs")   == 0) do_progs  = 1;
            if (strcmp(argv[i], "links")   == 0) do_links  = 1;
            if (strcmp(argv[i], "maps")    == 0) do_maps   = 1;
            if (strcmp(argv[i], "kprobes") == 0) do_kprobe = 1;
            if (strcmp(argv[i], "ftrace")  == 0) do_ftrace = 1;
            if (strcmp(argv[i], "lsm")     == 0) do_lsm    = 1;
            if (strcmp(argv[i], "perf")    == 0) do_perf   = 1;
        }
    }

    if (argc >= 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "help") == 0)) {
        fprintf(stderr, "usage: %s <--help|help>\n", argv[0]);
        return 0;
    }

    printf("[*] EDR recon - 12 vendors, 8 detection methods\n\n");

    if (do_procs)  recon_processes();
    if (do_arts)   recon_artifacts();
    if (do_mods)   recon_modules();
    if (do_avail)  recon_available_funcs();
    if (do_progs)  recon_bpf_progs();
    if (do_links)  recon_bpf_links();
    if (do_maps)   recon_bpf_maps();
    if (do_kprobe) recon_kprobes();
    if (do_ftrace) recon_ftrace();
    if (do_lsm)    recon_lsm();
    if (do_perf)   recon_perf_bpf();

    print_summary();
    return 0;
}
