#define _GNU_SOURCE
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>

#define BPF_ATTR_SZ(field) \
    (unsigned int)(offsetof(union bpf_attr, field) + sizeof(((union bpf_attr *)0)->field))

static int bpf_call(int cmd, union bpf_attr *a, unsigned int sz)
{
    return (int)syscall(__NR_bpf, cmd, a, sz);
}

static int link_fd_by_id(uint32_t id)
{
    union bpf_attr a = {}; a.link_id = id;
    return bpf_call(BPF_LINK_GET_FD_BY_ID, &a, BPF_ATTR_SZ(link_id));
}

static int prog_fd_by_id(uint32_t id)
{
    union bpf_attr a = {}; a.prog_id = id;
    return bpf_call(BPF_PROG_GET_FD_BY_ID, &a, BPF_ATTR_SZ(prog_id));
}

static const char *link_type_name(uint32_t t)
{
    switch (t) {
    case BPF_LINK_TYPE_RAW_TRACEPOINT:  return "raw_tracepoint";
    case BPF_LINK_TYPE_TRACING:         return "tracing(kprobe/tp/lsm)";
    case BPF_LINK_TYPE_CGROUP:          return "cgroup";
    case BPF_LINK_TYPE_ITER:            return "iter";
    case BPF_LINK_TYPE_NETNS:           return "netns";
    case BPF_LINK_TYPE_XDP:             return "xdp";
    case BPF_LINK_TYPE_PERF_EVENT:      return "perf_event";
    case BPF_LINK_TYPE_KPROBE_MULTI:    return "kprobe_multi";
    case BPF_LINK_TYPE_UPROBE_MULTI:    return "uprobe_multi";
    default:                            return "unknown";
    }
}

static const char *prog_type_name(uint32_t t)
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

static int is_monitoring_type(uint32_t pt)
{
    switch (pt) {
    case BPF_PROG_TYPE_KPROBE:
    case BPF_PROG_TYPE_TRACEPOINT:
    case BPF_PROG_TYPE_RAW_TRACEPOINT:
    case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE:
    case BPF_PROG_TYPE_PERF_EVENT:
    case BPF_PROG_TYPE_LSM:
    case BPF_PROG_TYPE_TRACING:
        return 1;
    default:
        return 0;
    }
}

static int get_link_info(int fd, struct bpf_link_info *info)
{
    union bpf_attr a = {};
    a.info.bpf_fd   = (uint32_t)fd;
    a.info.info_len = sizeof(*info);
    a.info.info     = (uint64_t)(uintptr_t)info;
    return bpf_call(BPF_OBJ_GET_INFO_BY_FD, &a, BPF_ATTR_SZ(info));
}

static int get_prog_type(uint32_t prog_id)
{
    int fd = prog_fd_by_id(prog_id);
    if (fd < 0) return -1;

    struct bpf_prog_info info = {};
    union bpf_attr a = {};
    a.info.bpf_fd   = (uint32_t)fd;
    a.info.info_len = sizeof(info);
    a.info.info     = (uint64_t)(uintptr_t)&info;
    int r = bpf_call(BPF_OBJ_GET_INFO_BY_FD, &a, BPF_ATTR_SZ(info));
    close(fd);
    if (r < 0) return -1;
    return (int)info.type;
}

static int do_detach(int fd)
{
    union bpf_attr a = {};
    a.link_detach.link_fd = (uint32_t)fd;
    return bpf_call(BPF_LINK_DETACH, &a, BPF_ATTR_SZ(link_detach));
}

int main(int argc, char *argv[])
{
    int dry_run    = 0;
    int monitoring_only = 1;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <detach-all|detach-any|detach>\n", argv[0]);
        return 1;
    }

    int do_detach_flag = 0;
    if (strcmp(argv[1], "detach-all") == 0) {
        do_detach_flag = 1; monitoring_only = 1;
    } else if (strcmp(argv[1], "detach-any") == 0) {
        do_detach_flag = 1; monitoring_only = 0;
    } else if (strcmp(argv[1], "detach") == 0 && argc >= 3) {
        uint32_t id = (uint32_t)atoi(argv[2]);
        int fd = link_fd_by_id(id);
        if (fd < 0) { perror("BPF_LINK_GET_FD_BY_ID"); return 1; }
        if (do_detach(fd) == 0) printf("[+] link %u detached\n", id);
        else perror("BPF_LINK_DETACH");
        close(fd);
        return 0;
    }

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--dry-run") == 0) dry_run = 1;
        if (strcmp(argv[i], "--all") == 0) monitoring_only = 0;
    }

    uint32_t id = 0;
    int total = 0, detached = 0, skipped = 0;

    for (;;) {
        union bpf_attr nx = {}; nx.start_id = id;
        int r = bpf_call(BPF_LINK_GET_NEXT_ID, &nx, BPF_ATTR_SZ(next_id));
        if (r < 0) { if (errno == ENOENT) break; perror("GET_NEXT_ID"); break; }
        id = nx.next_id;

        int fd = link_fd_by_id(id);
        if (fd < 0) continue;

        struct bpf_link_info linfo = {};
        if (get_link_info(fd, &linfo) < 0) { close(fd); continue; }

        int prog_type = get_prog_type(linfo.prog_id);

        total++;
        printf("  link_id=%-5u  prog_id=%-5u  link_type=%-22s  prog_type=%s\n",
               id, linfo.prog_id,
               link_type_name(linfo.type),
               prog_type >= 0 ? prog_type_name((uint32_t)prog_type) : "?");

        if (do_detach_flag) {
            if (monitoring_only && prog_type >= 0 && !is_monitoring_type((uint32_t)prog_type)) {
                printf("    [skip] not a monitoring prog type\n");
                skipped++;
            } else if (dry_run) {
                printf("    [dry-run] would detach link %u\n", id);
            } else {
                if (do_detach(fd) == 0) {
                    printf("    [+] detached\n"); detached++;
                } else {
                    printf("    [!] detach failed: %s\n", strerror(errno));
                }
            }
        }
        close(fd);
    }

    printf("[*] %d links total", total);
    if (do_detach_flag) printf(", %d detached, %d skipped", detached, skipped);
    printf("\n");
    return 0;
}
