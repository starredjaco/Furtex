#define _GNU_SOURCE
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

#define BPF_ATTR_SZ(f) \
    (offsetof(union bpf_attr, f) + sizeof(((union bpf_attr *)0)->f))

#define MAX_MAP_IDS 64

static int bpf_call(int cmd, union bpf_attr *a, unsigned sz)
{
    return (int)syscall(__NR_bpf, cmd, a, sz);
}

static const char *prog_type_str(uint32_t t)
{
    switch (t) {
    case BPF_PROG_TYPE_SOCKET_FILTER:      return "socket_filter";
    case BPF_PROG_TYPE_KPROBE:             return "kprobe";
    case BPF_PROG_TYPE_SCHED_CLS:          return "sched_cls";
    case BPF_PROG_TYPE_TRACEPOINT:         return "tracepoint";
    case BPF_PROG_TYPE_XDP:                return "xdp";
    case BPF_PROG_TYPE_PERF_EVENT:         return "perf_event";
    case BPF_PROG_TYPE_CGROUP_SKB:         return "cgroup_skb";
    case BPF_PROG_TYPE_CGROUP_SOCK:        return "cgroup_sock";
    case BPF_PROG_TYPE_RAW_TRACEPOINT:     return "raw_tracepoint";
    case BPF_PROG_TYPE_LSM:                return "lsm";
    case BPF_PROG_TYPE_TRACING:            return "tracing";
    case BPF_PROG_TYPE_STRUCT_OPS:         return "struct_ops";
    default:                               return "other";
    }
}

static void print_prog(const struct bpf_prog_info *info, int show_maps)
{
    char tag[17] = {};
    for (int i = 0; i < 8; i++) sprintf(tag + i*2, "%02x", info->tag[i]);

    printf("id=%-5u  type=%-20s  name=%-20s  tag=%s\n",
           info->id, prog_type_str(info->type),
           info->name[0] ? info->name : "(unnamed)", tag);
    printf("         jited=%uB  xlated=%uB  load_time=%llu\n",
           info->jited_prog_len, info->xlated_prog_len,
           (unsigned long long)info->load_time);

    if (show_maps && info->nr_map_ids > 0) {
        printf("         maps=[");
        uint32_t *ids = (uint32_t *)(uintptr_t)info->map_ids;
        for (uint32_t i = 0; i < info->nr_map_ids; i++)
            printf("%u%s", ids[i], i+1 < info->nr_map_ids ? "," : "");
        printf("]\n");
    }
}

int main(int argc, char *argv[])
{
    int show_maps = 0, lsm_only = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--maps")     == 0) show_maps = 1;
        if (strcmp(argv[i], "--lsm-only") == 0) lsm_only  = 1;
    }

    uint32_t id = 0;
    int total = 0;

    for (;;) {

        union bpf_attr na = {}; na.start_id = id;
        if (bpf_call(BPF_PROG_GET_NEXT_ID, &na, BPF_ATTR_SZ(start_id)) < 0) break;
        id = na.next_id;

        union bpf_attr fa = {}; fa.prog_id = id;
        int fd = bpf_call(BPF_PROG_GET_FD_BY_ID, &fa, BPF_ATTR_SZ(prog_id));
        if (fd < 0) continue;

        uint32_t map_ids[MAX_MAP_IDS] = {};
        struct bpf_prog_info info = {};
        info.nr_map_ids = MAX_MAP_IDS;
        info.map_ids    = (uint64_t)(uintptr_t)map_ids;

        union bpf_attr ia = {};
        ia.info.bpf_fd   = (uint32_t)fd;
        ia.info.info_len = sizeof(info);
        ia.info.info     = (uint64_t)(uintptr_t)&info;

        if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &ia, BPF_ATTR_SZ(info)) == 0) {
            if (!lsm_only || info.type == BPF_PROG_TYPE_LSM) {
                print_prog(&info, show_maps);
                total++;
            }
        }
        close(fd);
    }
    printf("\n[*] %d programs\n", total);
    return 0;
}
