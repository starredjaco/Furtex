#define _GNU_SOURCE
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define BPF_ATTR_SZ(f) \
    (offsetof(union bpf_attr, f) + sizeof(((union bpf_attr *)0)->f))

static int bpf_call(int cmd, union bpf_attr *a, unsigned sz)
{
    return (int)syscall(__NR_bpf, cmd, a, sz);
}

static const char *map_type_str(uint32_t t)
{
    switch (t) {
    case BPF_MAP_TYPE_HASH:          return "hash";
    case BPF_MAP_TYPE_ARRAY:         return "array";
    case BPF_MAP_TYPE_PROG_ARRAY:    return "prog_array";
    case BPF_MAP_TYPE_PERF_EVENT_ARRAY: return "perf_event_array";
    case BPF_MAP_TYPE_HASH_OF_MAPS: return "hash_of_maps";
    case BPF_MAP_TYPE_LRU_HASH:     return "lru_hash";
    case BPF_MAP_TYPE_RINGBUF:      return "ringbuf";
    case BPF_MAP_TYPE_SOCKHASH:     return "sockhash";
    case BPF_MAP_TYPE_SOCKMAP:      return "sockmap";
    default:                         return "other";
    }
}

static int freeze_map_by_fd(int map_fd, uint32_t id, int verbose)
{
    union bpf_attr fa = {}; fa.map_fd = (uint32_t)map_fd;
    if (bpf_call(BPF_MAP_FREEZE, &fa, BPF_ATTR_SZ(map_fd)) < 0) {
        if (verbose)
            fprintf(stderr, "[-] map id=%-5u  freeze failed: %s\n",
                    id, strerror(errno));
        return -1;
    }
    if (verbose)
        printf("[+] map id=%-5u  frozen (writes now return -EPERM)\n", id);
    return 0;
}

static int freeze_one(uint32_t map_id)
{
    union bpf_attr fa = {}; fa.map_id = map_id;
    int fd = bpf_call(BPF_MAP_GET_FD_BY_ID, &fa, BPF_ATTR_SZ(map_id));
    if (fd < 0) { perror("BPF_MAP_GET_FD_BY_ID"); return -1; }

    struct bpf_map_info info = {};
    union bpf_attr ia = {};
    ia.info.bpf_fd   = (uint32_t)fd;
    ia.info.info_len = sizeof(info);
    ia.info.info     = (uint64_t)(uintptr_t)&info;
    if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &ia, BPF_ATTR_SZ(info)) == 0)
        printf("[*] map id=%-5u  type=%-20s  name=%s\n",
               info.id, map_type_str(info.type),
               info.name[0] ? info.name : "(unnamed)");

    int r = freeze_map_by_fd(fd, map_id, 1);
    close(fd);
    return r;
}

static int freeze_by_prog(const char *prog_name_substr)
{
    int frozen = 0, checked = 0;
    uint32_t prog_id = 0;

#define MAX_MIDS 64
    uint32_t map_ids[MAX_MIDS];

    for (;;) {
        union bpf_attr na = {}; na.start_id = prog_id;
        if (bpf_call(BPF_PROG_GET_NEXT_ID, &na, BPF_ATTR_SZ(start_id)) < 0) break;
        prog_id = na.next_id;

        union bpf_attr pfa = {}; pfa.prog_id = prog_id;
        int pfd = bpf_call(BPF_PROG_GET_FD_BY_ID, &pfa, BPF_ATTR_SZ(prog_id));
        if (pfd < 0) continue;

        struct bpf_prog_info pinfo = {};
        pinfo.nr_map_ids = MAX_MIDS;
        pinfo.map_ids    = (uint64_t)(uintptr_t)map_ids;

        union bpf_attr pia = {};
        pia.info.bpf_fd   = (uint32_t)pfd;
        pia.info.info_len = sizeof(pinfo);
        pia.info.info     = (uint64_t)(uintptr_t)&pinfo;

        if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &pia, BPF_ATTR_SZ(info)) < 0) {
            close(pfd); continue;
        }
        close(pfd);

        if (!strstr(pinfo.name, prog_name_substr)) continue;

        printf("[*] matched prog id=%-5u name=%s  maps=%u\n",
               pinfo.id, pinfo.name, pinfo.nr_map_ids);

        for (uint32_t i = 0; i < pinfo.nr_map_ids; i++) {
            union bpf_attr mfa = {}; mfa.map_id = map_ids[i];
            int mfd = bpf_call(BPF_MAP_GET_FD_BY_ID, &mfa, BPF_ATTR_SZ(map_id));
            if (mfd < 0) continue;
            checked++;
            if (freeze_map_by_fd(mfd, map_ids[i], 1) == 0) frozen++;
            close(mfd);
        }
    }
    printf("[*] %d/%d maps frozen\n", frozen, checked);
    return frozen > 0 ? 0 : -1;
}

static void list_maps(void)
{
    uint32_t id = 0; int total = 0;
    printf("%-6s  %-20s  %-24s  flags\n", "id", "type", "name");
    for (;;) {
        union bpf_attr na = {}; na.start_id = id;
        if (bpf_call(BPF_MAP_GET_NEXT_ID, &na, BPF_ATTR_SZ(start_id)) < 0) break;
        id = na.next_id;

        union bpf_attr fa = {}; fa.map_id = id;
        int fd = bpf_call(BPF_MAP_GET_FD_BY_ID, &fa, BPF_ATTR_SZ(map_id));
        if (fd < 0) continue;

        struct bpf_map_info info = {};
        union bpf_attr ia = {};
        ia.info.bpf_fd   = (uint32_t)fd;
        ia.info.info_len = sizeof(info);
        ia.info.info     = (uint64_t)(uintptr_t)&info;

        if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &ia, BPF_ATTR_SZ(info)) == 0) {
            printf("%-6u  %-20s  %-24s  0x%x\n",
                   info.id, map_type_str(info.type),
                   info.name[0] ? info.name : "(unnamed)",
                   info.map_flags);
            total++;
        }
        close(fd);
    }
    printf("\n[*] %d maps\n", total);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  %s --list                     list all maps with flags\n"
            "  %s <map_id>                   freeze a specific map by id\n"
            "  %s --prog <name_substr>        freeze all maps of matching programs\n"
            "\n"
            "requires: CAP_BPF  (Linux 5.2+ for BPF_MAP_FREEZE)\n"
            "warning:  freeze is permanent for the map's lifetime\n",
            argv[0], argv[0], argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--list") == 0) {
        list_maps();
        return 0;
    }

    if (strcmp(argv[1], "--prog") == 0) {
        if (argc < 3) { fprintf(stderr, "missing name_substr\n"); return 1; }
        return freeze_by_prog(argv[2]);
    }

    uint32_t map_id = (uint32_t)atoi(argv[1]);
    if (map_id == 0) { fprintf(stderr, "invalid map id\n"); return 1; }
    return freeze_one(map_id);
}
