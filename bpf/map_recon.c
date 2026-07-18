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

static int bpf_call(int cmd, union bpf_attr *attr, unsigned sz)
{
    return (int)syscall(__NR_bpf, cmd, attr, sz);
}

static int map_get_next_id(uint32_t cur, uint32_t *next)
{
    union bpf_attr a = {};
    a.start_id = cur;
    int r = bpf_call(BPF_MAP_GET_NEXT_ID, &a, BPF_ATTR_SZ(start_id));
    if (r < 0) return -errno;
    *next = a.next_id;
    return 0;
}

static int map_fd_by_id(uint32_t id)
{
    union bpf_attr a = {};
    a.map_id = id;
    return bpf_call(BPF_MAP_GET_FD_BY_ID, &a, BPF_ATTR_SZ(map_id));
}

static int map_get_info(int fd, struct bpf_map_info *info)
{
    union bpf_attr a = {};
    a.info.bpf_fd   = (uint32_t)fd;
    a.info.info_len = sizeof(*info);
    a.info.info     = (uint64_t)(uintptr_t)info;
    return bpf_call(BPF_OBJ_GET_INFO_BY_FD, &a, BPF_ATTR_SZ(info));
}

static const char *map_type_str(uint32_t t)
{
    switch (t) {
    case BPF_MAP_TYPE_HASH:         return "hash";
    case BPF_MAP_TYPE_ARRAY:        return "array";
    case BPF_MAP_TYPE_PROG_ARRAY:   return "prog_array";
    case BPF_MAP_TYPE_PERF_EVENT_ARRAY: return "perf_event_array";
    case BPF_MAP_TYPE_PERCPU_HASH:  return "percpu_hash";
    case BPF_MAP_TYPE_PERCPU_ARRAY: return "percpu_array";
    case BPF_MAP_TYPE_LRU_HASH:     return "lru_hash";
    case BPF_MAP_TYPE_LPM_TRIE:     return "lpm_trie";
    case BPF_MAP_TYPE_RINGBUF:      return "ringbuf";
    default:                        return "other";
    }
}

static void dump_map_entries(int fd, const struct bpf_map_info *info, int max_entries)
{
    if (info->key_size > 8 || info->value_size > 8) {
        printf("    [skip dump: key=%uB val=%uB too large for inline print]\n",
               info->key_size, info->value_size);
        return;
    }

    uint8_t key[8]  = {};
    uint8_t nkey[8] = {};
    uint8_t val[8]  = {};
    int count = 0;

    union bpf_attr la = {}, na = {};

    uint8_t *kptr = NULL;
    while (count < max_entries) {
        na = (union bpf_attr){};
        na.map_fd = (uint32_t)fd;
        na.key    = (uint64_t)(uintptr_t)kptr;
        na.next_key = (uint64_t)(uintptr_t)nkey;
        if (bpf_call(BPF_MAP_GET_NEXT_KEY, &na, BPF_ATTR_SZ(next_key)) < 0) break;
        memcpy(key, nkey, info->key_size);
        kptr = key;

        la = (union bpf_attr){};
        la.map_fd = (uint32_t)fd;
        la.key    = (uint64_t)(uintptr_t)key;
        la.value  = (uint64_t)(uintptr_t)val;
        if (bpf_call(BPF_MAP_LOOKUP_ELEM, &la, BPF_ATTR_SZ(value)) < 0) continue;

        printf("    key=");
        for (uint32_t i = 0; i < info->key_size; i++) printf("%02x ", key[i]);
        printf(" val=");
        for (uint32_t i = 0; i < info->value_size; i++) printf("%02x ", val[i]);
        printf("\n");
        count++;
    }
}

int main(int argc, char *argv[])
{
    int dump_id = -1;
    if (argc == 3 && strcmp(argv[1], "--dump") == 0)
        dump_id = atoi(argv[2]);

    printf("%-6s %-16s %-18s %8s %8s %12s %6s\n",
           "ID", "NAME", "TYPE", "KEY_B", "VAL_B", "MAX_ENT", "FLAGS");
    printf("%.80s\n", "----------------------------------------"
                      "----------------------------------------");

    uint32_t id = 0;
    for (;;) {
        uint32_t next = 0;
        if (map_get_next_id(id, &next) < 0) break;
        id = next;

        int fd = map_fd_by_id(id);
        if (fd < 0) continue;

        struct bpf_map_info info = {};
        if (map_get_info(fd, &info) == 0) {
            printf("%-6u %-16s %-18s %8u %8u %12u %6u\n",
                   info.id,
                   info.name[0] ? info.name : "(unnamed)",
                   map_type_str(info.type),
                   info.key_size,
                   info.value_size,
                   info.max_entries,
                   info.map_flags);

            if ((int)info.id == dump_id) {
                printf("  [dump id=%u]\n", info.id);
                dump_map_entries(fd, &info, 32);
            }
        }
        close(fd);
    }

    return 0;
}
