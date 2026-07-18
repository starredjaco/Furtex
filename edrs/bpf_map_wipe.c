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

static int bpf_call(int cmd, union bpf_attr *attr, unsigned int sz)
{
    return (int)syscall(__NR_bpf, cmd, attr, sz);
}

static int map_fd_by_id(uint32_t id)
{
    union bpf_attr a = {}; a.map_id = id;
    return bpf_call(BPF_MAP_GET_FD_BY_ID, &a, BPF_ATTR_SZ(map_id));
}

static int map_info(int fd, struct bpf_map_info *info)
{
    union bpf_attr a = {};
    a.info.bpf_fd   = (uint32_t)fd;
    a.info.info_len = sizeof(*info);
    a.info.info     = (uint64_t)(uintptr_t)info;
    return bpf_call(BPF_OBJ_GET_INFO_BY_FD, &a, BPF_ATTR_SZ(info));
}

static const char *map_type_name(uint32_t t)
{
    switch (t) {
    case BPF_MAP_TYPE_HASH:            return "hash";
    case BPF_MAP_TYPE_ARRAY:           return "array";
    case BPF_MAP_TYPE_PROG_ARRAY:      return "prog_array";
    case BPF_MAP_TYPE_PERF_EVENT_ARRAY:return "perf_event_array";
    case BPF_MAP_TYPE_RINGBUF:         return "ringbuf";
    case BPF_MAP_TYPE_LRU_HASH:        return "lru_hash";
    default:                           return "other";
    }
}

static int zero_array_map(int fd, const struct bpf_map_info *info)
{
    uint8_t *zero = calloc(1, info->value_size);
    if (!zero) return -1;

    int zeroed = 0;
    for (uint32_t i = 0; i < info->max_entries; i++) {
        union bpf_attr a = {};
        a.map_fd = (uint32_t)fd;
        a.key    = (uint64_t)(uintptr_t)&i;
        a.value  = (uint64_t)(uintptr_t)zero;
        a.flags  = BPF_ANY;
        if (bpf_call(BPF_MAP_UPDATE_ELEM, &a, BPF_ATTR_SZ(flags)) == 0) zeroed++;
    }
    free(zero);
    return zeroed;
}

static int zero_hash_map(int fd, const struct bpf_map_info *info)
{
    uint8_t *key  = calloc(1, info->key_size);
    uint8_t *nkey = calloc(1, info->key_size);
    if (!key || !nkey) { free(key); free(nkey); return -1; }

    int deleted = 0;
    union bpf_attr first = {};
    first.map_fd = (uint32_t)fd;
    first.key    = (uint64_t)(uintptr_t)key;
    if (bpf_call(BPF_MAP_GET_NEXT_KEY, &first, BPF_ATTR_SZ(key)) < 0) {
        free(key); free(nkey); return 0;
    }

    memcpy(key, nkey, info->key_size);
    for (;;) {
        union bpf_attr del = {};
        del.map_fd = (uint32_t)fd;
        del.key    = (uint64_t)(uintptr_t)key;
        bpf_call(BPF_MAP_DELETE_ELEM, &del, BPF_ATTR_SZ(key));
        deleted++;

        union bpf_attr nxt = {};
        nxt.map_fd = (uint32_t)fd;
        nxt.key    = (uint64_t)(uintptr_t)key;
        nxt.value  = (uint64_t)(uintptr_t)nkey;
        if (bpf_call(BPF_MAP_GET_NEXT_KEY, &nxt, BPF_ATTR_SZ(value)) < 0) break;
        memcpy(key, nkey, info->key_size);
    }

    free(key); free(nkey);
    return deleted;
}

int main(int argc, char *argv[])
{
    int do_wipe = 0;
    int min_entries = 0;
    int dry_run = 0;

    if (argc < 2) {
        fprintf(stderr, "usage: %s wipe [args]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "wipe") == 0) {
        do_wipe = 1;
        min_entries = 100;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--dry-run") == 0) dry_run = 1;
            if (strcmp(argv[i], "--min") == 0 && i+1 < argc) min_entries = atoi(argv[++i]);
        }
    }

    uint32_t id = 0;
    int total = 0, wiped = 0;

    for (;;) {
        union bpf_attr nx = {}; nx.start_id = id;
        int r = bpf_call(BPF_MAP_GET_NEXT_ID, &nx, BPF_ATTR_SZ(next_id));
        if (r < 0) { if (errno == ENOENT) break; perror("GET_NEXT_ID"); break; }
        id = nx.next_id;

        int fd = map_fd_by_id(id);
        if (fd < 0) continue;

        struct bpf_map_info info = {};
        if (map_info(fd, &info) < 0) { close(fd); continue; }

        total++;
        printf("  map_id=%-5u  type=%-16s  key=%u  val=%u  entries=%u  name=%s\n",
               id, map_type_name(info.type),
               info.key_size, info.value_size, info.max_entries, info.name);

        if (do_wipe && (int)info.max_entries >= min_entries) {
            if (dry_run) {
                printf("    [dry-run] would wipe %u entries\n", info.max_entries);
            } else {
                int n = 0;
                if (info.type == BPF_MAP_TYPE_ARRAY ||
                    info.type == BPF_MAP_TYPE_LRU_HASH) {
                    n = zero_array_map(fd, &info);
                } else if (info.type == BPF_MAP_TYPE_HASH) {
                    n = zero_hash_map(fd, &info);
                }
                if (n > 0) { printf("    [wiped %d entries]\n", n); wiped++; }
            }
        }
        close(fd);
    }

    printf("[*] %d maps total", total);
    if (do_wipe && !dry_run) printf(", %d wiped", wiped);
    printf("\n");
    return 0;
}
