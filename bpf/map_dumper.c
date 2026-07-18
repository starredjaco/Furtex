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

static int map_fd_by_id(uint32_t id)
{
    union bpf_attr a = {}; a.map_id = id;
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

static int map_lookup(int fd, const void *key, void *val, uint32_t val_sz)
{
    union bpf_attr a = {};
    a.map_fd = (uint32_t)fd;
    a.key    = (uint64_t)(uintptr_t)key;
    a.value  = (uint64_t)(uintptr_t)val;
    (void)val_sz;
    return bpf_call(BPF_MAP_LOOKUP_ELEM, &a, BPF_ATTR_SZ(value));
}

static int map_next_key(int fd, const void *key, void *next_key)
{
    union bpf_attr a = {};
    a.map_fd    = (uint32_t)fd;
    a.key       = (uint64_t)(uintptr_t)key;
    a.next_key  = (uint64_t)(uintptr_t)next_key;
    return bpf_call(BPF_MAP_GET_NEXT_KEY, &a, BPF_ATTR_SZ(next_key));
}

static void print_hex(const uint8_t *buf, uint32_t sz)
{
    for (uint32_t i = 0; i < sz; i++) printf("%02x ", buf[i]);
}

static void print_ascii(const uint8_t *buf, uint32_t sz)
{
    for (uint32_t i = 0; i < sz; i++)
        printf("%c", (buf[i] >= 0x20 && buf[i] < 0x7f) ? buf[i] : '.');
}

static void dump_array(int fd, const struct bpf_map_info *info, int ascii)
{
    uint8_t *key = calloc(1, info->key_size);
    uint8_t *val = calloc(1, info->value_size);
    uint32_t entries = 0;

    for (uint32_t i = 0; i < info->max_entries; i++) {
        *(uint32_t *)key = i;
        if (map_lookup(fd, key, val, info->value_size) < 0) continue;

        int nonzero = 0;
        for (uint32_t j = 0; j < info->value_size; j++) if (val[j]) { nonzero = 1; break; }
        if (!nonzero && info->max_entries > 32) continue;

        printf("[%4u]  key=", i);
        print_hex(key, info->key_size);
        printf(" -> val=");
        print_hex(val, info->value_size);
        if (ascii) { printf(" |"); print_ascii(val, info->value_size); printf("|"); }
        printf("\n");
        entries++;
    }
    printf("[*] %u non-zero entries (array max=%u)\n", entries, info->max_entries);
    free(key); free(val);
}

static void dump_hash(int fd, const struct bpf_map_info *info, int ascii)
{
    uint8_t *key  = calloc(1, info->key_size);
    uint8_t *nkey = calloc(1, info->key_size);
    uint8_t *val  = calloc(1, info->value_size);
    uint32_t entries = 0;
    uint8_t *cur = NULL;

    for (;;) {
        if (map_next_key(fd, cur, nkey) < 0) break;
        memcpy(key, nkey, info->key_size);
        cur = key;

        if (map_lookup(fd, key, val, info->value_size) < 0) continue;

        printf("key="); print_hex(key, info->key_size);
        printf("-> val="); print_hex(val, info->value_size);
        if (ascii) { printf(" |"); print_ascii(val, info->value_size); printf("|"); }
        printf("\n");
        entries++;
    }
    printf("[*] %u entries\n", entries);
    free(key); free(nkey); free(val);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <map_id> [--ascii]\n", argv[0]);
        return 1;
    }

    uint32_t id = (uint32_t)atoi(argv[1]);
    int ascii   = (argc >= 3 && strcmp(argv[2], "--ascii") == 0);

    int fd = map_fd_by_id(id);
    if (fd < 0) { perror("map_fd"); return 1; }

    struct bpf_map_info info = {};
    if (map_get_info(fd, &info) < 0) { perror("map_info"); return 1; }

    printf("[*] map id=%u name='%s' type=%u key=%uB val=%uB max=%u flags=%u\n",
           info.id, info.name, info.type,
           info.key_size, info.value_size, info.max_entries, info.map_flags);

    switch (info.type) {
    case BPF_MAP_TYPE_ARRAY:
    case BPF_MAP_TYPE_PERCPU_ARRAY:
        dump_array(fd, &info, ascii);
        break;
    case BPF_MAP_TYPE_HASH:
    case BPF_MAP_TYPE_PERCPU_HASH:
    case BPF_MAP_TYPE_LRU_HASH:
    case BPF_MAP_TYPE_PROG_ARRAY:
        dump_hash(fd, &info, ascii);
        break;
    default:
        fprintf(stderr, "[!] unsupported type %u, trying hash walk\n", info.type);
        dump_hash(fd, &info, ascii);
        break;
    }

    close(fd);
    return 0;
}
