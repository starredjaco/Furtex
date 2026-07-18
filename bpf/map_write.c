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

static int parse_hex(const char *s, uint8_t *out, size_t maxlen)
{
    size_t slen = strlen(s);
    if (slen % 2 != 0 || slen / 2 > maxlen) return -1;
    for (size_t i = 0; i < slen / 2; i++) {
        char byte[3] = { s[i*2], s[i*2+1], 0 };
        out[i] = (uint8_t)strtoul(byte, NULL, 16);
    }
    return (int)(slen / 2);
}

int main(int argc, char *argv[])
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s <map_id> <key_hex> <value_hex>\n", argv[0]);
        fprintf(stderr, "  key/value as hex without spaces: 3b000000\n");
        return 1;
    }

    uint32_t id = (uint32_t)atoi(argv[1]);

    int fd = map_fd_by_id(id);
    if (fd < 0) { perror("map_fd"); return 1; }

    struct bpf_map_info info = {};
    if (map_get_info(fd, &info) < 0) { perror("map_info"); return 1; }

    printf("[*] map id=%u name='%s' key=%uB val=%uB\n",
           info.id, info.name, info.key_size, info.value_size);

    uint8_t key[256] = {}, val[256] = {};
    int klen = parse_hex(argv[2], key, sizeof(key));
    int vlen = parse_hex(argv[3], val, sizeof(val));

    if (klen < 0 || (uint32_t)klen != info.key_size) {
        fprintf(stderr, "[!] key is %d bytes, map expects %u\n", klen, info.key_size);
        return 1;
    }
    if (vlen < 0 || (uint32_t)vlen != info.value_size) {
        fprintf(stderr, "[!] value is %d bytes, map expects %u\n", vlen, info.value_size);
        return 1;
    }

    union bpf_attr a = {};
    a.map_fd = (uint32_t)fd;
    a.key    = (uint64_t)(uintptr_t)key;
    a.value  = (uint64_t)(uintptr_t)val;
    a.flags  = BPF_ANY;
    if (bpf_call(BPF_MAP_UPDATE_ELEM, &a, BPF_ATTR_SZ(flags)) < 0) {
        perror("update");
        return 1;
    }
    printf("[*] wrote key=");
    for (int i = 0; i < klen; i++) printf("%02x", key[i]);
    printf(" val=");
    for (int i = 0; i < vlen; i++) printf("%02x", val[i]);
    printf("\n");

    close(fd);
    return 0;
}
