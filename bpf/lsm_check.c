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

static void list_lsm_progs(void)
{
    printf("[*] LSM BPF programs loaded:\n");
    int found = 0;
    uint32_t id = 0;
    for (;;) {
        union bpf_attr na = {}; na.start_id = id;
        if (bpf_call(BPF_PROG_GET_NEXT_ID, &na, BPF_ATTR_SZ(start_id)) < 0) break;
        id = na.next_id;

        union bpf_attr fa = {}; fa.prog_id = id;
        int fd = bpf_call(BPF_PROG_GET_FD_BY_ID, &fa, BPF_ATTR_SZ(prog_id));
        if (fd < 0) continue;

        struct bpf_prog_info info = {};
        union bpf_attr ia = {};
        ia.info.bpf_fd = (uint32_t)fd; ia.info.info_len = sizeof(info);
        ia.info.info   = (uint64_t)(uintptr_t)&info;
        if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &ia, BPF_ATTR_SZ(info)) == 0) {
            if (info.type == BPF_PROG_TYPE_LSM) {
                printf("    id=%-5u  name=%s\n", info.id,
                       info.name[0] ? info.name : "(unnamed)");
                found++;
            }
        }
        close(fd);
    }
    if (!found) printf("    (none)\n");
    printf("\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <map_id>\n", argv[0]);
        return 1;
    }

    uint32_t map_id = (uint32_t)atoi(argv[1]);

    list_lsm_progs();

    union bpf_attr fa = {}; fa.map_id = map_id;
    int fd = bpf_call(BPF_MAP_GET_FD_BY_ID, &fa, BPF_ATTR_SZ(map_id));
    if (fd < 0) { perror("map_fd"); return 1; }

    struct bpf_map_info info = {};
    union bpf_attr ia = {};
    ia.info.bpf_fd = (uint32_t)fd; ia.info.info_len = sizeof(info);
    ia.info.info   = (uint64_t)(uintptr_t)&info;
    bpf_call(BPF_OBJ_GET_INFO_BY_FD, &ia, BPF_ATTR_SZ(info));

    printf("[*] testing map id=%u name='%s' type=%u key=%uB val=%uB\n",
           info.id, info.name, info.type, info.key_size, info.value_size);

    if (info.key_size == 0 || info.value_size == 0) {
        fprintf(stderr, "[!] can't determine key/value size\n");
        return 1;
    }

    uint8_t key[32] = {};
    uint8_t val[32] = {};
    union bpf_attr la = {};
    la.map_fd = (uint32_t)fd;
    la.key    = (uint64_t)(uintptr_t)key;
    la.value  = (uint64_t)(uintptr_t)val;

    if (bpf_call(BPF_MAP_LOOKUP_ELEM, &la, BPF_ATTR_SZ(value)) < 0) {
        fprintf(stderr, "[!] lookup failed: %s\n", strerror(errno));
        return 1;
    }

    union bpf_attr ua = {};
    ua.map_fd = (uint32_t)fd;
    ua.key    = (uint64_t)(uintptr_t)key;
    ua.value  = (uint64_t)(uintptr_t)val;
    ua.flags  = BPF_EXIST;

    int r = bpf_call(BPF_MAP_UPDATE_ELEM, &ua, BPF_ATTR_SZ(flags));
    if (r < 0 && errno == EPERM) {
        printf("[!] EPERM - security_bpf_map is enforced\n");
        printf("    Map writes are blocked. BPF map poisoning won't work on this target.\n");
    } else if (r == 0) {
        printf("[+] Write succeeded - map is NOT protected by security_bpf_map\n");
        printf("    BPF map poisoning is viable on this target.\n");
    } else {
        printf("[?] unexpected error: %s\n", strerror(errno));
    }

    close(fd);
    return 0;
}
