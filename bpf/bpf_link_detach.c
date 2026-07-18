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

static const char *link_type_str(uint32_t t)
{
    switch (t) {
    case BPF_LINK_TYPE_RAW_TRACEPOINT: return "raw_tracepoint";
    case BPF_LINK_TYPE_TRACING:        return "tracing";
    case BPF_LINK_TYPE_CGROUP:         return "cgroup";
    case BPF_LINK_TYPE_ITER:           return "iter";
    case BPF_LINK_TYPE_XDP:            return "xdp";
    case BPF_LINK_TYPE_PERF_EVENT:     return "perf_event";
    case BPF_LINK_TYPE_KPROBE_MULTI:   return "kprobe_multi";
    default:                           return "other";
    }
}

static const char *prog_type_str(uint32_t t)
{
    switch (t) {
    case BPF_PROG_TYPE_KPROBE:       return "kprobe";
    case BPF_PROG_TYPE_TRACEPOINT:   return "tracepoint";
    case BPF_PROG_TYPE_RAW_TRACEPOINT: return "raw_tracepoint";
    case BPF_PROG_TYPE_TRACING:      return "tracing/fentry";
    case BPF_PROG_TYPE_LSM:          return "lsm";
    default:                         return "other";
    }
}

static int get_prog_type(uint32_t prog_id, uint32_t *prog_type_out)
{
    union bpf_attr fa = {}; fa.prog_id = prog_id;
    int fd = bpf_call(BPF_PROG_GET_FD_BY_ID, &fa, BPF_ATTR_SZ(prog_id));
    if (fd < 0) return -1;

    struct bpf_prog_info info = {};
    union bpf_attr ia = {};
    ia.info.bpf_fd   = (uint32_t)fd;
    ia.info.info_len = sizeof(info);
    ia.info.info     = (uint64_t)(uintptr_t)&info;
    int r = bpf_call(BPF_OBJ_GET_INFO_BY_FD, &ia, BPF_ATTR_SZ(info));
    close(fd);
    if (r < 0) return -1;
    *prog_type_out = info.type;
    return 0;
}

static int link_fd_by_id(uint32_t id)
{
    union bpf_attr a = {}; a.link_id = id;
    return bpf_call(BPF_LINK_GET_FD_BY_ID, &a, BPF_ATTR_SZ(link_id));
}

static int cmd_list(int lsm_only)
{
    printf("%-6s  %-18s  %-8s  %-22s\n",
           "ID", "LINK_TYPE", "PROG_ID", "PROG_TYPE");
    printf("%.60s\n",
           "------------------------------------------------------------");

    uint32_t id = 0;
    int total = 0, lsm_count = 0;

    for (;;) {
        union bpf_attr na = {}; na.start_id = id;
        if (bpf_call(BPF_LINK_GET_NEXT_ID, &na, BPF_ATTR_SZ(start_id)) < 0) break;
        id = na.next_id;

        int fd = link_fd_by_id(id);
        if (fd < 0) continue;

        struct bpf_link_info info = {};
        union bpf_attr ia = {};
        ia.info.bpf_fd   = (uint32_t)fd;
        ia.info.info_len = sizeof(info);
        ia.info.info     = (uint64_t)(uintptr_t)&info;

        if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &ia, BPF_ATTR_SZ(info)) < 0) {
            close(fd); continue;
        }

        uint32_t prog_type = 0;
        get_prog_type(info.prog_id, &prog_type);

        int is_lsm = (prog_type == BPF_PROG_TYPE_LSM);
        if (lsm_only && !is_lsm) { close(fd); continue; }

        printf("%-6u  %-18s  %-8u  %-22s%s\n",
               info.id, link_type_str(info.type),
               info.prog_id, prog_type_str(prog_type),
               is_lsm ? "  [LSM]" : "");

        total++;
        if (is_lsm) lsm_count++;
        close(fd);
    }

    printf("\n[*] %d links  (%d LSM)\n", total, lsm_count);
    return 0;
}

static int do_detach(int fd, uint32_t id)
{
    union bpf_attr da = {};
    da.link_detach.link_fd = (uint32_t)fd;
    int r = bpf_call(BPF_LINK_DETACH, &da, BPF_ATTR_SZ(link_detach));
    if (r < 0) {
        fprintf(stderr, "[-] detach link id=%u: %s\n", id, strerror(errno));
        return -1;
    }
    printf("[+] detached link id=%u\n", id);
    return 0;
}

static int cmd_detach(uint32_t link_id)
{
    int fd = link_fd_by_id(link_id);
    if (fd < 0) { perror("link_fd"); return 1; }

    struct bpf_link_info info = {};
    union bpf_attr ia = {};
    ia.info.bpf_fd   = (uint32_t)fd;
    ia.info.info_len = sizeof(info);
    ia.info.info     = (uint64_t)(uintptr_t)&info;
    bpf_call(BPF_OBJ_GET_INFO_BY_FD, &ia, BPF_ATTR_SZ(info));

    uint32_t prog_type = 0;
    get_prog_type(info.prog_id, &prog_type);

    printf("[*] link id=%u  type=%s  prog_id=%u  prog_type=%s\n",
           info.id, link_type_str(info.type),
           info.prog_id, prog_type_str(prog_type));

    int r = do_detach(fd, link_id);
    close(fd);
    return r < 0 ? 1 : 0;
}

static int cmd_detach_lsm(int dry_run)
{
    uint32_t id = 0;
    int detached = 0;

    for (;;) {
        union bpf_attr na = {}; na.start_id = id;
        if (bpf_call(BPF_LINK_GET_NEXT_ID, &na, BPF_ATTR_SZ(start_id)) < 0) break;
        id = na.next_id;

        int fd = link_fd_by_id(id);
        if (fd < 0) continue;

        struct bpf_link_info info = {};
        union bpf_attr ia = {};
        ia.info.bpf_fd   = (uint32_t)fd;
        ia.info.info_len = sizeof(info);
        ia.info.info     = (uint64_t)(uintptr_t)&info;

        if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &ia, BPF_ATTR_SZ(info)) < 0) {
            close(fd); continue;
        }

        uint32_t prog_type = 0;
        get_prog_type(info.prog_id, &prog_type);

        if (prog_type != BPF_PROG_TYPE_LSM) { close(fd); continue; }

        printf("[%s] link id=%-4u prog_id=%-4u (%s)\n",
               dry_run ? "dry-run" : "detach",
               info.id, info.prog_id,
               link_type_str(info.type));

        if (!dry_run) {
            if (do_detach(fd, info.id) == 0) detached++;
        }
        close(fd);
    }

    if (!dry_run) printf("[*] %d LSM links detached\n", detached);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  %s list [--lsm-only]          list all BPF links\n"
            "  %s detach <link_id>            detach a specific link\n"
            "  %s detach-lsm [--dry-run]      detach all BPF LSM links\n"
            "\nrequires: CAP_BPF  (Linux 5.9+ for BPF_LINK_DETACH)\n",
            argv[0], argv[0], argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "list") == 0) {
        int lsm_only = (argc >= 3 && strcmp(argv[2], "--lsm-only") == 0);
        return cmd_list(lsm_only);

    } else if (strcmp(argv[1], "detach") == 0 && argc >= 3) {
        return cmd_detach((uint32_t)atoi(argv[2]));

    } else if (strcmp(argv[1], "detach-lsm") == 0) {
        int dry_run = (argc >= 3 && strcmp(argv[2], "--dry-run") == 0);
        return cmd_detach_lsm(dry_run);

    } else {
        fprintf(stderr, "unknown command: %s\n", argv[1]);
        return 1;
    }
}
