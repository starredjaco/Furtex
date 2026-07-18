#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define CAP_SZ        256

struct tty_event {
    __u32 pid;
    __u32 fd;
    __u32 len;
    __u64 ns;
    __u8  comm[TASK_COMM_LEN];
    __u8  data[CAP_SZ];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int is_interesting_fd(__u32 fd)
{
    return fd <= 2;
}

struct sys_enter_write_args {
    __u64 pad;
    long  syscall_nr;
    __u64 fd;
    const char *buf;
    __u64 count;
};

SEC("tracepoint/syscalls/sys_enter_write")
int tty_write_sniff(struct sys_enter_write_args *ctx)
{
    __u32 fd = (__u32)ctx->fd;
    if (!is_interesting_fd(fd)) return 0;

    __u32 count = (__u32)ctx->count;
    if (count == 0) return 0;

    struct tty_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    e->fd  = fd;
    e->ns  = bpf_ktime_get_ns();
    e->len = count < CAP_SZ ? count : CAP_SZ;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_probe_read_user(e->data, sizeof(e->data), ctx->buf);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u64);
} pending_reads SEC(".maps");

struct sys_enter_read_args {
    __u64 pad;
    long  syscall_nr;
    __u64 fd;
    char *buf;
    __u64 count;
};

SEC("tracepoint/syscalls/sys_enter_read")
int tty_read_enter(struct sys_enter_read_args *ctx)
{
    __u32 fd = (__u32)ctx->fd;
    if (!is_interesting_fd(fd)) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 buf_addr = (__u64)(__u64)ctx->buf;
    bpf_map_update_elem(&pending_reads, &pid_tgid, &buf_addr, BPF_ANY);
    return 0;
}

struct sys_exit_read_args {
    __u64 pad;
    long  syscall_nr;
    long  ret;
};

SEC("tracepoint/syscalls/sys_exit_read")
int tty_read_exit(struct sys_exit_read_args *ctx)
{
    if (ctx->ret <= 0) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *bufp = bpf_map_lookup_elem(&pending_reads, &pid_tgid);
    if (!bufp) return 0;
    bpf_map_delete_elem(&pending_reads, &pid_tgid);

    struct tty_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = (__u32)(pid_tgid >> 32);
    e->fd  = 0;
    e->ns  = bpf_ktime_get_ns();
    e->len = (__u32)(ctx->ret < CAP_SZ ? ctx->ret : CAP_SZ);
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_probe_read_user(e->data, sizeof(e->data), (void *)*bufp);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
