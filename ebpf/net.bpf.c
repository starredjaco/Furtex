#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define AF_INET  2
#define TASK_COMM_LEN 16

struct conn_event {
    __u32 pid;
    __u32 daddr;
    __u16 dport;
    __u8  comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 65536);
} events SEC(".maps");

struct sys_enter_connect_args {
    __u64 pad;
    long  syscall_nr;
    long  fd;
    struct sockaddr *uservaddr;
    int   addrlen;
};

struct my_sockaddr_in {
    __u16 sin_family;
    __u16 sin_port;
    __u32 sin_addr;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int net_spy(struct sys_enter_connect_args *ctx)
{
    struct my_sockaddr_in sa = {};
    if (bpf_probe_read_user(&sa, sizeof(sa), ctx->uservaddr) < 0) return 0;
    if (sa.sin_family != AF_INET) return 0;

    struct conn_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid   = ((__u64)bpf_get_current_pid_tgid()) >> 32;
    e->daddr = sa.sin_addr;
    e->dport = bpf_ntohs(sa.sin_port);
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
