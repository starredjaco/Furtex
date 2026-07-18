#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define ARG_MAX       128

struct exec_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u64 ns;
    __u8  comm[TASK_COMM_LEN];
    __u8  argv0[ARG_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 131072);
} events SEC(".maps");

struct sys_enter_execve_args {
    __u64 pad;
    long  syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int exec_spy(struct sys_enter_execve_args *ctx)
{
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    e->pid  = (__u32)(pid_tgid >> 32);
    e->uid  = (__u32)(uid_gid  & 0xffffffff);
    e->ns   = bpf_ktime_get_ns();
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_probe_read_user_str(e->argv0, sizeof(e->argv0), ctx->filename);

    e->ppid = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
