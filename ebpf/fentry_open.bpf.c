#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_PATH 256
#define MAX_COMM 16

struct file_event {
    __u32 pid;
    __u32 uid;
    __u32 flags;
    char  comm[MAX_COMM];
    char  path[MAX_PATH];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} cfg_map SEC(".maps");

struct sys_enter_openat_args {
    __u64 pad;
    long  syscall_nr;
    long  dfd;
    const char *filename;
    long  flags;
    long  mode;
};

static int path_is_interesting(const char *path, int len)
{
    if (len >= 5 && path[0]=='/' && path[1]=='e' && path[2]=='t'
                 && path[3]=='c' && path[4]=='/') return 1;
    if (len >= 6 && path[0]=='/' && path[1]=='r' && path[2]=='o'
                 && path[3]=='o' && path[4]=='t' && path[5]=='/') return 1;
    if (len >= 8 && path[0]=='/' && path[1]=='p' && path[2]=='r'
                 && path[3]=='o' && path[4]=='c' && path[5]=='/'
                 && path[6]=='1' && path[7]=='/') return 1;
    if (len >= 12 && path[0]=='/' && path[1]=='p' && path[2]=='r'
                  && path[3]=='o' && path[4]=='c' && path[5]=='/'
                  && path[6]=='s' && path[7]=='e' && path[8]=='l'
                  && path[9]=='f' && path[10]=='/'
                  && path[11]=='m') return 1;
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(struct sys_enter_openat_args *ctx)
{
    __u32 cfg_key = 0;
    __u8 *cfg_val = bpf_map_lookup_elem(&cfg_map, &cfg_key);
    int secrets_only = cfg_val ? *cfg_val : 0;

    struct file_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    __u64 id = bpf_get_current_pid_tgid();
    ev->pid   = (__u32)(id >> 32);
    ev->uid   = bpf_get_current_uid_gid() & 0xffffffff;
    ev->flags = (__u32)ctx->flags;
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    int path_len = bpf_probe_read_user_str(ev->path, sizeof(ev->path),
                                            ctx->filename);

    if (secrets_only && !path_is_interesting(ev->path, path_len)) {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
