#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH 256
#define MAX_DATA 512

static const char *watch_paths[] = {
    "/etc/shadow",
    "/etc/passwd",
    "/etc/gshadow",
    "/root/.ssh/id_rsa",
    "/root/.aws/credentials",
};
#define N_WATCH (sizeof(watch_paths)/sizeof(watch_paths[0]))

struct open_event {
    __u32 pid;
    __u32 uid;
    char  comm[16];
    char  path[MAX_PATH];
};

struct read_event {
    __u32 pid;
    __u32 uid;
    __u32 fd;
    __u32 len;
    char  comm[16];
    char  path[MAX_PATH];
    char  data[MAX_DATA];
};

struct {
    __uint(type,  BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,   __u64);
    __type(value, char[MAX_PATH]);
} pending_opens SEC(".maps");

struct {
    __uint(type,  BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   __u64);
    __type(value, char[MAX_PATH]);
} watched_fds SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

static int path_matches(const char *path)
{
    char p[MAX_PATH];
    bpf_probe_read_user_str(p, sizeof(p), path);

    if (p[0]=='/') {

        if (p[1]=='e' && p[2]=='t' && p[3]=='c' && p[4]=='/'
            && p[5]=='s' && p[6]=='h' && p[7]=='a' && p[8]=='d'
            && p[9]=='o' && p[10]=='w' && p[11]=='\0') return 1;

        if (p[1]=='e' && p[2]=='t' && p[3]=='c' && p[4]=='/'
            && p[5]=='p' && p[6]=='a' && p[7]=='s' && p[8]=='s'
            && p[9]=='w' && p[10]=='d' && p[11]=='\0') return 1;

        if (p[1]=='e' && p[2]=='t' && p[3]=='c' && p[4]=='/'
            && p[5]=='g' && p[6]=='s' && p[7]=='h' && p[8]=='a'
            && p[9]=='d' && p[10]=='o' && p[11]=='w' && p[12]=='\0') return 1;

        if (p[1]=='r' && p[2]=='o' && p[3]=='o' && p[4]=='t'
            && p[5]=='/' && p[6]=='.' && p[7]=='s' && p[8]=='s'
            && p[9]=='h' && p[10]=='/') return 1;

        if (p[1]=='r' && p[2]=='o' && p[3]=='o' && p[4]=='t'
            && p[5]=='/' && p[6]=='.' && p[7]=='a' && p[8]=='w'
            && p[9]=='s' && p[10]=='/') return 1;

        if (p[1]=='p' && p[2]=='r' && p[3]=='o' && p[4]=='c'
            && p[5]=='/' && p[6]=='1' && p[7]=='/'
            && p[8]=='e' && p[9]=='n' && p[10]=='v') return 1;
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    const char *user_path = (const char *)ctx->args[1];
    if (!path_matches(user_path)) return 0;

    __u64 id = bpf_get_current_pid_tgid();
    char  path[MAX_PATH];
    bpf_probe_read_user_str(path, sizeof(path), user_path);
    bpf_map_update_elem(&pending_opens, &id, path, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tp_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    char *path = bpf_map_lookup_elem(&pending_opens, &id);
    if (!path) return 0;
    bpf_map_delete_elem(&pending_opens, &id);

    int ret = (int)ctx->ret;
    if (ret < 0) return 0;

    __u64 key = (id & 0xFFFFFFFF00000000ULL) | ((__u64)(unsigned)ret & 0xFFFFFFFFULL);
    bpf_map_update_elem(&watched_fds, &key, path, BPF_ANY);

    struct open_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (ev) {
        ev->pid = (__u32)(id >> 32);
        ev->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        bpf_get_current_comm(ev->comm, sizeof(ev->comm));
        bpf_probe_read_kernel_str(ev->path, sizeof(ev->path), path);
        bpf_ringbuf_submit(ev, 0);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int tp_exit_read(struct trace_event_raw_sys_exit *ctx)
{
    int bytes = (int)ctx->ret;
    if (bytes <= 0) return 0;

    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(id >> 32);

    (void)pid;
    return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,  __u64);
    __type(value, __u32);
} pending_reads SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_read")
int tp_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    __u64 id  = bpf_get_current_pid_tgid();
    __u32 fd  = (__u32)ctx->args[0];

    __u64 key = (id & 0xFFFFFFFF00000000ULL) | ((__u64)fd & 0xFFFFFFFFULL);
    if (!bpf_map_lookup_elem(&watched_fds, &key)) return 0;

    bpf_map_update_elem(&pending_reads, &id, &fd, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read2")
int tp_exit_read2(struct trace_event_raw_sys_exit *ctx)
{
    int bytes = (int)ctx->ret;
    if (bytes <= 0) return 0;

    __u64 id = bpf_get_current_pid_tgid();
    __u32 *fdp = bpf_map_lookup_elem(&pending_reads, &id);
    if (!fdp) return 0;
    __u32 fd = *fdp;
    bpf_map_delete_elem(&pending_reads, &id);

    __u64 fkey = (id & 0xFFFFFFFF00000000ULL) | ((__u64)fd & 0xFFFFFFFFULL);
    char *path = bpf_map_lookup_elem(&watched_fds, &fkey);
    if (!path) return 0;

    struct read_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->pid = (__u32)(id >> 32);
    ev->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev->fd  = fd;
    ev->len = (__u32)bytes;
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));
    bpf_probe_read_kernel_str(ev->path, sizeof(ev->path), path);

    ev->data[0] = '['; ev->data[1] = 'r'; ev->data[2] = 'e'; ev->data[3] = 'd';
    ev->data[4] = 'a'; ev->data[5] = 'c'; ev->data[6] = 't'; ev->data[7] = 'e';
    ev->data[8] = 'd'; ev->data[9] = ']'; ev->data[10] = 0;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
