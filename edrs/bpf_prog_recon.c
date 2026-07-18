#define _GNU_SOURCE
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#define BPF_ATTR_SZ(f) \
    (offsetof(union bpf_attr, f) + sizeof(((union bpf_attr *)0)->f))

static int bpf_call(int cmd, union bpf_attr *a, unsigned sz)
{ return (int)syscall(__NR_bpf, cmd, a, sz); }

static int prog_fd_by_id(uint32_t id)
{ union bpf_attr a={}; a.prog_id=id; return bpf_call(BPF_PROG_GET_FD_BY_ID,&a,BPF_ATTR_SZ(prog_id)); }
static int map_fd_by_id(uint32_t id)
{ union bpf_attr a={}; a.map_id=id; return bpf_call(BPF_MAP_GET_FD_BY_ID,&a,BPF_ATTR_SZ(map_id)); }

static int get_map_info(int fd, struct bpf_map_info *i)
{ union bpf_attr a={}; a.info.bpf_fd=(uint32_t)fd;
  a.info.info_len=sizeof(*i); a.info.info=(uint64_t)(uintptr_t)i;
  return bpf_call(BPF_OBJ_GET_INFO_BY_FD,&a,BPF_ATTR_SZ(info)); }

static int get_prog_info(int fd, struct bpf_prog_info *i, uint32_t *mids, uint32_t nm)
{ i->nr_map_ids=nm; i->map_ids=(uint64_t)(uintptr_t)mids;
  union bpf_attr a={}; a.info.bpf_fd=(uint32_t)fd;
  a.info.info_len=sizeof(*i); a.info.info=(uint64_t)(uintptr_t)i;
  return bpf_call(BPF_OBJ_GET_INFO_BY_FD,&a,BPF_ATTR_SZ(info)); }

static int map_lookup(int fd, const void *key, void *val)
{ union bpf_attr a={}; a.map_fd=(uint32_t)fd;
  a.key=(uint64_t)(uintptr_t)key; a.value=(uint64_t)(uintptr_t)val;
  return bpf_call(BPF_MAP_LOOKUP_ELEM,&a,BPF_ATTR_SZ(value)); }

static const char *prog_type_name(uint32_t t)
{
    static const char *n[] = {
        "UNSPEC","SOCKET_FILTER","KPROBE","SCHED_CLS","SCHED_ACT",
        "TRACEPOINT","XDP","PERF_EVENT","CGROUP_SKB","CGROUP_SOCK",
        "LWT_IN","LWT_OUT","LWT_XMIT","SOCK_OPS","SK_SKB",
        "CGROUP_DEVICE","SK_MSG","RAW_TRACEPOINT","CGROUP_SOCK_ADDR",
        "LWT_SEG6LOCAL","LIRC_MODE2","SK_REUSEPORT","FLOW_DISSECTOR",
        "CGROUP_SYSCTL","RAW_TRACEPOINT_WRITABLE","CGROUP_SOCKOPT",
        "TRACING","STRUCT_OPS","EXT","LSM","SK_LOOKUP","SYSCALL"
    };
    return t < sizeof(n)/sizeof(*n) ? n[t] : "?";
}

static const char *map_type_name(uint32_t t)
{
    static const char *n[] = {
        "UNSPEC","HASH","ARRAY","PROG_ARRAY","PERF_EVENT_ARRAY",
        "PERCPU_HASH","PERCPU_ARRAY","STACK_TRACE","CGROUP_ARRAY",
        "LRU_HASH","LRU_PERCPU_HASH","LPM_TRIE","ARRAY_OF_MAPS",
        "HASH_OF_MAPS","DEVMAP","SOCKMAP","CPUMAP","XSKMAP","SOCKHASH",
        "CGROUP_STORAGE","REUSEPORT_SOCKARRAY","PERCPU_CGROUP_STORAGE",
        "QUEUE","STACK","SK_STORAGE","DEVMAP_HASH","STRUCT_OPS",
        "RINGBUF","INODE_STORAGE","TASK_STORAGE","BLOOM_FILTER"
    };
    return t < sizeof(n)/sizeof(*n) ? n[t] : "?";
}

static void do_progs(void)
{
    printf("\n[BPF PROGRAMS]\n");
    printf("%-6s %-22s %-22s %s\n", "ID", "TYPE", "NAME", "MAPS");

    uint32_t id = 0; int total = 0;
    for (;;) {
        union bpf_attr a = {}; a.start_id = id;
        if (bpf_call(BPF_PROG_GET_NEXT_ID, &a, BPF_ATTR_SZ(next_id)) < 0) break;
        id = a.next_id;

        int fd = prog_fd_by_id(id); if (fd < 0) continue;

        uint32_t mids[32] = {};
        struct bpf_prog_info info = {};
        get_prog_info(fd, &info, mids, 32);
        close(fd);

        int hi = (info.type == 26  ||
                  info.type == 29               ||
                  info.type == 2  );

        printf("%s%-6u %-22s %-22s nr_maps=%u%s\n",
               hi ? "\033[33m" : "",
               info.id, prog_type_name(info.type),
               info.name[0] ? info.name : "(anon)",
               info.nr_map_ids,
               hi ? "\033[0m" : "");
        total++;
    }
    printf("[total: %d programas]\n", total);
}

static void do_maps(void)
{
    printf("\n[BPF MAPS]\n");
    printf("%-6s %-16s %-24s %-10s %s\n", "ID", "TYPE", "NAME", "ENTRIES", "FLAGS");

    uint32_t id = 0; int total = 0;
    int protect_fd = -1; uint32_t protect_id = 0;

    for (;;) {
        union bpf_attr a = {}; a.start_id = id;
        if (bpf_call(BPF_MAP_GET_NEXT_ID, &a, BPF_ATTR_SZ(next_id)) < 0) break;
        id = a.next_id;

        int fd = map_fd_by_id(id); if (fd < 0) continue;

        struct bpf_map_info mi = {};
        get_map_info(fd, &mi);

        int is_ringbuf  = (mi.type == 27 );
        int is_hash     = (mi.type == 1 || mi.type == 9 );

        int is_guard    = (is_hash && mi.max_entries <= 1024 &&
                           strstr(mi.name, "protect"));

        const char *flag = is_ringbuf ? " [RINGBUF]" :
                           is_guard   ? " [GUARD?]"  : "";

        int hi = (is_ringbuf || is_guard);
        printf("%s%-6u %-16s %-24s %-10u%s%s\n",
               hi ? "\033[33m" : "",
               mi.id, map_type_name(mi.type),
               mi.name[0] ? mi.name : "(anon)",
               mi.max_entries, flag,
               hi ? "\033[0m" : "");

        if (is_guard && protect_fd < 0) {
            protect_fd = fd; protect_id = mi.id;
            fd = -1;
        }
        if (fd >= 0) close(fd);
        total++;
    }
    printf("[total: %d mapas]\n", total);

    if (protect_fd >= 0) {
        printf("\n[GUARD MAP id=%u - testando lookup de IDs]\n", protect_id);

        int hits = 0;
        for (uint32_t test = 1; test < 512; test++) {
            uint8_t val = 0;
            if (map_lookup(protect_fd, &test, &val) == 0) {
                printf("  map id=%u protected (val=%u)\n", test, val);
                hits++;
            }
        }
        if (!hits) printf("  no IDs found in range 1-512\n");
        close(protect_fd);
    }
}

static void do_kprobes(void)
{
    printf("\n[ACTIVE KPROBES]\n");
    FILE *f = fopen("/sys/kernel/debug/kprobes/list", "r");
    if (!f) {
        printf("  no access (debugfs not mounted or no permission)\n");
        return;
    }
    char line[256]; int n = 0;
    while (fgets(line, sizeof(line), f)) { printf("  %s", line); n++; }
    fclose(f);
    if (!n) printf("  (empty)\n");
    else printf("[total: %d kprobes]\n", n);
}

int main(int argc, char *argv[])
{
    int do_p = 0, do_m = 0, do_k = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i],"--progs"))   do_p = 1;
        if (!strcmp(argv[i],"--maps"))    do_m = 1;
        if (!strcmp(argv[i],"--kprobes")) do_k = 1;
        if (!strcmp(argv[i],"--all"))     do_p = do_m = do_k = 1;
    }
    if (!do_p && !do_m && !do_k) do_p = do_m = do_k = 1;

    if (do_p) do_progs();
    if (do_m) do_maps();
    if (do_k) do_kprobes();
    return 0;
}
