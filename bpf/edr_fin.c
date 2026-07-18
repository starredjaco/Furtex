#define _GNU_SOURCE
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define BPF_ATTR_SZ(f) \
    (offsetof(union bpf_attr, f) + sizeof(((union bpf_attr *)0)->f))

static int bpf_call(int cmd, union bpf_attr *a, unsigned sz)
{
    return (int)syscall(__NR_bpf, cmd, a, sz);
}

struct score {
    int falco;
    int tetragon;
    int elastic;
    int generic_edr;
    int has_lsm;
    int has_ringbuf;
    int has_prog_array;
    uint32_t interesting_sys_id;
    uint32_t trusted_pids_id;
};

static void score_map(const struct bpf_map_info *m, struct score *s)
{
    const char *n = m->name;

    if (strcmp(n, "interesting_sys") == 0) {
        s->falco += 10;
        s->interesting_sys_id = m->id;
    }
    if (strcmp(n, "syscall_exit_ta") == 0) s->falco += 5;
    if (strncmp(n, "tg_", 3) == 0)         s->tetragon += 3;
    if (strstr(n, "execve_map"))            s->tetragon += 5;
    if (strstr(n, "tcpmon"))               s->tetragon += 3;
    if (strstr(n, "elastic"))              s->elastic += 5;
    if (strstr(n, "endpoint"))             s->elastic += 3;

    if (m->type == BPF_MAP_TYPE_HASH && m->key_size == 4 && m->value_size == 1) {
        s->generic_edr++;
        if (strcmp(n, "trusted_pids") == 0 || strstr(n, "allowlist") || strstr(n, "whitelist")) {
            s->generic_edr += 3;
            s->trusted_pids_id = m->id;
        }
    }

    if (m->type == BPF_MAP_TYPE_ARRAY && m->max_entries == 512 && m->value_size == 1) {
        s->generic_edr += 3;
        s->falco += 3;
    }

    if (m->type == BPF_MAP_TYPE_RINGBUF)    s->has_ringbuf++;
    if (m->type == BPF_MAP_TYPE_PROG_ARRAY) s->has_prog_array++;
}

static void score_prog(const struct bpf_prog_info *p, struct score *s)
{
    const char *n = p->name;

    if (p->type == BPF_PROG_TYPE_LSM)          s->has_lsm++;
    if (strstr(n, "falco") || strstr(n, "ppm")) s->falco += 3;
    if (strstr(n, "tetragon") || strstr(n, "tg")) s->tetragon += 3;
    if (strstr(n, "elastic"))                   s->elastic += 3;

    if (p->type == BPF_PROG_TYPE_RAW_TRACEPOINT && (strstr(n, "sys_enter") || strstr(n, "sys_exit")))
        s->falco += 5;
}

int main(void)
{
    struct score s = {};

    uint32_t id = 0;
    for (;;) {
        union bpf_attr na = {}; na.start_id = id;
        if (bpf_call(BPF_MAP_GET_NEXT_ID, &na, BPF_ATTR_SZ(start_id)) < 0) break;
        id = na.next_id;

        union bpf_attr fa = {}; fa.map_id = id;
        int fd = bpf_call(BPF_MAP_GET_FD_BY_ID, &fa, BPF_ATTR_SZ(map_id));
        if (fd < 0) continue;

        struct bpf_map_info info = {};
        union bpf_attr ia = {};
        ia.info.bpf_fd = (uint32_t)fd; ia.info.info_len = sizeof(info);
        ia.info.info   = (uint64_t)(uintptr_t)&info;
        if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &ia, BPF_ATTR_SZ(info)) == 0)
            score_map(&info, &s);
        close(fd);
    }

    id = 0;
    for (;;) {
        union bpf_attr na = {}; na.start_id = id;
        if (bpf_call(BPF_PROG_GET_NEXT_ID, &na, BPF_ATTR_SZ(start_id)) < 0) break;
        id = na.next_id;

        union bpf_attr fa = {}; fa.prog_id = id;
        int fd = bpf_call(BPF_PROG_GET_FD_BY_ID, &fa, BPF_ATTR_SZ(prog_id));
        if (fd < 0) continue;

        struct bpf_prog_info info = {};
        union bpf_attr ia = {};
        ia.info.bpf_fd = (uint32_t)fd; ia.info.info_len = sizeof(info);
        ia.info.info   = (uint64_t)(uintptr_t)&info;
        if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &ia, BPF_ATTR_SZ(info)) == 0)
            score_prog(&info, &s);
        close(fd);
    }

    printf("=== EDR Fingerprint ===\n");
    printf("Falco score:     %d\n", s.falco);
    printf("Tetragon score:  %d\n", s.tetragon);
    printf("Elastic score:   %d\n", s.elastic);
    printf("Generic EDR:     %d\n", s.generic_edr);
    printf("\n");
    printf("LSM programs:    %d  %s\n", s.has_lsm,
           s.has_lsm ? "(security_bpf_map may be enforced!)" : "(map writes likely allowed)");
    printf("Ringbuf maps:    %d\n", s.has_ringbuf);
    printf("Prog arrays:     %d\n", s.has_prog_array);
    printf("\n");

    if (s.interesting_sys_id)
        printf("[!] interesting_sys map id=%u  (Falco syscall filter - poisonable)\n",
               s.interesting_sys_id);
    if (s.trusted_pids_id)
        printf("[!] PID allowlist map id=%u  (insert your PID with pid_allowlist)\n",
               s.trusted_pids_id);

    printf("\n=== Verdict ===\n");
    int mx = s.falco;
    const char *edr = "Falco";
    if (s.tetragon > mx) { mx = s.tetragon; edr = "Tetragon"; }
    if (s.elastic   > mx) { mx = s.elastic;  edr = "Elastic Defend"; }
    if (mx > 0)
        printf("Most likely: %s (score=%d)\n", edr, mx);
    else
        printf("No known eBPF EDR detected (or running without sufficient privileges)\n");

    return 0;
}
