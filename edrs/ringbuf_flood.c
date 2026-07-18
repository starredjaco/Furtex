#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>

static volatile int stop = 0;
static void on_sig(int s) { (void)s; stop = 1; }

struct targ { long ops; int id; };

static void *file_flood(void *arg)
{
    struct targ *t = arg;
    while (!stop) {
        int fd = open("/proc/cpuinfo", O_RDONLY);
        if (fd >= 0) close(fd);
        t->ops++;
    }
    return NULL;
}

static void *fork_flood(void *arg)
{
    struct targ *t = arg;
    while (!stop) {
        pid_t p = fork();
        if (p == 0) { execl("/bin/true", "true", NULL); _exit(0); }
        if (p > 0)  { waitpid(p, NULL, 0); t->ops++; }
    }
    return NULL;
}

static void *net_flood(void *arg)
{
    struct targ *t = arg;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return NULL;
    struct sockaddr_in sa = {};
    sa.sin_family = AF_INET; sa.sin_port = htons(53);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    char buf[8] = {};
    while (!stop) {
        sendto(s, buf, sizeof(buf), MSG_NOSIGNAL, (struct sockaddr*)&sa, sizeof(sa));
        t->ops++;
    }
    close(s);
    return NULL;
}

static void do_flood(int n_threads, int sec)
{

    int nf = n_threads / 2 + (n_threads % 2);
    int nfork = n_threads / 4;
    int nnet  = n_threads - nf - nfork;
    if (nnet  < 1) nnet  = 1;
    if (nfork < 1) nfork = 1;

    int total = nf + nfork + nnet;
    pthread_t *tids = malloc((size_t)total * sizeof(pthread_t));
    struct targ *args = calloc((size_t)total, sizeof(struct targ));

    signal(SIGINT, on_sig); signal(SIGALRM, on_sig);
    alarm((unsigned)sec);

    int idx = 0;
    for (int i = 0; i < nf;   i++) pthread_create(&tids[idx], NULL, file_flood, &args[idx]), idx++;
    for (int i = 0; i < nfork;i++) pthread_create(&tids[idx], NULL, fork_flood, &args[idx]), idx++;
    for (int i = 0; i < nnet; i++) pthread_create(&tids[idx], NULL, net_flood,  &args[idx]), idx++;

    fprintf(stderr, "[flood] %d threads (file=%d fork=%d net=%d) for %ds\n",
            total, nf, nfork, nnet, sec);

    long ops = 0;
    for (int i = 0; i < total; i++) { pthread_join(tids[i], NULL); ops += args[i].ops; }

    printf("[flood] %ld events in %ds (%.0f /s)\n", ops, sec, (double)ops/sec);
    free(tids); free(args);
}

static void do_measure(void)
{
    const int N = 5000;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < N; i++) {
        int fd = open("/proc/cpuinfo", O_RDONLY);
        if (fd >= 0) close(fd);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ns = (long)((t1.tv_sec-t0.tv_sec)*1000000000L + (t1.tv_nsec-t0.tv_nsec));
    printf("[measure] %d ops em %.1f ms = %.0f ops/s  (%.1f us/op)\n",
           N, (double)ns/1e6, (double)N*1e9/ns, (double)ns/N/1e3);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <--measure|--flood>\n", argv[0]);
        return 1;
    }
    if (!strcmp(argv[1], "--measure")) { do_measure(); return 0; }
    if (!strcmp(argv[1], "--flood")) {
        int threads = 8, sec = 10;
        for (int i = 2; i < argc-1; i++) {
            if (!strcmp(argv[i],"--threads")) threads = atoi(argv[++i]);
            if (!strcmp(argv[i],"--sec"))     sec     = atoi(argv[++i]);
        }
        do_flood(threads, sec);
        return 0;
    }
    return 1;
}
