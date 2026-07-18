#define _GNU_SOURCE
#include <sys/syscall.h>
#include <linux/memfd.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static int memfd_new(void)
{
    return (int)syscall(__NR_memfd_create, "so", MFD_CLOEXEC);
}

static int write_bytes(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) return -1;
        p += n; len -= (size_t)n;
    }
    return 0;
}

static void *load_so_from_path(const char *so_path, int *mfd_out)
{
    int src = open(so_path, O_RDONLY);
    if (src < 0) { perror(so_path); return NULL; }

    int mfd = memfd_new();
    if (mfd < 0) { perror("memfd_create"); close(src); return NULL; }

    char buf[65536];
    ssize_t n;
    while ((n = read(src, buf, sizeof(buf))) > 0)
        if (write_bytes(mfd, buf, (size_t)n) < 0) {
            perror("write"); close(src); close(mfd); return NULL;
        }
    close(src);

    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", mfd);

    void *h = dlopen(fd_path, RTLD_NOW | RTLD_LOCAL);
    if (!h) fprintf(stderr, "[!] dlopen: %s\n", dlerror());

    if (mfd_out) *mfd_out = mfd;
    else close(mfd);

    return h;
}

static void *load_so_from_stdin(int *mfd_out)
{
    int mfd = memfd_new();
    if (mfd < 0) { perror("memfd_create"); return NULL; }

    char buf[65536];
    ssize_t n;
    while ((n = read(STDIN_FILENO, buf, sizeof(buf))) > 0)
        if (write_bytes(mfd, buf, (size_t)n) < 0) {
            perror("write"); close(mfd); return NULL;
        }

    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", mfd);

    void *h = dlopen(fd_path, RTLD_NOW | RTLD_LOCAL);
    if (!h) fprintf(stderr, "[!] dlopen: %s\n", dlerror());

    if (mfd_out) *mfd_out = mfd;
    else close(mfd);

    return h;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <load|stdin>\n", argv[0]);
        return 1;
    }

    void *handle = NULL;
    int mfd = -1;
    const char *sym = NULL;

    if (strcmp(argv[1], "load") == 0 && argc >= 3) {
        sym = argc >= 4 ? argv[3] : NULL;
        handle = load_so_from_path(argv[2], &mfd);
    } else if (strcmp(argv[1], "stdin") == 0) {
        sym = argc >= 3 ? argv[2] : NULL;
        handle = load_so_from_stdin(&mfd);
    } else {
        fprintf(stderr, "unknown: %s\n", argv[1]);
        return 1;
    }

    if (!handle) return 1;
    printf("[+] loaded via /proc/self/fd/%d\n", mfd);

    if (sym) {
        void (*fn)(void) = dlsym(handle, sym);
        if (!fn) { fprintf(stderr, "[!] sym '%s' not found: %s\n", sym, dlerror()); }
        else { printf("[*] calling %s()\n", sym); fn(); }
    }

    printf("[*] handle open - press Enter to dlclose and exit\n");
    getchar();
    dlclose(handle);
    return 0;
}
