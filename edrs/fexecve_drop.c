#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static int memfd_new(const char *name)
{
    return (int)syscall(__NR_memfd_create, name, MFD_CLOEXEC);
}

static int load_into_memfd(int mfd, const char *path)
{
    int src = open(path, O_RDONLY);
    if (src < 0) { perror(path); return -1; }

    char buf[65536];
    ssize_t n;
    while ((n = read(src, buf, sizeof(buf))) > 0) {
        const char *p = buf;
        while (n > 0) {
            ssize_t w = write(mfd, p, (size_t)n);
            if (w < 0) { perror("write memfd"); close(src); return -1; }
            p += w; n -= w;
        }
    }
    close(src);
    return 0;
}

static int load_from_stdin(int mfd)
{
    char buf[65536];
    ssize_t n;
    while ((n = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
        const char *p = buf;
        while (n > 0) {
            ssize_t w = write(mfd, p, (size_t)n);
            if (w < 0) { perror("write memfd"); return -1; }
            p += w; n -= w;
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s - [args]\n", argv[0]);
        return 1;
    }

    int mfd = memfd_new("anon");
    if (mfd < 0) { perror("memfd_create"); return 1; }

    if (strcmp(argv[1], "-") == 0) {
        if (load_from_stdin(mfd) < 0) return 1;
        char *exec_argv[] = { "anon", NULL };
        fexecve(mfd, exec_argv, environ);
    } else {
        if (load_into_memfd(mfd, argv[1]) < 0) return 1;

        char **exec_argv = argv + 1;
        fexecve(mfd, exec_argv, environ);
    }

    perror("fexecve");
    return 1;
}
