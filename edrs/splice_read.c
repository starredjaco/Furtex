#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s [args]\n", argv[0]);
        return 1;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }

    int pfd[2];
    if (pipe(pfd) < 0) { perror("pipe"); close(fd); return 1; }

    for (;;) {
        ssize_t n = splice(fd, NULL, pfd[1], NULL, 1 << 17, SPLICE_F_MOVE);
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("splice");
            break;
        }

        ssize_t rem = n;
        while (rem > 0) {
            char buf[65536];
            ssize_t r = read(pfd[0], buf,
                             rem < (ssize_t)sizeof(buf) ? (size_t)rem : sizeof(buf));
            if (r <= 0) break;
            fwrite(buf, 1, (size_t)r, stdout);
            rem -= r;
        }
    }

    close(pfd[0]);
    close(pfd[1]);
    close(fd);
    return 0;
}
