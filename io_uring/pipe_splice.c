#define _GNU_SOURCE
#include <linux/io_uring.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "iouring_utils.h"

#define SPLICE_SZ (64 * 1024)

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <src_file> <dst_file|->\n", argv[0]);
        return 1;
    }

    const char *src_path = argv[1];
    const char *dst_path = argv[2];

    struct uring u = {};
    if (uring_init(&u, 16) < 0) { perror("uring_init"); return 1; }

    struct io_uring_sqe *sqe = uring_get_sqe(&u);
    sqe->opcode     = IORING_OP_OPENAT;
    sqe->fd         = AT_FDCWD;
    sqe->addr       = (uint64_t)(uintptr_t)src_path;
    sqe->open_flags = O_RDONLY;
    sqe->user_data  = 1;

    uring_submit_wait(&u, 1);
    struct io_uring_cqe cqe;
    uring_peek_cqe(&u, &cqe);
    if ((int)cqe.res < 0) {
        fprintf(stderr, "[!] open src: %s\n", strerror(-(int)cqe.res));
        return 1;
    }
    int src_fd = (int)cqe.res;

    int dst_fd;
    if (strcmp(dst_path, "-") == 0) {
        dst_fd = STDOUT_FILENO;
    } else {
        sqe = uring_get_sqe(&u);
        sqe->opcode     = IORING_OP_OPENAT;
        sqe->fd         = AT_FDCWD;
        sqe->addr       = (uint64_t)(uintptr_t)dst_path;
        sqe->open_flags = O_WRONLY | O_CREAT | O_TRUNC;
        sqe->len        = 0600;
        sqe->user_data  = 2;

        uring_submit_wait(&u, 1);
        uring_peek_cqe(&u, &cqe);
        if ((int)cqe.res < 0) {
            fprintf(stderr, "[!] open dst: %s\n", strerror(-(int)cqe.res));
            return 1;
        }
        dst_fd = (int)cqe.res;
    }

    int pfd[2];
    if (pipe2(pfd, O_NONBLOCK) < 0) { perror("pipe"); return 1; }

    uint64_t total = 0;
    for (;;) {

        sqe = uring_get_sqe(&u);
        sqe->opcode     = IORING_OP_SPLICE;
        sqe->splice_fd_in = src_fd;
        sqe->splice_off_in = (uint64_t)-1;
        sqe->fd         = pfd[1];
        sqe->off        = (uint64_t)-1;
        sqe->len        = SPLICE_SZ;
        sqe->splice_flags = 0;
        sqe->user_data  = 3;

        uring_submit_wait(&u, 1);
        uring_peek_cqe(&u, &cqe);
        int n = (int)cqe.res;
        if (n <= 0) break;

        if (dst_fd == STDOUT_FILENO) {
            char rbuf[SPLICE_SZ];
            ssize_t r, written = 0;
            while (written < n) {
                r = read(pfd[0], rbuf + written, (size_t)(n - written));
                if (r <= 0) break;
                written += r;
            }
            if (written > 0) {
                write(STDOUT_FILENO, rbuf, (size_t)written);
                total += (uint64_t)written;
            }
        } else {
            sqe = uring_get_sqe(&u);
            sqe->opcode     = IORING_OP_SPLICE;
            sqe->splice_fd_in = pfd[0];
            sqe->splice_off_in = (uint64_t)-1;
            sqe->fd         = dst_fd;
            sqe->off        = (uint64_t)-1;
            sqe->len        = (uint32_t)n;
            sqe->splice_flags = 0;
            sqe->user_data  = 4;

            uring_submit_wait(&u, 1);
            uring_peek_cqe(&u, &cqe);
            if ((int)cqe.res > 0) total += (uint64_t)cqe.res;
        }
    }

    if (dst_fd != STDOUT_FILENO) {
        sqe = uring_get_sqe(&u);
        sqe->opcode = IORING_OP_CLOSE; sqe->fd = dst_fd;
        uring_submit_wait(&u, 1); uring_peek_cqe(&u, &cqe);
    }

    sqe = uring_get_sqe(&u);
    sqe->opcode = IORING_OP_CLOSE; sqe->fd = src_fd;
    uring_submit_wait(&u, 1); uring_peek_cqe(&u, &cqe);

    close(pfd[0]); close(pfd[1]);
    uring_free(&u);

    if (dst_fd != STDOUT_FILENO)
        fprintf(stderr, "[*] spliced %llu bytes: %s -> %s\n",
                (unsigned long long)total, src_path, dst_path);
    return 0;
}
