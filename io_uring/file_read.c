#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/io_uring.h>
#include "iouring_utils.h"

#define BUF_SZ (1024 * 64)

#define UD_OPEN  1
#define UD_READ  2
#define UD_CLOSE 3

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 1;
    }

    struct uring u;
    if (uring_init(&u, 8) < 0) {
        perror("uring_init");
        return 1;
    }

    char *buf = aligned_alloc(4096, BUF_SZ);
    if (!buf) { perror("aligned_alloc"); return 1; }

    struct io_uring_sqe *sqe = uring_get_sqe(&u);
    sqe->opcode     = IORING_OP_OPENAT;
    sqe->fd         = AT_FDCWD;
    sqe->addr       = (uint64_t)(uintptr_t)argv[1];
    sqe->open_flags = O_RDONLY;
    sqe->len        = 0;
    sqe->user_data  = UD_OPEN;

    uring_submit_wait(&u, 1);

    struct io_uring_cqe cqe;
    uring_peek_cqe(&u, &cqe);
    if ((int)cqe.res < 0) {
        fprintf(stderr, "openat failed: %s\n", strerror(-(int)cqe.res));
        return 1;
    }
    int file_fd = (int)cqe.res;

    sqe = uring_get_sqe(&u);
    sqe->opcode    = IORING_OP_READ;
    sqe->fd        = file_fd;
    sqe->addr      = (uint64_t)(uintptr_t)buf;
    sqe->len       = BUF_SZ - 1;
    sqe->off       = 0;
    sqe->user_data = UD_READ;

    uring_submit_wait(&u, 1);

    uring_peek_cqe(&u, &cqe);
    if ((int)cqe.res < 0) {
        fprintf(stderr, "read failed: %s\n", strerror(-(int)cqe.res));
        return 1;
    }
    int nread = (int)cqe.res;
    buf[nread] = '\0';

    sqe = uring_get_sqe(&u);
    sqe->opcode    = IORING_OP_CLOSE;
    sqe->fd        = file_fd;
    sqe->user_data = UD_CLOSE;

    uring_submit_wait(&u, 1);
    uring_peek_cqe(&u, &cqe);

    fwrite(buf, 1, nread, stdout);

    free(buf);
    uring_free(&u);
    return 0;
}
