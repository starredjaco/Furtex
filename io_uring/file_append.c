#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/io_uring.h>
#include "iouring_utils.h"

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <path> <line>\n", argv[0]);
        return 1;
    }

    const char *path = argv[1];
    const char *line = argv[2];
    size_t len       = strlen(line);

    struct uring u;
    if (uring_init(&u, 8) < 0) { perror("uring_init"); return 1; }

    struct io_uring_sqe *sqe = uring_get_sqe(&u);
    sqe->opcode     = IORING_OP_OPENAT;
    sqe->fd         = AT_FDCWD;
    sqe->addr       = (uint64_t)(uintptr_t)path;
    sqe->open_flags = O_WRONLY | O_APPEND | O_CREAT;
    sqe->len        = 0600;
    sqe->user_data  = 1;

    uring_submit_wait(&u, 1);
    struct io_uring_cqe cqe;
    uring_peek_cqe(&u, &cqe);
    if ((int)cqe.res < 0) {
        fprintf(stderr, "openat: %s\n", strerror(-(int)cqe.res));
        return 1;
    }
    int fd = (int)cqe.res;

    sqe = uring_get_sqe(&u);
    sqe->opcode    = IORING_OP_WRITE;
    sqe->fd        = fd;
    sqe->addr      = (uint64_t)(uintptr_t)line;
    sqe->len       = (uint32_t)len;
    sqe->off       = (uint64_t)-1;
    sqe->user_data = 2;

    uring_submit_wait(&u, 1);
    uring_peek_cqe(&u, &cqe);
    if ((int)cqe.res < 0) {
        fprintf(stderr, "write: %s\n", strerror(-(int)cqe.res));
        return 1;
    }
    printf("[*] appended %d bytes to %s\n", cqe.res, path);

    sqe = uring_get_sqe(&u);
    sqe->opcode   = IORING_OP_CLOSE;
    sqe->fd       = fd;
    sqe->user_data = 3;
    uring_submit_wait(&u, 1);
    uring_peek_cqe(&u, &cqe);

    uring_free(&u);
    return 0;
}
