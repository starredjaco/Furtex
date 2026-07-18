#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/io_uring.h>
#include "iouring_utils.h"

#define MAX_FILES 64
#define BUF_SZ    (32 * 1024)

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file1> [file2 ...]\n", argv[0]);
        return 1;
    }

    int nfiles = argc - 1;
    if (nfiles > MAX_FILES) nfiles = MAX_FILES;

    struct uring u;
    if (uring_init(&u, (unsigned)(nfiles * 4)) < 0) { perror("uring_init"); return 1; }

    char  **bufs = calloc(nfiles, sizeof(char *));
    int    *fds  = calloc(nfiles, sizeof(int));
    for (int i = 0; i < nfiles; i++) {
        bufs[i] = aligned_alloc(4096, BUF_SZ);
        fds[i]  = -1;
    }

    for (int i = 0; i < nfiles; i++) {
        struct io_uring_sqe *sqe = uring_get_sqe(&u);
        sqe->opcode     = IORING_OP_OPENAT;
        sqe->fd         = AT_FDCWD;
        sqe->addr       = (uint64_t)(uintptr_t)argv[i + 1];
        sqe->open_flags = O_RDONLY;
        sqe->len        = 0;
        sqe->user_data  = (uint64_t)i;
    }
    uring_submit_wait(&u, (unsigned)nfiles);

    for (int i = 0; i < nfiles; i++) {
        struct io_uring_cqe cqe;
        if (uring_peek_cqe(&u, &cqe) < 0) break;
        int idx = (int)cqe.user_data;
        if ((int)cqe.res < 0)
            fprintf(stderr, "[-] open %s: %s\n", argv[idx+1], strerror(-(int)cqe.res));
        else
            fds[idx] = (int)cqe.res;
    }

    int submitted = 0;
    for (int i = 0; i < nfiles; i++) {
        if (fds[i] < 0) continue;
        struct io_uring_sqe *sqe = uring_get_sqe(&u);
        sqe->opcode    = IORING_OP_READ;
        sqe->fd        = fds[i];
        sqe->addr      = (uint64_t)(uintptr_t)bufs[i];
        sqe->len       = BUF_SZ - 1;
        sqe->off       = 0;
        sqe->user_data = (uint64_t)i;
        submitted++;
    }
    if (submitted > 0) uring_submit_wait(&u, (unsigned)submitted);

    for (int i = 0; i < submitted; i++) {
        struct io_uring_cqe cqe;
        if (uring_peek_cqe(&u, &cqe) < 0) break;
        int idx = (int)cqe.user_data;
        int n   = (int)cqe.res;
        if (n > 0) {
            bufs[idx][n] = '\0';
            printf("\n=== %s (%d bytes) ===\n", argv[idx+1], n);
            fwrite(bufs[idx], 1, n, stdout);
        }
    }

    for (int i = 0; i < nfiles; i++) {
        if (fds[i] < 0) continue;
        struct io_uring_sqe *sqe = uring_get_sqe(&u);
        sqe->opcode   = IORING_OP_CLOSE;
        sqe->fd       = fds[i];
        sqe->user_data = (uint64_t)i;
    }
    uring_submit_wait(&u, 0);

    for (int i = 0; i < nfiles; i++) free(bufs[i]);
    free(bufs); free(fds);
    uring_free(&u);
    return 0;
}
