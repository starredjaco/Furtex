#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/io_uring.h>
#include "iouring_utils.h"

#define RECV_BUF_SZ 4096

#define UD_SOCKET  1
#define UD_CONNECT 2
#define UD_SEND    3
#define UD_RECV    4
#define UD_CLOSE   5

int main(int argc, char *argv[])
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s <ip> <port> <message>\n", argv[0]);
        return 1;
    }

    const char *ip  = argv[1];
    int port        = atoi(argv[2]);
    const char *msg = argv[3];

    struct uring u;
    if (uring_init(&u, 8) < 0) { perror("uring_init"); return 1; }

    char *recv_buf = malloc(RECV_BUF_SZ);
    if (!recv_buf) { perror("malloc"); return 1; }

    struct io_uring_sqe *sqe = uring_get_sqe(&u);
    sqe->opcode    = IORING_OP_SOCKET;
    sqe->fd        = AF_INET;
    sqe->off       = SOCK_STREAM;
    sqe->len       = 0;
    sqe->user_data = UD_SOCKET;

    uring_submit_wait(&u, 1);

    struct io_uring_cqe cqe;
    uring_peek_cqe(&u, &cqe);
    if ((int)cqe.res < 0) {
        fprintf(stderr, "socket: %s\n", strerror(-(int)cqe.res));
        return 1;
    }
    int sock = (int)cqe.res;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        fprintf(stderr, "invalid ip: %s\n", ip);
        return 1;
    }

    sqe = uring_get_sqe(&u);
    sqe->opcode   = IORING_OP_CONNECT;
    sqe->fd       = sock;
    sqe->addr     = (uint64_t)(uintptr_t)&addr;
    sqe->off      = sizeof(addr);
    sqe->user_data = UD_CONNECT;

    uring_submit_wait(&u, 1);
    uring_peek_cqe(&u, &cqe);
    if ((int)cqe.res < 0) {
        fprintf(stderr, "connect: %s\n", strerror(-(int)cqe.res));
        return 1;
    }

    sqe = uring_get_sqe(&u);
    sqe->opcode    = IORING_OP_SEND;
    sqe->fd        = sock;
    sqe->addr      = (uint64_t)(uintptr_t)msg;
    sqe->len       = (uint32_t)strlen(msg);
    sqe->user_data = UD_SEND;

    uring_submit_wait(&u, 1);
    uring_peek_cqe(&u, &cqe);
    if ((int)cqe.res < 0) {
        fprintf(stderr, "send: %s\n", strerror(-(int)cqe.res));
        return 1;
    }
    printf("[*] sent %d bytes\n", cqe.res);

    sqe = uring_get_sqe(&u);
    sqe->opcode    = IORING_OP_RECV;
    sqe->fd        = sock;
    sqe->addr      = (uint64_t)(uintptr_t)recv_buf;
    sqe->len       = RECV_BUF_SZ - 1;
    sqe->user_data = UD_RECV;

    uring_submit_wait(&u, 1);
    uring_peek_cqe(&u, &cqe);
    if ((int)cqe.res > 0) {
        recv_buf[cqe.res] = '\0';
        fwrite(recv_buf, 1, cqe.res, stdout);
    }

    sqe = uring_get_sqe(&u);
    sqe->opcode    = IORING_OP_CLOSE;
    sqe->fd        = sock;
    sqe->user_data = UD_CLOSE;
    uring_submit_wait(&u, 1);
    uring_peek_cqe(&u, &cqe);

    free(recv_buf);
    uring_free(&u);
    return 0;
}
