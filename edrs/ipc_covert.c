#define _GNU_SOURCE
#include <mqueue.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#define Q_NAME   "/furtex-ipc"
#define MSG_MAX  4096
#define Q_DEPTH  8

static mqd_t open_queue(int create)
{
    struct mq_attr attr = {
        .mq_flags   = 0,
        .mq_maxmsg  = Q_DEPTH,
        .mq_msgsize = MSG_MAX,
    };
    int flags = create ? (O_CREAT | O_RDWR) : O_RDWR;
    mqd_t q = mq_open(Q_NAME, flags, 0600, &attr);
    if (q == (mqd_t)-1) perror("mq_open");
    return q;
}

static void cmd_server(void)
{
    mqd_t q = open_queue(1);
    if (q == (mqd_t)-1) return;

    printf("[*] mqueue server on %s\n", Q_NAME);
    printf("[*] visible at /dev/mqueue%s (if mounted)\n", Q_NAME);

    char buf[MSG_MAX + 1];
    for (;;) {
        ssize_t n = mq_receive(q, buf, MSG_MAX, NULL);
        if (n < 0) { perror("mq_receive"); break; }
        buf[n] = '\0';

        if (strcmp(buf, "quit") == 0) { printf("[*] quit received\n"); break; }

        printf("[cmd] %s\n", buf);

        FILE *f = popen(buf, "r");
        if (!f) { mq_send(q, "[!] popen failed\n", 17, 0); continue; }

        char out[MSG_MAX];
        size_t total = 0, r;
        while (total < MSG_MAX - 1 && (r = fread(out + total, 1, MSG_MAX - total - 1, f)) > 0)
            total += r;
        pclose(f);

        if (total == 0) { mq_send(q, "[no output]\n", 12, 0); continue; }
        out[total] = '\0';
        mq_send(q, out, total, 0);
    }

    mq_close(q);
    mq_unlink(Q_NAME);
}

static void cmd_client(void)
{
    mqd_t q = open_queue(0);
    if (q == (mqd_t)-1) return;

    printf("[*] connected to %s\n", Q_NAME);

    char cmd[MSG_MAX], out[MSG_MAX + 1];
    for (;;) {
        printf("ipc> "); fflush(stdout);
        if (!fgets(cmd, sizeof(cmd), stdin)) break;
        cmd[strcspn(cmd, "\n")] = '\0';
        if (strlen(cmd) == 0) continue;

        if (mq_send(q, cmd, strlen(cmd), 1) < 0) { perror("mq_send"); break; }
        if (strcmp(cmd, "quit") == 0) break;

        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5;

        ssize_t n = mq_timedreceive(q, out, MSG_MAX, NULL, &ts);
        if (n < 0) { perror("mq_timedreceive"); continue; }
        out[n] = '\0';
        fputs(out, stdout);
    }
    mq_close(q);
}

static void cmd_info(void)
{
    mqd_t q = mq_open(Q_NAME, O_RDONLY);
    if (q == (mqd_t)-1) { fprintf(stderr, "[!] queue %s not open\n", Q_NAME); return; }

    struct mq_attr attr;
    mq_getattr(q, &attr);
    printf("[*] queue %s\n", Q_NAME);
    printf("    maxmsg  = %ld\n", attr.mq_maxmsg);
    printf("    msgsize = %ld\n", attr.mq_msgsize);
    printf("    curmsgs = %ld\n", attr.mq_curmsgs);
    mq_close(q);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <server|client|info>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "server") == 0) cmd_server();
    else if (strcmp(argv[1], "client") == 0) cmd_client();
    else if (strcmp(argv[1], "info") == 0) cmd_info();
    else { fprintf(stderr, "unknown: %s\n", argv[1]); return 1; }

    return 0;
}
