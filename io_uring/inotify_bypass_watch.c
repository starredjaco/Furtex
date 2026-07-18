#define _GNU_SOURCE
#include <linux/io_uring.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#include "iouring_utils.h"

#define MAX_FILE_SZ (1 << 20)

static volatile int running = 1;
static void sigint(int s) { (void)s; running = 0; }

static void sleep_ms(long ms)
{
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file> [interval_ms]\n", argv[0]);
        return 1;
    }

    const char *path = argv[1];
    long interval_ms = argc >= 3 ? atol(argv[2]) : 500;
    if (interval_ms < 10) interval_ms = 10;

    signal(SIGINT, sigint);

    struct uring u = {};
    if (uring_init(&u, 8) < 0) { perror("uring_init"); return 1; }

    uint8_t *buf  = malloc(MAX_FILE_SZ);
    uint8_t *prev = calloc(1, MAX_FILE_SZ);
    size_t prev_len = 0;

    printf("[*] watching %s (interval %ldms, ctrl-c to stop)\n", path, interval_ms);

    while (running) {

        struct io_uring_sqe *sqe = uring_get_sqe(&u);
        sqe->opcode     = IORING_OP_OPENAT;
        sqe->fd         = AT_FDCWD;
        sqe->addr       = (uint64_t)(uintptr_t)path;
        sqe->open_flags = O_RDONLY;
        sqe->user_data  = 1;
        uring_submit_wait(&u, 1);
        struct io_uring_cqe cqe;
        uring_peek_cqe(&u, &cqe);

        if ((int)cqe.res < 0) {

            sleep_ms(interval_ms);
            continue;
        }
        int fd = (int)cqe.res;

        sqe = uring_get_sqe(&u);
        sqe->opcode    = IORING_OP_READ;
        sqe->fd        = fd;
        sqe->addr      = (uint64_t)(uintptr_t)buf;
        sqe->len       = MAX_FILE_SZ - 1;
        sqe->off       = 0;
        sqe->user_data = 2;
        uring_submit_wait(&u, 1);
        uring_peek_cqe(&u, &cqe);
        int n = (int)cqe.res;

        sqe = uring_get_sqe(&u);
        sqe->opcode = IORING_OP_CLOSE; sqe->fd = fd;
        uring_submit_wait(&u, 1); uring_peek_cqe(&u, &cqe);

        if (n <= 0) { sleep_ms(interval_ms); continue; }
        buf[n] = '\0';

        if ((size_t)n != prev_len || memcmp(buf, prev, (size_t)n) != 0) {

            if (prev_len == 0) {

                printf("--- initial content of %s ---\n", path);
                fwrite(buf, 1, (size_t)n, stdout);
                if (buf[n-1] != '\n') putchar('\n');
            } else if ((size_t)n > prev_len) {

                printf("--- %s +%zu bytes ---\n", path, (size_t)n - prev_len);
                fwrite(buf + prev_len, 1, (size_t)n - prev_len, stdout);
                if (buf[n-1] != '\n') putchar('\n');
            } else {

                printf("--- %s changed (was %zu, now %d bytes) ---\n",
                       path, prev_len, n);
                fwrite(buf, 1, (size_t)n, stdout);
                if (buf[n-1] != '\n') putchar('\n');
            }
            fflush(stdout);

            memcpy(prev, buf, (size_t)n);
            prev_len = (size_t)n;
        }

        sleep_ms(interval_ms);
    }

    printf("\n[*] stopped\n");
    free(buf); free(prev);
    uring_free(&u);
    return 0;
}
